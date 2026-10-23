// Implement optional fixed-budget profile storage, sampling, and record publication.
#include <astra/profile.hpp>

#if defined(ASTRA_PROFILE) && ASTRA_PROFILE
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <new>
#include <string_view>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

namespace astra {
/// Keeps the mapped recording resident until process exit so every in-flight span retains valid storage.
class Profile::Storage {
public:
    /// Current Linux little-endian 64-bit ABI; offline parsers revalidate the fixed-width layout.
    struct Entry {
        /// Monotonic start in nanoseconds, alignable across processes on one host.
        std::uint64_t start;
        /// Elapsed nanoseconds including instrumented child calls.
        std::uint64_t elapsed;
        /// Elapsed nanoseconds excluding synchronous child probes, still including uninstrumented work and preemption.
        std::uint64_t own;
        /// Optional thread CPU nanoseconds; zero when disabled.
        std::uint64_t cpu;
        /// CPU nanoseconds excluding synchronous children; zero when disabled.
        std::uint64_t exclusive;
        /// Process-unique span ID starting at 1; zero for count events.
        std::uint64_t id;
        /// Same-thread parent span ID; zero at the root, without invented asynchronous parentage.
        std::uint64_t parent;
        /// Fixed probe-name FNV-1a ID, resolved and checked for collisions against the source catalog.
        std::uint64_t site;
        /// Nonsensitive count-event value; zero for ordinary spans.
        std::uint64_t value;
        /// Kernel thread ID for timeline and nesting checks.
        std::uint32_t thread;
        /// Bit 0 CPU timing; bit 1 count; bit 2 asynchronous interval; bit 3 signed count.
        std::uint32_t flags;
    };

    /// Fixed-format file metadata and shared reservation counters for one process recording.
    struct Header {
        /// Fixed format marker, distinct from earlier temporary probes.
        std::uint64_t magic = 0x4153545241505246ULL;
        /// v2 adds feature selection, duration limits, and signed values while retaining fixed-size records.
        std::uint64_t version = 2;
        /// Bytes per record.
        std::uint64_t width = sizeof(Entry);
        /// File record capacity; never grows during collection.
        std::uint64_t capacity{};
        /// High watermark reserved in 64-slot blocks, including unused zero slots.
        std::atomic_uint64_t count{};
        /// Direct rejections before capacity stops collection, not all omitted events.
        std::atomic_uint64_t missed{};
        /// Clock anomaly or invalid nesting count; nonzero prevents claims of complete profiling.
        std::atomic_uint64_t errors{};
        /// Outermost selected spans sample at about 1/N; children inherit the decision.
        std::uint64_t sample{};
        /// Whether extra thread CPU clock syscalls are enabled.
        std::uint64_t cpu{};
        /// Enabled feature bits from the fixed name table below.
        std::uint64_t groups{};
        /// Maximum collection seconds; zero leaves capacity as the only limit.
        std::uint64_t seconds{};
        /// Fixed 128-byte header; extensions require a version increment.
        std::array<std::uint64_t, 5> reserved{};
    };

    static_assert(sizeof(Header) == 128 && sizeof(Entry) == 80);
    static_assert(std::atomic_uint64_t::is_always_lock_free);

    /// Empty without a directory or after creation failure; diagnostics disable without changing business results.
    Header* header{};
    /// Fixed mapped-record area, read by the analyzer only after process exit.
    Entry* entries{};

    /// Reads diagnostic environment. Directory must already exist and be absolute; creates no threads, downloads nothing, and prints no values.
    Storage() noexcept;

    /// Unselected features read no clocks or TLS stack. Expiry atomically stops collection without unmapping in-flight span storage.
    bool active(std::uint64_t group) noexcept;

    /// Parses comma-separated feature names at startup only; rejects empty, unknown, or duplicate names and supports no environment reload.
    static std::uint64_t selection(const char* text) noexcept;

    /// Parses unsigned decimal configuration: absent uses fallback; empty, overflow, or nondigits return UINT64_MAX.
    static std::uint64_t number(const char* name, std::uint64_t fallback, std::uint64_t minimum, std::uint64_t maximum) noexcept;

    /// Initialization failure emits a fixed diagnostic only; harness must treat missing or corrupt files as measurement failure.
    static void failure() noexcept;

    /// Each thread owns 64 slots and contends on the atomic counter only for a new block; 64-byte boundaries avoid false sharing.
    std::uint64_t reserve() noexcept;

    /// Starts trivial record lifetime in an exclusive slot without heap allocation; readers must await process exit, with no online publication protocol.
    void write(std::uint64_t slot, const Entry& entry) noexcept {
        ::new (static_cast<void*>(entries + slot)) Entry(entry);
    }

private:
    /// Monotonic nanosecond deadline, read-only after initialization; zero means unlimited duration.
    std::uint64_t stop_{};
    /// Any thread observing expiry or capacity stops collection; subsequent entries read no clocks.
    std::atomic_bool stopped_{};
};

Profile::Storage::Storage() noexcept {

    const char* directory = std::getenv("ASTRA_PROFILE_DIR"); // No file is created by default.
    if (!directory) {
        return;
    }
    const auto sample = number("ASTRA_PROFILE_SAMPLE", 64, 1, 65536);   // Top-level sampling interval, default 64.
    const auto mib = number("ASTRA_PROFILE_MIB", 64, 1, 512);           // Per-process mapping budget, default 64 MiB.
    const auto cpu = number("ASTRA_PROFILE_CPU", 0, 0, 1);              // CPU syscalls require explicit enablement and perturbation measurement.
    const auto groups = selection(std::getenv("ASTRA_PROFILE_GROUPS")); // Defaults to all; invalid names stop collection instead of silently enabling every feature.
    const auto seconds = number("ASTRA_PROFILE_SECONDS", 0, 0, 86400);  // Collection window at most one day; zero preserves capacity-only mode.
    if (directory[0] != '/' || sample == UINT64_MAX || mib == UINT64_MAX || cpu == UINT64_MAX || !groups || seconds == UINT64_MAX) {
        failure();
        return;
    }

    char path[4096]; // Path is used to open the file only and never enters performance records.
    const auto length = std::snprintf(path, sizeof(path), "%s/%ld.profile", directory, static_cast<long>(::getpid()));
    if (length < 0 || static_cast<std::size_t>(length) >= sizeof(path)) {
        failure();
        return;
    }
    const auto bytes = static_cast<std::size_t>(mib) * 1024 * 1024;             // Maximum 512 MiB; multiplication bounds already checked.
    const int file = ::open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600); // Never overwrite existing evidence.
    if (file < 0) {
        failure();
        return;
    }
    if (::ftruncate(file, static_cast<off_t>(bytes)) != 0 || ::posix_fallocate(file, 0, static_cast<off_t>(bytes)) != 0) {
        ::close(file);
        failure();
        return;
    }
    void* memory = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0); // Disk space is reserved, but first-touch and kernel writeback costs remain; no synchronous flush.
    ::close(file);
    if (memory == MAP_FAILED) {
        failure();
        return;
    }
    header = new (memory) Header;
    header->capacity = (bytes - sizeof(Header)) / sizeof(Entry) / 64 * 64;
    header->sample = sample;
    header->cpu = cpu;
    header->groups = groups;
    header->seconds = seconds;
    entries = reinterpret_cast<Entry*>(static_cast<char*>(memory) + sizeof(Header));
    stop_ = seconds ? now() + seconds * 1'000'000'000 : 0;
}

bool Profile::Storage::active(std::uint64_t group) noexcept {

    if (!header || !(header->groups & group) || stopped_.load(std::memory_order_relaxed)) {
        return false;
    }
    if (stop_ && now() >= stop_) {
        stopped_.store(true, std::memory_order_relaxed);
        return false;
    }
    return true;
}

std::uint64_t Profile::Storage::selection(const char* text) noexcept {

    if (!text || std::string_view(text) == "all") {
        return 255;
    }
    constexpr std::array names{"clock", "storage", "rpc", "replication", "watch", "sdk", "core", "test"}; // Order matches fixed file-header bit positions.
    std::string_view remaining(text);                                                                     // Borrows startup environment without allocating or copying values.
    std::uint64_t result{};                                                                               // Matched feature bits; zero also denotes configuration failure.
    do {
        const auto end = remaining.find(','); // Current feature-name boundaries; no whitespace or implicit spelling correction.
        const auto name = remaining.substr(0, end);
        std::uint64_t bit{}; // A matched item has exactly one bit; unknown items remain zero.
        for (std::size_t index = 0; index < names.size(); ++index) {
            if (name == names[index]) {
                bit = std::uint64_t{1} << index;
            }
        }
        if (!bit || (result & bit)) {
            return 0;
        }
        result |= bit;
        if (end == std::string_view::npos) {
            return result;
        }
        remaining.remove_prefix(end + 1);
    } while (!remaining.empty());
    return 0;
}

std::uint64_t Profile::Storage::number(const char* name, std::uint64_t fallback, std::uint64_t minimum, std::uint64_t maximum) noexcept {

    const char* text = std::getenv(name); // Synchronously borrows process environment; runtime configuration changes are unsupported.
    if (!text) {
        return fallback;
    }
    if (!*text) {
        return UINT64_MAX;
    }
    std::uint64_t value{}; // Accumulate digits with bounds checked before multiplication.
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') {
            return UINT64_MAX;
        }
        const auto digit = static_cast<std::uint64_t>(*text - '0');
        if (digit > maximum || value > (maximum - digit) / 10) {
            return UINT64_MAX;
        }
        value = value * 10 + digit;
    }
    return value >= minimum ? value : UINT64_MAX;
}

void Profile::Storage::failure() noexcept {

    std::fputs("Astra profiling initialization failed\n", stderr);
}

std::uint64_t Profile::Storage::reserve() noexcept {

    /// One thread's exclusive reservation window; exhaustion permanently stops further reservations.
    struct Block {
        /// Next slot index; zero before block assignment.
        std::uint64_t next{};
        /// Exclusive block end.
        std::uint64_t end{};
        /// Stop reserving blocks at capacity to prevent unbounded watermark growth.
        bool full{};
    };

    thread_local Block block; // Paired with the process's sole Storage; collection through inherited mappings after fork is unsupported.
    if (block.next == block.end && !block.full) {
        block.next = header->count.fetch_add(64, std::memory_order_relaxed);
        block.end = block.next + 64;
        block.full = block.next >= header->capacity;
    }

    if (block.full) {
        header->missed.fetch_add(1, std::memory_order_relaxed);
        stopped_.store(true, std::memory_order_relaxed); // Capacity rejection stops new collection process-wide, avoiding continued hot-path contention on missed.
        return UINT64_MAX;
    }
    return block.next++;
}

Profile::Storage& Profile::storage() noexcept {

    static Storage result;
    return result;
}

std::uint32_t Profile::thread() noexcept {

    thread_local const auto value = static_cast<std::uint32_t>(::syscall(SYS_gettid));
    return value;
}

std::uint64_t Profile::cpu(Storage& output) noexcept {

    timespec time{}; // Kernel-written seconds and nanoseconds.
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time) != 0) {
        output.header->errors.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    return static_cast<std::uint64_t>(time.tv_sec) * 1000000000ULL + static_cast<std::uint64_t>(time.tv_nsec);
}

Profile::Span::Span(Site site) noexcept : site_(site.id) {

    auto& output = storage(); // Open the mapping before taking the first timing sample.
    if (!output.active(site.group)) {
        return;
    }
    parent_ = current_;
    // GCC 16's inline escape analysis misses TLS restoration by finish/destruction; suppress only this assignment's false positive.
    // Other lifetime checks remain enabled; independent cases cover nesting, early finish, and exception unwinding.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdangling-pointer"
    current_ = this;
#pragma GCC diagnostic pop
    open_ = true;
    output_ = &output;
    if (parent_ ? parent_->id_ == 0 : !select(output.header->sample)) {
        return;
    }
    const auto slot = output.reserve(); // Reserve thread-local storage early; finishing writes directly without per-record atomic contention.
    if (slot == UINT64_MAX) {
        return;
    }
    id_ = slot + 1;
    if (output.header->cpu) {
        cpu_ = cpu(output);
    }
    start_ = now();
}

void Profile::Span::finish() noexcept {

    if (!open_) {
        return;
    }
    if (current_ != this) {
        output_->header->errors.fetch_add(1, std::memory_order_relaxed);
        std::abort(); // Internal probe misuse must not continue with a dangling TLS parent chain.
    }
    current_ = parent_;
    open_ = false;
    if (!id_) {
        return;
    }
    const auto end = now(); // End elapsed timing first, excluding record-writing work from this span.
    const auto elapsed = end >= start_ ? end - start_ : 0;
    const auto used = output_->header->cpu ? cpu(*output_) : 0;
    const auto consumed = used >= cpu_ ? used - cpu_ : 0;
    if (end < start_ || children_ > elapsed || used < cpu_ || consumed_ > consumed) {
        output_->header->errors.fetch_add(1, std::memory_order_relaxed);
    }
    if (parent_) {
        parent_->children_ += elapsed;
        parent_->consumed_ += consumed;
    }
    output_->write(id_ - 1, {start_, elapsed, elapsed >= children_ ? elapsed - children_ : 0, consumed, consumed >= consumed_ ? consumed - consumed_ : 0, id_, parent_ ? parent_->id_ : 0, site_, 0, thread(), static_cast<std::uint32_t>(output_->header->cpu)});
}

bool Profile::Span::select(std::uint64_t interval) noexcept {

    if (interval == 1) {
        return true;
    }
    if (!random_) {
        random_ = thread() ^ 0x9e3779b9U; // Stagger thread seeds; replace a zero XOR result with a nonzero constant.
        if (!random_) {
            random_ = 1;
        }
    }

    random_ ^= random_ << 13;
    random_ ^= random_ >> 17;
    random_ ^= random_ << 5;
    return random_ % interval == 0;
}

void Profile::Span::count(Site site, std::uint64_t value, bool signedValue) noexcept {

    if (!current_ || !current_->id_ || !current_->output_->active(site.group)) {
        return;
    }
    auto& output = *current_->output_;
    const auto slot = output.reserve(); // Count events also use thread-exclusive slots; capacity failure reports explicitly without extra memory allocation.
    if (slot == UINT64_MAX) {
        return;
    }
    output.write(slot, {now(), 0, 0, 0, 0, 0, current_->id_, site.id, value, thread(), signedValue ? 10U : 2U});
}

void Profile::Stamp::consume(Site site) noexcept {

    if (!start_) {
        return;
    }
    const auto start = start_; // Clear first to avoid duplicate event records.
    start_ = 0;
    auto& output = storage();
    if (!output.active(site.group)) {
        return;
    }
    const auto end = now(); // Unselected features clear consumed markers without reading diagnostic clocks.
    if (end < start) {
        output.header->errors.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const auto slot = output.reserve();
    if (slot == UINT64_MAX) {
        return;
    }
    output.write(slot, {start, end - start, end - start, 0, 0, 0, 0, site.id, 0, thread(), 4});
}
} // namespace astra
#endif
