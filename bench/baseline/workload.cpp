// Implement shared baseline configuration, observation checks, and failure publication.
#include "workload.hpp"

Workload::Route::Route(const Options& options) {
    // Copy endpoint strings into endpoints_; reject empty or duplicate addresses.
    for (const auto part : options.endpoint | std::views::split(',')) {
        const std::string address(part.begin(), part.end());
        check(!address.empty() && std::ranges::find(endpoints_, address) == endpoints_.end(), "Empty or duplicate Star endpoint");
        endpoints_.push_back(address);
    }
    check(!endpoints_.empty(), "Missing Star endpoint");

    // One node is diagnostic only; multinode workloads need records at every producer and subscriptions covering all nodes.
    const auto count = endpoints_.size();
    check(count <= 8 && options.clients >= count && options.clients % count == 0 && options.writers >= count && options.writers % count == 0 && options.records >= options.clients && options.records % options.clients == 0 && options.fanout >= count, "Workload does not cover every Star");
}

Workload::Options Workload::parse(int count, char** arguments) {
    check(count == 16 || count == 17, "Expected endpoint domain mode records groups fanout clients writers bytes attr seconds ttl rate poll v1 [legacy_view_ms]");
    Options options;
    options.endpoint = arguments[1];
    options.catalog = std::string_view(arguments[2]) == "catalog";
    options.visible = std::string_view(arguments[3]) == "visible";
    check(options.catalog || std::string_view(arguments[2]) == "ephemeris", "Invalid domain");
    check(options.visible || std::string_view(arguments[3]) == "receipt", "Invalid mode");
    options.records = number(arguments[4]);
    options.groups = number(arguments[5]);
    options.fanout = number(arguments[6]);
    options.clients = number(arguments[7]);
    options.writers = number(arguments[8]);
    options.bytes = number(arguments[9]);
    options.attr = number(arguments[10]);
    options.seconds = number(arguments[11]);
    options.ttl = number(arguments[12]);
    options.rate = number(arguments[13]);
    options.poll = number(arguments[14]);
    options.legacy = count == 17 ? number(arguments[16]) : 0;
    check(std::string_view(arguments[15]) == "v1", "Unsupported baseline contract");

    check(!options.endpoint.empty() && options.records >= 8 && options.records <= 1024 && options.groups >= 1 && options.groups <= 8 && options.fanout >= 1 && options.fanout <= 32 && options.clients >= 1 && options.clients <= 8 && options.writers >= 1 && options.writers <= 32 && options.bytes >= 16 && options.bytes <= 4096 && options.attr >= 16 && options.attr <= 16384 && options.seconds >= 2 && options.seconds <= 30 && options.ttl >= 1000 && options.ttl <= 600000 && options.rate <= 100000 && options.poll >= 100 && options.poll <= 10000, "Baseline limit exceeded");
    check(options.records % options.groups == 0 && options.records % options.writers == 0 && options.groups * options.fanout <= 128, "Unbalanced workload");
    check(options.legacy <= 1000, "Invalid legacy view interval");
    return options;
}

void Workload::check(bool value, std::string_view reason) {
    if (!value) {
        throw std::runtime_error(std::string(reason));
    }
}

std::vector<std::uint8_t> Workload::content(std::size_t bytes, std::uint64_t record, std::uint64_t version) {
    std::vector<std::uint8_t> value(bytes, 42); // The first sixteen bytes use the same host encoding on all tested platforms.
    std::memcpy(value.data(), &record, sizeof(record));
    std::memcpy(value.data() + sizeof(record), &version, sizeof(version));
    return value;
}

Workload::Workload(const Options& options) : options_(options), seen_(std::make_unique<std::atomic<std::uint64_t>[]>(options.records * options.fanout)), versions_(options.records, 1) {
}

bool Workload::visible(std::size_t record, std::uint64_t version) const {
    for (std::size_t watcher = 0; watcher < options_.fanout; ++watcher) {
        if (seen_[record * options_.fanout + watcher].load(std::memory_order_relaxed) < version) {
            return false;
        }
    }
    return true;
}

bool Workload::complete() const {
    for (std::size_t record = 0; record < options_.records; ++record) {
        if (!visible(record, versions_[record])) {
            return false;
        }
    }
    return true;
}

void Workload::fail() {
    const std::lock_guard lock(gate_);
    if (!failure_) {
        failure_ = std::current_exception();
    }
    failed_.store(true);
}

void Workload::rethrow() {
    if (failed_.load()) {
        const std::lock_guard lock(gate_);
        std::rethrow_exception(failure_);
    }
}
