// Verify SDK client configuration, admission, and public operation boundaries.
#include "catalog_service.hpp"
#include "check.hpp"
#include "core.hpp"
#include "ephemeris_service.hpp"
#include "identity.hpp"
#include "reading.hpp"
#include "readout.hpp"
#include <comet/client.hpp>

#include <grpcpp/server_builder.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <map>
#include <ranges>
#include <source_location>
#include <span>
#include <thread>
#include <unordered_set>

namespace {
using namespace std::chrono_literals;

/// Actual public TLS endpoint, separate from internal node admission; the OS allocates each case an independent port.
class Fixture {
public:
    /// Test commits enter actual Almanac, without an in-memory Stub replacing service behavior.
    astra::Library library;
    /// Credentials default empty; password() installs a public test account explicitly.
    astra::Access access;
    /// At most one Session verifies that Readers share login.
    astra::Gateway gateway;
    /// Production snapshot, suffix, and cancellation handling.
    astra::Readout readout;
    /// Controllable registration clock; observers do not access Pulsar.
    std::atomic<std::int64_t> now{1'000'000'000};
    /// Actual native source and TTL.
    astra::Ephemeris::State ephemeris{[this] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(std::chrono::nanoseconds(now.load())), .ready = true}); }, {}};
    /// Shares the sole login service with Almanac.
    astra::Ephemeris::Service registrations{ephemeris, gateway, [this] { changed_.notify_all(); }};
    /// Same controllable epoch as registration.
    astra::Catalog::State catalog{[this] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(std::chrono::nanoseconds(now.load())), .ready = true}); }, {}};
    /// Actual dynamic-business entry.
    astra::Catalog::Service publications{catalog, gateway, [this] { changed_.notify_all(); }};
    /// Kernel-selected address; listens only while server lives.
    std::string endpoint;

    /// auth may disable login to test anonymous access; TLS remains enabled by default.
    explicit Fixture(std::string instance = "star-test", bool auth = true, bool tls = true) : library({}, [this](const astra::Scope& scope, const astra::Almanac::Change& change) noexcept { readout.changed(scope, change); }), gateway(access, std::move(instance), auth, 1), readout(library, gateway, [this] { changed_.notify_all(); }) {

        grpc::ServerBuilder builder; // Public interface registers neither Pulsar nor Orbit; client owns no node private key.
        builder.RegisterService(&gateway);
        builder.RegisterService(&readout);
        builder.RegisterService(&registrations);
        builder.RegisterService(&publications);
        builder.SetMaxReceiveMessageSize(8 * 1024 * 1024);
        builder.SetMaxSendMessageSize(8 * 1024 * 1024);
        auto credentials = astra::Identity::external(std::filesystem::path(ASTRA_FIXTURES) / "star-a");
        if (!credentials) {
            throw std::runtime_error(credentials.error().message);
        }
        int port{};
        builder.AddListeningPort("127.0.0.1:0", tls ? *credentials : grpc::InsecureServerCredentials(), &port);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);
        endpoint = "127.0.0.1:" + std::to_string(port);
        try {
            worker_ = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    readout.pump(std::chrono::steady_clock::now());
                    registrations.pump(std::chrono::steady_clock::now());
                    publications.pump(std::chrono::steady_clock::now());
                    std::unique_lock lock(mutex_);
                    changed_.wait_for(lock, stop, 2ms, [] { return false; });
                }
            });
            gateway.ready();
        } catch (...) {
            server_->Shutdown();
            server_->Wait();
            throw;
        }
    }

    ~Fixture() { // Success, assertion failure, and repeated shutdown share cleanup, isolated from other fixture ports.
        stop();
    }

    void stop() {
        if (server_) {
            gateway.stop();
            readout.stop();
            registrations.stop();
            publications.stop();
            server_->Shutdown(std::chrono::system_clock::now() + 2s);
            server_->Wait();
            worker_.request_stop();
            changed_.notify_all();
            worker_.join();
            readout.pump(std::chrono::steady_clock::now(), 65536);
            registrations.pump(std::chrono::steady_clock::now(), 65536);
            publications.pump(std::chrono::steady_clock::now(), 65536);
            server_.reset();
        }
    }

    /// Complete baseline has count Keys, one by default; first string value checks cross-Star regression prevention.
    void fill(std::uint64_t version = 1, unsigned count = 1) {
        auto draft = library.prepare({"routes", "main"}, version);
        CHECK(draft);
        for (unsigned index = 0; index < count; ++index) {
            CHECK(draft->set("key-" + std::to_string(index), {static_cast<std::uint8_t>(index % 251)}));
        }
        CHECK(library.reset(std::move(*draft)));
    }

    void password(std::uint8_t value) { // Simulates internal credential submission already validated by Receiver, without mutating Session directly.
        CHECK(access.apply("test", astra::Almanac::Buffer{value}, [] { return std::expected<bool, astra::Almanac::Error>(true); }));
    }

    comet::Client::Options options(bool auth = true, bool tls = true) const {
        comet::Client::Options options;
        options.endpoints = {endpoint};
        options.auth = auth;
        options.tls = tls;
        if (auth) {
            options.key = "test";
            options.secret = {42};
        }
        if (tls) {
            options.ca = std::filesystem::path(ASTRA_FIXTURES) / "star-a" / "ca.pem";
        }
        options.timeout = 500ms;
        return options;
    }

private:
    /// Control-thread bounded waits only; never held while waiting under Readout or Library locks.
    std::mutex mutex_;
    /// New events wake the shared control loop only.
    std::condition_variable_any changed_;
    /// Drain actual Server before worker_ stops.
    std::unique_ptr<grpc::Server> server_;
    /// One control thread per service, independent of Watch count.
    std::jthread worker_;
};

/// Exceptional exits close SDK and await actual local completion before destroying server or callback-borrowed locals.
class Client {
public:
    /// Public SDK handle; tests do not access its private Core.
    comet::Client value;

    explicit Client(comet::Client::Options options) {
        auto opened = comet::Client::open(std::move(options));
        CHECK(opened);
        value = std::move(*opened);
    }

    ~Client() {
        value.close();
        if (!value.wait(5s)) {
            std::terminate(); // Cleanup deadline failure fails the test explicitly, without leaving callbacks accessing destroyed fixtures.
        }
    }
};

/// Bounded network waits observe actual state instead of inferring peer completion from fixed sleeps.
void eventually(auto&& condition, std::chrono::seconds timeout = 5s, const std::source_location& caller = std::source_location::current()) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!condition()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            std::cerr << "COMET-WAIT " << caller.file_name() << ':' << caller.line() << '\n'; // Keep the exact waiting oracle without extending its deadline.
        }
        CHECK(now < deadline);
        std::this_thread::sleep_for(1ms);
    }
}

/// Close completion need not mean destruction; verify the final Alarm closure cannot retain Core forever.
void cleanup() {

    Fixture fixture("cleanup", false, false); // Exclusive anonymous loopback service, without fixed test ports.
    fixture.fill();
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        auto core = comet::detail::Core::prepare(fixture.options(false, false)); // Observe ownership through a private test entry without expanding public SDK API.
        CHECK(core);
        const std::weak_ptr<comet::detail::Core> retained = *core; // Weak references permit actual destruction and cover immediate close racing the first callback.
        auto reader = (*core)->reader({"routes", "main"}, {}, {}); // Workspace must actually capture objects to expose cross-round strong-reference cycles.
        CHECK(reader);
        const std::weak_ptr<comet::detail::Activity> activity = *reader; // Both objects must release naturally after closure.
        (*core)->start();
        if (attempt % 2 != 0) {
            eventually([&] { return (*reader)->load().state() == comet::Reader::State::Ready; });
        } // Covers closure before advancement and after data capture or consumption.
        (*core)->close();
        CHECK((*core)->wait(3s));
        reader->reset();
        core->reset();
        eventually([&] { return retained.expired() && activity.expired(); });
    }
}

/// Duplicate wakes, requeue during poll, late post-close events, and directory reuse share the actual control path.
void queued() {

    Fixture fixture("queued", false, false); // No login stream triggers global refresh for local events.
    fixture.fill();
    auto prepared = comet::detail::Core::prepare(fixture.options(false, false)); // Admit before start to accumulate duplicate wakes deterministically.
    CHECK(prepared);
    const auto core = *prepared;
    std::vector<std::shared_ptr<comet::detail::Reading>> readers; // Retain active objects until actual closure; no raw network pointers.
    std::weak_ptr<comet::detail::Reading> first;                  // Callbacks borrow weak references to avoid cycles with Reading.

    /// Drain Core notifications before local callback borrows and readers are destroyed.
    struct Stop {
        /// Destructor drains notifications before readers and first are destroyed.
        std::shared_ptr<comet::detail::Core> core;
        /// Preparation failure still starts shutdown advancement; an unset Alarm must not prevent cleanup.
        bool started{};

        ~Stop() {
            core->close();
            if (!started) {
                core->start();
            }
            if (!core->wait(5s)) {
                std::terminate();
            }
        }
    } stop{core};

    for (unsigned index = 0; index < 32; ++index) {
        comet::Reader::Options options; // First object closes inside its own notification, forcing requeue before poll returns.
        if (index == 0) {
            options.changed = [&first](const comet::Reader::View& view) {
                if (view.state() == comet::Reader::State::Ready) {
                    if (auto reader = first.lock()) {
                        reader->close();
                    }
                }
            };
        }
        auto reader = core->reader({"routes", "main"}, {}, std::move(options));
        CHECK(reader);
        readers.push_back(std::move(*reader));
    }
    first = readers.front(); // Bind callbacks before start, avoiding concurrent weak-reference mutation by the control thread.

    {
        std::array<std::jthread, 4> workers; // Multiple producers emit readiness only, without business-state changes or duplicate streams.
        for (unsigned index = 0; index < workers.size(); ++index) {
            workers[index] = std::jthread([&, index] {
                for (unsigned repeat = 0; repeat < 1024; ++repeat) {
                    core->wake(readers[(repeat + index) % readers.size()].get());
                }
            });
        }
    } // Start after all events are posted; each object needs one reserved queue slot despite duplicates.
    core->start();
    stop.started = true;
    CHECK(readers.front()->wait(3s)); // Closure occurs inside notification; later work must consume events created during that round.
    eventually([&] {
        return std::ranges::all_of(readers | std::views::drop(1), [](const auto& reader) { return reader->load().state() == comet::Reader::State::Ready; });
    });

    for (unsigned round = 0; round < 32; ++round) {
        const auto old = readers.back(); // Retain a finished object deliberately to model late wakes from old RPCs or callers.
        old->close();
        CHECK(old->wait(3s));
        auto fresh = core->reader({"routes", "main"}, {}, {});
        CHECK(fresh);
        readers.back() = std::move(*fresh);
        core->wake(old.get()); // New admission pruned the old directory; the old pointer remains valid but must not reenter the ready queue.
        eventually([&] { return readers.back()->load().state() == comet::Reader::State::Ready; });
    }
    CHECK(core->exceptions() == 0);
    const auto rounds = core->schedule(); // Targeted wakes covered every object; ready rounds must occur with at least one advancement per object.
    CHECK(rounds.ready > 0 && rounds.polled >= readers.size());
}

/// One login stream serves multiple objects; pages become visible only when complete, and retained views survive moves and closure.
void shared() {

    Fixture fixture;
    fixture.password(42);
    fixture.fill(1, 600);
    Client client(fixture.options());
    auto copy = client.value;
    auto first = copy.reader({"routes", "main"});
    auto exact = client.value.reader({"routes", "main"}, "key-599");
    CHECK(first && exact);
    eventually([&] { return first->load().state() == comet::Reader::State::Ready && exact->load().state() == comet::Reader::State::Ready; });
    const auto old = first->load();
    CHECK(old.size() == 600 && old.version() == 1 && exact->load().size() == 1);
    const auto original = old.find("key-0");
    CHECK(original && original->at(0) == 0);

    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{9}));
    eventually([&] { return first->load().version() == 2 && exact->load().version() == 2; });
    CHECK(first->load().find("key-0")->at(0) == 9);
    CHECK(old.find("key-0") == original && original->at(0) == 0);
    first->close();
    CHECK(first->wait(3s));
    CHECK(first->load().state() == comet::Reader::State::Closed);
    CHECK(fixture.library.apply({"routes", "main"}, 3, "key-599", astra::Almanac::Buffer{}));
    eventually([&] { return exact->load().version() == 3; });
    CHECK(exact->load().find("key-599") && exact->load().find("key-599")->empty());
    client.value.close();
    CHECK(copy.wait(3s));
    CHECK(old.size() == 600 && old.find("key-0") == original);
}

/// Invalid credentials fail without downgrade; updating SECRET recovers the same object without changing old bindings.
void authentication() {

    Fixture fixture;
    fixture.password(43);
    fixture.fill();
    Client client(fixture.options());
    auto reader = client.value.reader({"routes", "main"});
    CHECK(reader);
    eventually([&] { const auto view = reader->load(); return view.state() == comet::Reader::State::Failed && view.error() && view.error()->code == comet::Error::Code::Session; });
    CHECK(!reader->load().version());
    CHECK(client.value.secret({43}));
    eventually([&] { return reader->load().state() == comet::Reader::State::Ready; });
    const auto before = reader->load();
    fixture.password(44);
    eventually([&] { return reader->load().state() != comet::Reader::State::Ready; });
    CHECK(before.version() == 1 && before.size() == 1);
    CHECK(client.value.secret({44}));
    eventually([&] { return reader->load().state() == comet::Reader::State::Ready; });
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{7}));
    eventually([&] { return reader->load().version() == 2; });
}

/// Fail over sequentially after the first Star fails; retain old contents until the lagging target catches up and installs its new instance.
void failover() {

    Fixture first("star-first", false);
    Fixture second("star-second", false);
    first.fill(3);
    second.fill(1);
    auto options = first.options(false);
    options.endpoints.push_back(second.endpoint);
    Client client(std::move(options));
    auto reader = client.value.reader({"routes", "main"});
    CHECK(reader);
    eventually([&] { return reader->load().state() == comet::Reader::State::Ready; });
    CHECK(reader->load().version() == 3 && reader->load().instance() == "star-first");
    first.stop();
    eventually([&] { const auto view = reader->load(); return view.error() && view.error()->code == comet::Error::Code::Version; });
    CHECK(reader->load().version() == 3 && reader->load().instance() == "star-first");
    second.fill(3);
    eventually([&] { const auto view = reader->load(); return view.state() == comet::Reader::State::Ready && view.instance() == "star-second"; });
    CHECK(reader->load().version() == 3);
}

/// Observer exceptions are diagnosable; SDK waits are rejected, while observer-initiated nonblocking close prevents new notifications.
void callbacks() {

    Fixture fixture("star-test", false);
    fixture.fill();
    std::atomic_uint calls{}; // Callbacks are serial per object; atomics communicate with the assertion thread only.
    std::atomic_bool rejected{};
    Client client(fixture.options(false));
    comet::Reader::Options options;
    options.changed = [&](comet::Reader::View view) {
        if (view.state() != comet::Reader::State::Ready) {
            return;
        }
        calls.fetch_add(1);
        try {
            static_cast<void>(client.value.wait(0ms));
        } catch (const std::logic_error&) {
            rejected.store(true);
        }
        if (view.version() == 2) {
            client.value.close();
        }
        throw std::runtime_error("Deliberate observer exception");
    };
    auto reader = client.value.reader({"routes", "main"}, {}, std::move(options));
    CHECK(reader);
    eventually([&] { return client.value.exceptions() == 1 && rejected.load(); });
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{8}));
    CHECK(client.value.wait(3s));
    CHECK(calls.load() == 2 && client.value.exceptions() == 2);
    CHECK(reader->wait(0ms) && reader->load().state() == comet::Reader::State::Closed);
}

/// Repeated create, move, and close return application and actual-stream quota; releasing Client does not revoke live Readers.
void lifetime() {

    Fixture fixture("star-test", false, false);
    fixture.fill();
    auto options = fixture.options(false, false);
    options.readers = 1;
    Client client(std::move(options));
    for (unsigned round = 0; round < 40; ++round) {
        auto reader = client.value.reader({"routes", "main"});
        CHECK(reader);
        CHECK(!client.value.reader({"routes", "main"}));
        comet::Reader moved = std::move(*reader);
        eventually([&] { return moved.load().state() == comet::Reader::State::Ready; });
        moved.close();
        CHECK(moved.wait(3s));
    }
    auto final = client.value.reader({"routes", "main"});
    CHECK(final);
    eventually([&] { return final->load().version() == 1; });
    client.value = {}; // Reader's independent application ownership preserves subscription; an empty Client destructor does not close it.
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{6}));
    eventually([&] { return final->load().version() == 2; });
    final->close();
    CHECK(final->wait(3s));
}

/// Moving over a live reader closes its old intent without rebinding retained views or losing capacity.
void assignment() {

    // Distinct scopes and payloads expose accidental reuse of either reader's binding.
    Fixture fixture("star-assignment", false, false);
    fixture.fill();
    auto draft = fixture.library.prepare({"routes", "second"}, 2);
    CHECK(draft && draft->set("second", astra::Almanac::Buffer{7}));
    CHECK(fixture.library.reset(std::move(*draft)));
    std::atomic_uint released{}; // Outlives Client's joined callbacks, including exceptional exits.

    /// A unique callback capture records disposal without requiring a closing notification.
    struct Notice {
        /// Count destruction of the capture owned only by the displaced reader.
        ~Notice() noexcept {
            ++released;
        }

        /// Borrow the counter until Client finishes draining callbacks.
        std::atomic_uint& released;
    };

    auto options = fixture.options(false, false);
    options.readers = 2;
    Client client(std::move(options));
    comet::Reader::Options reading;
    reading.changed = [notice = std::make_unique<Notice>(released)](comet::Reader::View) { static_cast<void>(notice); };
    auto first = client.value.reader({"routes", "main"}, "key-0", std::move(reading));
    auto second = client.value.reader({"routes", "second"}, "second");
    CHECK(first && second && !client.value.reader({"routes", "main"}));
    eventually([&first, &second] { return first->state().state() == comet::Reader::State::Ready && second->state().state() == comet::Reader::State::Ready; });

    // Move construction empties its source; assignment must close the displaced live intent exactly once.
    const auto held = first->state();
    comet::Reader assigned = std::move(*first);
    CHECK(first->state().state() == comet::Reader::State::Waiting && first->wait(0ms));
    assigned = std::move(*second);
    CHECK(second->state().state() == comet::Reader::State::Waiting && second->wait(0ms));
    auto& alias = assigned; // Self assignment must preserve the replacement intent, not close it.
    assigned = std::move(alias);
    const auto current = assigned.state();
    CHECK(current.state() == comet::Reader::State::Ready && current.version() == 2);
    CHECK(current.scope().sector == "routes" && current.scope().spectrum == "second" && current.target() == "second");
    CHECK(current.find("second") && *current.find("second") == std::vector<std::uint8_t>{7} && !current.find("key-0"));
    eventually([&released] { return released.load() == 1; });

    // The displaced reader releases admission while its independent immutable view remains readable.
    auto recycled = client.value.reader({"routes", "main"}, "key-0");
    CHECK(recycled);
    eventually([&recycled] { return recycled->state().version() == 1; });
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{9}));
    eventually([&recycled] { return recycled->state().version() == 2; });
    CHECK(*recycled->state().find("key-0") == std::vector<std::uint8_t>{9});
    CHECK(held.version() == 1 && held.scope().sector == "routes" && held.scope().spectrum == "main" && held.target() == "key-0");
    CHECK(held.find("key-0") && *held.find("key-0") == std::vector<std::uint8_t>{0} && !held.find("second"));
    CHECK(assigned.state().find("second") == current.find("second"));

    // Empty assignment relinquishes the replacement; explicit client completion drains all real RPCs.
    assigned = comet::Reader{};
    CHECK(assigned.state().state() == comet::Reader::State::Waiting && assigned.wait(0ms));
    client.value.close();
    CHECK(client.value.wait(3s) && recycled->wait(0ms) && released.load() == 1);
}

/// Invalid local inputs send no network work: empty or duplicate endpoints, mixed TLS material, internal scope, and invalid capacity.
void inputs() {

    CHECK(!comet::Client::open({}));
    Fixture fixture("star-test", false);
    auto options = fixture.options(false);
    options.endpoints.push_back(fixture.endpoint);
    CHECK(!comet::Client::open(std::move(options)));
    options = fixture.options(false);
    options.tls = false;
    CHECK(!comet::Client::open(std::move(options)));
    options = fixture.options(false);
    options.ca = std::filesystem::path(ASTRA_FIXTURES) / "star-a" / "key.pem";
    CHECK(!comet::Client::open(std::move(options)));
    Client client(fixture.options(false));
    CHECK(!client.value.reader({"__auth", "keys"}));
    CHECK(!client.value.reader({"routes", "main"}, std::string(1025, 'x')));
    comet::Reader::Options small;
    small.bytes = 1;
    CHECK(!client.value.reader({"routes", "main"}, {}, std::move(small)));
    client.value.close();
    CHECK(!client.value.reader({"routes", "main"}));
    CHECK(client.value.wait(3s));
}

/// One Session serves Reader and Observer; Data-only updates share Attr, and closing one object leaves the other active.
void observers() {

    Fixture fixture;
    fixture.password(42);
    fixture.fill();
    Client client(fixture.options());
    auto reader = client.value.reader({"routes", "main"});
    auto observer = client.value.observer({"service", "main"});
    CHECK(reader && observer && !client.value.observer({"service", "main"}, "invalid"));
    eventually([&] { return reader->load().state() == comet::Reader::State::Ready && observer->select().state() == comet::Observer::State::Ready; });
    CHECK(observer->select().size() == 0 && observer->select().version() == 0);
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const astra::Ephemeris::Buffer>(32, 0xff);
    const auto data = std::make_shared<const astra::Ephemeris::Buffer>(3, 1);
    auto created = fixture.ephemeris.create(scope, attr, data, 1000);
    CHECK(created);
    eventually([&] { return observer->select().find(created->uuid).has_value(); });
    const auto held = observer->select();
    CHECK(fixture.ephemeris.update(scope, created->uuid, std::make_shared<const astra::Ephemeris::Buffer>(), 1));
    eventually([&] { const auto value = observer->select().find(created->uuid); return value && value->data->empty(); });
    CHECK(observer->select().find(created->uuid)->attr == held.find(created->uuid)->attr);
    auto exact = client.value.observer({"service", "main"}, created->uuid);
    CHECK(exact);
    eventually([&] { return exact->select().state() == comet::Observer::State::Ready; });
    CHECK(exact->select().size() == 1);
    fixture.now.store(2'000'000'000); // Server alone advances TTL; SDK does not fabricate expiration deletes.
    eventually([&] { return observer->select().size() == 0 && exact->select().size() == 0; });
    observer->close();
    CHECK(observer->wait(3s) && held.find(created->uuid)->data->size() == 3);
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{7}));
    eventually([&] { return reader->load().version() == 2; });
}

/// Ephemeris cursors are local to each Star; failover must install a complete new membership list even at a lower version.
void relocating() {

    Fixture first("star-first", false);
    Fixture second("star-second", false);
    const astra::Scope scope{"service", "main"};
    const auto value = std::make_shared<const astra::Ephemeris::Buffer>(1, 1);
    auto old = first.ephemeris.create(scope, value, value, 1000);
    auto replacement = second.ephemeris.create(scope, value, value, 1000);
    CHECK(old && replacement);
    for (std::uint64_t order = 1; order <= 8; ++order) {
        CHECK(first.ephemeris.update(scope, old->uuid, std::make_shared<const astra::Ephemeris::Buffer>(1, static_cast<std::uint8_t>(order + 1)), order));
    }
    auto options = first.options(false);
    options.endpoints.push_back(second.endpoint);
    Client client(std::move(options));
    auto observer = client.value.observer({"service", "main"});
    CHECK(observer);
    eventually([&] { return observer->select().version() == 9; });
    first.stop();
    eventually([&] { return observer->select().instance() == "star-second" && observer->select().state() == comet::Observer::State::Ready; });
    CHECK(observer->select().version() == 1 && observer->select().find(replacement->uuid) && !observer->select().find(old->uuid));
}

/// Changing future login credentials does not revoke a confirmed Session; the server controls its validity.
void preparedSecret() {

    Fixture fixture;
    fixture.password(42);
    fixture.fill();
    Client client(fixture.options());
    auto reader = client.value.reader({"routes", "main"});
    CHECK(reader);
    eventually([&] { return reader->load().state() == comet::Reader::State::Ready; });
    CHECK(client.value.secret({43})); // Server has not yet accepted the next authentication credentials.
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{2}));
    eventually([&] { return reader->load().version() == 2; }); // An invalid new local password must not break the current valid login.
    fixture.password(43);
    CHECK(fixture.library.apply({"routes", "main"}, 3, "key-0", astra::Almanac::Buffer{3}));
    eventually([&] { return reader->load().state() == comet::Reader::State::Ready && reader->load().version() == 3; });
}

/// Actual Create, Data, Renew, Remove, and Observer lifecycle; after UUID expiry, recover automatically with latest Data.
void beacons() {

    Fixture fixture;
    fixture.password(42);
    Client client(fixture.options());
    auto observer = client.value.observer({"service", "main"});
    auto beacon = client.value.beacon({"service", "main"}, {4, 5}, {}, 1s, 250ms);
    CHECK(observer && beacon);
    eventually([&] { return beacon->state().phase == comet::Beacon::Phase::Ready; });
    const auto old = *beacon->state().identity;
    eventually([&] { return observer->select().find(old.uuid).has_value(); });
    const auto receipt = beacon->update(std::vector<std::uint8_t>{7, 8});
    CHECK(receipt && receipt->identity == old && receipt->order == 1);
    eventually([&] { const auto value = observer->select().find(old.uuid); return value && *value->data == std::vector<std::uint8_t>({7, 8}); });
    eventually([&] {
        bool renewed{};
        fixture.ephemeris.source().each([&](const astra::Scope&, std::string_view uuid, const astra::Ephemeris::Record& record) { if (uuid == old.uuid) { renewed = record.renewal > 0; } });
        return renewed;
    });                                   // Observe actual native Renew order; SDK ready alone cannot prove renewal.
    fixture.now.fetch_add(2'000'000'000); // Original TTL expired; same-ID recovery is allowed only after a subsequent Renew explicitly reports ended.
    fixture.ephemeris.tick();
    eventually([&] {
        bool restored{};
        fixture.ephemeris.source().each([&](const astra::Scope&, std::string_view uuid, const astra::Ephemeris::Record& record) { if (uuid == old.uuid) { restored = record.generation > 1; } });
        return restored && beacon->state().phase == comet::Beacon::Phase::Ready;
    });
    const auto current = *beacon->state().identity;
    CHECK(current.uuid == old.uuid);
    eventually([&] { const auto value = observer->select().find(current.uuid); return value && observer->select().size() == 1 && *value->attr == std::vector<std::uint8_t>({4, 5}) && *value->data == std::vector<std::uint8_t>({7, 8}); });
    beacon->close();
    CHECK(beacon->wait(3s));
    eventually([&] { return observer->select().size() == 0; });
    CHECK(fixture.ephemeris.source().size() == 0);
    auto closed = beacon->update(std::vector<std::uint8_t>{1});
    CHECK(!closed && closed.error().code == comet::Error::Code::Closed);
}

/// Initial registration failure returns immediately; corrected credentials require explicit recreation without retained pending payload.
void deferred() {

    Fixture fixture;
    fixture.password(43);
    Client client(fixture.options());
    auto denied = client.value.beacon({"service", "main"}, {}, {1}, 1s, 250ms);
    CHECK(!denied && fixture.ephemeris.source().size() == 0);
    CHECK(!client.value.beacon({"service", "main"}, {}, {}, 999ms, 250ms));
    CHECK(!client.value.beacon({"service", "main"}, {}, {}, 1s, 1s));
    CHECK(client.value.secret({43}));
    CHECK(fixture.ephemeris.source().size() == 0);
    auto beacon = client.value.beacon({"service", "main"}, {}, {2}, 1s, 250ms);
    CHECK(beacon && beacon->state().phase == comet::Beacon::Phase::Ready);
    const auto identity = *beacon->state().identity;
    const auto installed = fixture.ephemeris.find({"service", "main"}, identity.uuid);
    CHECK(installed && installed->record && *installed->record->data == std::vector<std::uint8_t>({2}));
    const auto invalid = beacon->update(comet::Value{});
    CHECK(!invalid && invalid.error().code == comet::Error::Code::Input);
}

/// Shared Client closure retains the confirmed Session for one bounded removal; internal cleanup must not use the admission stop gate.
void closingBeacon() {

    Fixture fixture;
    fixture.password(42);
    Client client(fixture.options());
    auto beacon = client.value.beacon({"service", "main"}, {}, {}, 1s, 250ms);
    CHECK(beacon);
    eventually([&] { return beacon->state().phase == comet::Beacon::Phase::Ready; });
    CHECK(fixture.ephemeris.source().size() == 1);
    client.value.close();
    CHECK(client.value.wait(5s) && beacon->wait(0ms));
    CHECK(beacon->state().phase == comet::Beacon::Phase::Closed && fixture.ephemeris.source().size() == 0); // Business clock has not reached TTL; disappearance must come from actual removal.
}

/// Star failover preserves logical UUID through independent recovery capability, without inferring ownership from APIKEY.
void beaconRelocation() {

    Fixture first("star-first", false);
    Fixture second("star-second", false);
    auto options = first.options(false);
    options.endpoints.push_back(second.endpoint);
    Client client(std::move(options));
    auto beacon = client.value.beacon({"service", "main"}, {9}, {8}, 1s, 250ms);
    CHECK(beacon);
    eventually([&] { return beacon->state().phase == comet::Beacon::Phase::Ready; });
    const auto old = *beacon->state().identity;
    first.stop();
    eventually([&] { const auto state = beacon->state(); return state.phase == comet::Beacon::Phase::Ready && state.identity && state.identity->instance == "star-second"; });
    const auto current = *beacon->state().identity;
    CHECK(current.uuid == old.uuid && second.ephemeris.source().size() == 1);
}

/// Synchronous publishing manages versions internally and accepts empty payloads; old subscription views remain stable.
void publications() {

    Fixture fixture;
    fixture.password(42);
    Client client(fixture.options());
    auto publisher = client.value.publisher({"dynamic", "main"});
    auto subscriber = client.value.subscriber({"dynamic", "main"});
    auto exact = client.value.subscriber({"dynamic", "main"}, "key");
    CHECK(publisher && subscriber && exact);
    eventually([&] { return subscriber->watch().state() == comet::Subscriber::State::Ready; });
    CHECK(subscriber->watch().size() == 0 && fixture.catalog.source().position() == 0);
    const auto receipt = publisher->update("key", {7}, 1s); // Synchronous return confirms Star commit.
    CHECK(receipt && receipt->version == 1 && receipt->instance == "star-test");
    eventually([&] { const auto view = exact->watch(); return view.find("key") && view.find("key")->version == 1 && subscriber->watch().find("key").has_value(); });
    const auto old = subscriber->watch(); // Later Data must not change application-retained immutable snapshots.
    const auto newer = publisher->update("key", {}, 2s);
    CHECK(newer && newer->version == 2);
    eventually([&] { const auto view = subscriber->watch(); return view.find("key") && view.find("key")->version == 2; });
    CHECK(subscriber->watch().find("key")->value->empty() && old.find("key")->value->at(0) == 7);

    // Delete only when server business time expires; SDK neither deletes by local TTL nor renews automatically.
    fixture.now = 4'000'000'000;
    eventually([&] { return subscriber->watch().size() == 0 && exact->watch().size() == 0; });
    CHECK(fixture.catalog.source().size() == 1);
    auto restarted = client.value.publisher({"dynamic", "main"}); // New objects still Query expired watermarks instead of restarting at version one.
    CHECK(restarted);
    const auto restored = restarted->update("key", {9}, 1s);
    CHECK(restored && restored->version == 3);
    publisher->close();
    CHECK(publisher->wait(3s));
}

/// Independent writers sharing a Client impose no Scope-wide version; active writers do not block idle subscriptions.
void scheduling() {

    Fixture fixture("scheduling", false, false);
    Client client(fixture.options(false, false));
    std::vector<comet::Publisher> publishers;   // Each object binds a scope only; the application ensures unique written Keys.
    std::vector<comet::Subscriber> subscribers; // Independent long-lived subscriptions per Key.
    for (unsigned index = 0; index < 16; ++index) {
        const auto key = std::to_string(index); // Adjacent Keys may both use version one.
        auto publisher = client.value.publisher({"dynamic", "schedule"});
        auto subscriber = client.value.subscriber({"dynamic", "schedule"}, key);
        CHECK(publisher && subscriber);
        publishers.push_back(std::move(*publisher));
        subscribers.push_back(std::move(*subscriber));
        const auto result = publishers.back().update(key, {7}, 1s);
        CHECK(result && result->version == 1);
    }
    for (std::uint64_t version = 2; version <= 64; ++version) {
        const auto result = publishers.front().update("0", {8}, 1s); // Versions increment within each object without a public version argument.
        CHECK(result && result->version == version);
    }
    eventually([&] { return std::ranges::all_of(subscribers, [](const auto& subscriber) { return subscriber.watch().state() == comet::Subscriber::State::Ready && subscriber.watch().size() == 1; }); });
    CHECK(fixture.catalog.capture({"dynamic", "schedule"})->version() == 79);
    client.value.close();
    CHECK(client.value.wait(3s));
    for (const auto& subscriber : subscribers) {
        CHECK(subscriber.wait(0ms));
    }
}

/// Closing Client in a notification immediately rejects new writes without awaiting control-round return.
void publicationsClosed() {

    Fixture fixture("star-test", false);
    fixture.fill();
    Client client(fixture.options(false));
    auto publisher = client.value.publisher({"dynamic", "main"});
    CHECK(publisher && publisher->update("key", {7}, 1s));
    std::atomic_bool observed{}; // Main thread reads after the control round ends.
    comet::Reader::Options options;
    options.changed = [&](comet::Reader::View view) {
        if (view.state() == comet::Reader::State::Ready && view.version() == 2) {
            client.value.close();
            const auto result = publisher->update("key", {8}, 1s); // Closed-state rejection precedes callback-blocking checks.
            observed.store(!result && result.error().code == comet::Error::Code::Closed);
        }
    };
    auto reader = client.value.reader({"routes", "main"}, {}, std::move(options));
    CHECK(reader);
    eventually([&] { return reader->load().version() == 1; });
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{8}));
    CHECK(client.value.wait(3s));
    CHECK(observed.load() && publisher->wait(0ms));
}

/// Failover does not restore old Catalog Data automatically; a new explicit full commit creates missing target Keys.
void publicationsRelocation() {

    Fixture first("star-first", false), second("star-second", false);
    auto options = first.options(false);
    options.endpoints.push_back(second.endpoint);
    Client client(std::move(options));
    auto publisher = client.value.publisher({"dynamic", "main"});
    auto subscriber = client.value.subscriber({"dynamic", "main"});
    CHECK(publisher && subscriber);
    const auto initial = publisher->update("key", {1}, 1s);
    CHECK(initial && initial->version == 1);
    eventually([&] { return subscriber->watch().find("key").has_value(); });
    first.stop();
    eventually([&] { const auto view = subscriber->watch(); return view.state() == comet::Subscriber::State::Ready && view.instance() == "star-second"; });
    CHECK(!subscriber->watch().find("key") && second.catalog.source().position() == 0);
    const auto moved = publisher->update("key", {2}, 1s);
    CHECK(moved && moved->instance == "star-second" && moved->version > initial->version);
    eventually([&] { const auto row = subscriber->watch().find("key"); return row && row->version == moved->version; });
}

/// Authentication failure retains no pending Data; fixing credentials cannot submit the previous call silently.
void publicationsPending() {

    Fixture fixture;
    fixture.password(43);
    Client client(fixture.options());
    auto publisher = client.value.publisher({"dynamic", "main"});
    CHECK(publisher);
    const auto rejected = publisher->update("key", {9}, 1s, 500ms);
    CHECK(!rejected && rejected.error().effect == comet::Error::Effect::Unapplied);
    CHECK(client.value.secret({43}));
    auto subscriber = client.value.subscriber({"dynamic", "main"});
    CHECK(subscriber);
    eventually([&] { return subscriber->watch().state() == comet::Subscriber::State::Ready; });
    CHECK(subscriber->watch().size() == 0 && fixture.catalog.source().position() == 0);
    const auto explicitUpdate = publisher->update("key", {8}, 1s);
    CHECK(explicitUpdate && explicitUpdate->version == 1);
}

/// Static rejection sends no RPC and consumes no version; each call validates Key and TTL independently.
void publicationInputs() {

    Fixture fixture("inputs", false);
    Client client(fixture.options(false));
    auto publisher = client.value.publisher({"dynamic", "main"});
    CHECK(publisher);
    const auto data = std::make_shared<const std::vector<std::uint8_t>>(1, 7); // Both entries deliberately reference the same immutable value.
    CHECK(publisher->update({{"a", data}, {"a", data}}, 1s).error().code == comet::Error::Code::Input);
    CHECK(publisher->update({{"a", {}}}, 1s).error().code == comet::Error::Code::Input);
    CHECK(publisher->update("a", {7}, 0ms).error().code == comet::Error::Code::Input);
    CHECK(publisher->update("a", {7}, 1s, 0ms).error().code == comet::Error::Code::Input);
    CHECK(fixture.catalog.source().position() == 0);
    const auto result = publisher->update("a", {7}, 1s);
    CHECK(result && result->version == 1);
}

/// Observers attached after synchronization still receive a baseline; complete atomic batches distinguish missing Keys from valid empty values.
void watching() {

    Fixture fixture("star-watch", false);
    std::atomic_uint maps{}, exacts{}, states{}, baselines{}; // Client destruction waits for all notifications borrowing these references.
    std::atomic_bool valid{true};
    Client client(fixture.options(false));
    auto subscriber = client.value.subscriber({"dynamic", "callbacks"});
    auto exact = client.value.subscriber({"dynamic", "callbacks"}, "a");
    auto publisher = client.value.publisher({"dynamic", "callbacks"});
    CHECK(subscriber && exact && publisher);
    eventually([&] { return subscriber->state().state() == comet::Subscriber::State::Ready && exact->state().state() == comet::Subscriber::State::Ready; });
    CHECK(subscriber->watch([&](comet::Subscriber::Map map) {
        if (map.size() != 0 && map.size() != 2) {
            valid = false;
        }
        ++maps;
    }));
    CHECK(exact->watch([&](std::string key, std::optional<comet::Value> value) {
        if (key != "a" || (value && !(*value)->empty())) {
            valid = false;
        }
        ++exacts;
    }));
    CHECK(subscriber->changed([&](comet::Subscriber::View) { ++states; }));
    eventually([&] { return maps.load() == 1 && exacts.load() == 1 && states.load() > 0; });
    const auto empty = std::make_shared<const std::vector<std::uint8_t>>();
    CHECK(publisher->update({{"a", empty}, {"b", empty}}, 1s));
    eventually([&] { return maps.load() >= 2 && exacts.load() >= 2; });
    const auto held = subscriber->state();
    CHECK(held.size() == 2 && held.find("a")->value->empty() && valid.load());
    subscriber->stop();
    CHECK(subscriber->wait(3s));
    CHECK(!subscriber->watch([](comet::Subscriber::Map) {}));
    CHECK(held.size() == 2);

    auto reader = client.value.reader({"routes", "callbacks"});
    CHECK(reader);
    CHECK(reader->watch([&](comet::Reader::Map map) { if (map.size() != 0) { valid = false; } ++baselines; }));
    eventually([&] { return baselines.load() == 1; });
    reader->stop();
    CHECK(reader->wait(3s) && valid.load());
}

/// selector runs outside the short lock; estimates affect later selection, while new authority values and stop reject stale-view writes.
void choosing() {

    Fixture fixture("star-pool", false);
    Client client(fixture.options(false));
    auto beacon = client.value.beacon({"service", "pool"}, {1}, {2}, 1s, 250ms);
    auto observer = client.value.observer({"service", "pool"});
    CHECK(beacon && observer);
    const auto id = beacon->state().identity->uuid;
    eventually([&] { return observer->select().state() == comet::Observer::State::Ready && observer->select().find(id); });
    // Selection and traversal callbacks may reenter the same observer without retaining an SDK lock.
    const auto select = [&observer, &id](const comet::Observer::Pool& pool) {
        CHECK(pool.size() == 1 && observer->select().find(id));
        unsigned count{}; // Every fixed pool contains the one independently registered Beacon.
        pool.each([&id, &count](comet::Observer::Item item) {
            CHECK(item.id() == id && item.record().attr && item.record().data);
            ++count;
        });
        CHECK(count == 1);

        const auto nested = observer->one([&id](const comet::Observer::Pool& current) {
            CHECK(current.size() == 1);
            return current.find(id);
        });
        CHECK(nested && *nested && (*nested)->id() == id);
        return pool.find(id);
    };
    auto selected = observer->one(select);
    CHECK(selected && *selected);
    auto old = **selected; // Independently retained old estimate token for the same authority value.
    CHECK((*selected)->update(std::vector<std::uint8_t>{3}));
    CHECK(!old.update(std::vector<std::uint8_t>{4}));
    auto next = observer->one(select);
    CHECK(next && *next && *(*next)->record().data == std::vector<std::uint8_t>{3});
    CHECK(beacon->update(std::vector<std::uint8_t>{5}));
    eventually([&] { return *observer->select().find(id)->data == std::vector<std::uint8_t>{5}; });
    CHECK(!(*selected)->update(std::vector<std::uint8_t>{6}));
    auto fresh = observer->one(select);
    CHECK(fresh && *fresh && *(*fresh)->record().data == std::vector<std::uint8_t>{5});
    observer->stop();
    CHECK(!observer->one(select) && !(*fresh)->update(std::vector<std::uint8_t>{7}));
    CHECK(*old.record().data == std::vector<std::uint8_t>{2});
}

/// After a callback removes itself, final capture destruction may reenter state reads; Watching's state lock must be released.
void captures() {

    Fixture fixture("star-captures", false);
    std::atomic_uint released{}; // Remains valid until Client drains.
    Client client(fixture.options(false));
    auto opened = client.value.subscriber({"dynamic", "captures"});
    CHECK(opened);
    auto subscriber = std::make_shared<comet::Subscriber>(std::move(*opened));

    /// Keep a Subscriber alive until capture destruction completes its reentrant state query.
    struct Capture {
        /// Retains the reentrant handle until capture release, without stack borrowing.
        std::shared_ptr<comet::Subscriber> owner;
        /// Borrow the counter proving the captured object was released at the expected lifetime boundary.
        std::atomic_uint& released;

        ~Capture() {
            static_cast<void>(owner->state());
            ++released;
        }
    };

    CHECK(subscriber->watch([capture = std::make_shared<Capture>(subscriber, released)](comet::Subscriber::Map) {
        CHECK(capture->owner->watch(std::move_only_function<void(comet::Subscriber::Map)>{}));
    }));
    eventually([&] { return released.load() == 1; });
    CHECK(subscriber->changed([capture = std::make_shared<Capture>(subscriber, released)](comet::Subscriber::View) {
        CHECK(capture->owner->changed({}));
    }));
    eventually([&] { return released.load() == 2; });
    subscriber->stop();
    CHECK(subscriber->wait(3s) && client.value.exceptions() == 0);
}

// Exercise public callback ownership, exact Almanac updates, and borrowed Beacon payloads in the existing real-service fixture.
namespace reading {
/// Compare every callback snapshot with three independently specified Almanac states, retaining the first root across later commits.
void maps() {

    Fixture fixture("reader-maps", false, false);
    fixture.fill(1, 2);
    const std::array<std::map<std::string, std::vector<std::uint8_t>>, 3> model{{{{"key-0", {0}}, {"key-1", {1}}}, {{"key-0", {9, 10}}, {"key-1", {1}}}, {{"key-1", {1}}}}}; // Literal expectations do not borrow production history or index helpers.
    std::mutex mutex;                                                                                                                                                        // Receipt storage outlives the Client and its drained callback domain.
    std::vector<comet::Reader::Map> maps;
    std::vector<std::pair<std::string, std::optional<comet::Value>>> exacts;
    std::atomic_uint states{};
    Client client(fixture.options(false, false));
    auto all = client.value.reader({"routes", "main"});
    auto exact = client.value.reader({"routes", "main"}, "key-0");
    CHECK(all && exact);
    eventually([&all, &exact] { return all->state().state() == comet::Reader::State::Ready && exact->state().state() == comet::Reader::State::Ready; });

    CHECK(all->changed([&states](comet::Reader::View view) {
        CHECK(view.scope() == comet::Scope("routes", "main") && view.target().empty());
        ++states;
    }));
    CHECK(all->watch([&mutex, &maps, &model](comet::Reader::Map map) {
        CHECK(map.version() && *map.version() >= 1 && *map.version() <= model.size());
        const auto& expected = model[*map.version() - 1];
        CHECK(map.size() == expected.size());
        for (const auto& [key, data] : expected) {
            const auto value = map.find(key);
            CHECK(value && *value == data);
        }

        const std::lock_guard lock(mutex);
        if (maps.empty() || maps.back().version() != map.version()) {
            maps.push_back(std::move(map));
        }
    }));
    CHECK(exact->watch([&mutex, &exacts](std::string key, std::optional<comet::Value> value) {
        CHECK(key == "key-0" && (!value || (*value && (**value == std::vector<std::uint8_t>{0} || **value == std::vector<std::uint8_t>{9, 10}))));

        const std::lock_guard lock(mutex);
        exacts.emplace_back(std::move(key), std::move(value));
    }));
    eventually([&mutex, &maps, &exacts, &states] {
        const std::lock_guard lock(mutex);
        return !maps.empty() && maps.back().version() == 1 && !exacts.empty() && exacts.back().second && states.load() > 0;
    });
    const auto frozen = all->state(); // This completed root must survive update, deletion and local stop.
    CHECK(frozen.version() == 1 && frozen.size() == 2 && *frozen.find("key-0") == std::vector<std::uint8_t>{0});

    const auto wrongExact = all->watch(std::move_only_function<void(std::string, std::optional<comet::Value>)>{});
    const auto wrongMap = exact->watch(std::move_only_function<void(comet::Reader::Map)>{});
    CHECK(!wrongExact && wrongExact.error().code == comet::Error::Code::Input && wrongExact.error().effect == comet::Error::Effect::Unapplied);
    CHECK(!wrongMap && wrongMap.error().code == comet::Error::Code::Input && wrongMap.error().effect == comet::Error::Effect::Unapplied);
    CHECK(fixture.library.apply({"routes", "main"}, 2, "key-0", astra::Almanac::Buffer{9, 10}));
    eventually([&mutex, &maps, &exacts] {
        const std::lock_guard lock(mutex);
        return maps.back().version() == 2 && exacts.back().second && **exacts.back().second == std::vector<std::uint8_t>{9, 10};
    });
    CHECK(fixture.library.apply({"routes", "main"}, 3, "key-0", std::nullopt));
    eventually([&mutex, &maps, &exacts] {
        const std::lock_guard lock(mutex);
        return maps.back().version() == 3 && !exacts.back().second;
    });

    CHECK(all->watch(std::move_only_function<void(comet::Reader::Map)>{}) && exact->watch(std::move_only_function<void(std::string, std::optional<comet::Value>)>{}));
    CHECK(all->changed({}));
    all->stop();
    exact->stop();
    CHECK(all->wait(3s) && exact->wait(3s) && client.value.exceptions() == 0);
    CHECK(all->state().state() == comet::Reader::State::Closed && all->state().version() == 3);
    CHECK(frozen.version() == 1 && frozen.size() == 2 && *frozen.find("key-0") == std::vector<std::uint8_t>{0});
    CHECK(maps.size() == 3 && maps[0].version() == 1 && maps[1].version() == 2 && maps[2].version() == 3);
    const auto reject = [](const auto& result) { CHECK(!result && result.error().code == comet::Error::Code::Closed && result.error().effect == comet::Error::Effect::Unapplied); };
    reject(all->changed({}));
    reject(all->watch(std::move_only_function<void(comet::Reader::Map)>{}));
    reject(exact->watch(std::move_only_function<void(std::string, std::optional<comet::Value>)>{}));
    comet::Reader empty; // A default handle has no transport to receive a callback or perform a write.
    reject(empty.changed({}));
    reject(empty.watch(std::move_only_function<void(comet::Reader::Map)>{}));
    reject(empty.watch(std::move_only_function<void(std::string, std::optional<comet::Value>)>{}));
}

/// Self-removal releases each last callback capture outside the reader lock and permits destructor reentry into the same handle.
void captures() {

    Fixture fixture("reader-captures", false, false);
    fixture.fill();
    std::atomic_uint released{}; // Remains alive until all Client callbacks have drained, including failure unwinding.
    Client client(fixture.options(false, false));
    auto opened = client.value.reader({"routes", "main"});
    auto selected = client.value.reader({"routes", "main"}, "key-0");
    CHECK(opened && selected);
    auto all = std::make_shared<comet::Reader>(std::move(*opened));
    auto exact = std::make_shared<comet::Reader>(std::move(*selected));
    eventually([&all, &exact] { return all->state().state() == comet::Reader::State::Ready && exact->state().state() == comet::Reader::State::Ready; });

    /// An owning callback receipt observes release and reenters its public owner without borrowing a stack handle.
    struct Capture {
        /// Keeps the application handle valid until its last callback reference is released.
        std::shared_ptr<comet::Reader> owner;
        /// Refers to a counter whose lifetime encloses the complete Client task domain.
        std::atomic_uint& released;

        /// Reentrant state inspection must complete before reporting physical capture release.
        ~Capture() {
            static_cast<void>(owner->state());
            ++released;
        }
    };

    CHECK(all->watch([capture = std::make_unique<Capture>(all, released)](comet::Reader::Map map) {
        CHECK(map.version() == 1 && map.size() == 1);
        CHECK(capture->owner->watch(std::move_only_function<void(comet::Reader::Map)>{}));
    }));
    eventually([&released] { return released.load() == 1; });
    CHECK(exact->watch([capture = std::make_unique<Capture>(exact, released)](std::string key, std::optional<comet::Value> value) {
        CHECK(key == "key-0" && value && *value && **value == std::vector<std::uint8_t>{0});
        CHECK(capture->owner->watch(std::move_only_function<void(std::string, std::optional<comet::Value>)>{}));
    }));
    eventually([&released] { return released.load() == 2; });
    CHECK(all->changed([capture = std::make_unique<Capture>(all, released)](comet::Reader::View view) {
        CHECK(view.version() == 1);
        CHECK(capture->owner->changed({}));
    }));
    eventually([&released] { return released.load() == 3; });

    all->stop();
    exact->stop();
    CHECK(all->wait(3s) && exact->wait(3s) && released.load() == 3 && client.value.exceptions() == 0);
}
} // namespace reading

namespace beaming {
/// Borrowed inputs become owned records; valid empty values remain distinct from missing values and rejected oversize requests consume no order.
void spans() {

    Fixture fixture("beacon-spans", false, false);
    Client client(fixture.options(false, false));
    auto beacon = client.value.beacon({"service", "spans"}, {3}, {4}, 1s, 250ms);
    auto observer = client.value.observer({"service", "spans"});
    CHECK(beacon && observer && beacon->state().identity);
    const auto identity = *beacon->state().identity;
    eventually([&observer, &identity] { return observer->select().find(identity.uuid).has_value(); });
    const auto frozen = observer->select(); // Old views retain the Create payload after the borrowed source is overwritten.
    CHECK(*frozen.find(identity.uuid)->data == std::vector<std::uint8_t>{4});

    std::array<std::uint8_t, 3> data{7, 8, 9}; // Borrowing lasts only for the synchronous public update call.
    const auto first = beacon->update(std::span<const std::uint8_t>(data));
    CHECK(first && first->identity == identity && first->order == 1);
    data.fill(0);
    eventually([&observer, &identity] {
        const auto record = observer->select().find(identity.uuid);
        return record && *record->data == std::vector<std::uint8_t>{7, 8, 9};
    });
    const auto empty = beacon->update(std::span<const std::uint8_t>{});
    CHECK(empty && empty->identity == identity && empty->order == first->order + 1);
    eventually([&observer, &identity] {
        const auto record = observer->select().find(identity.uuid);
        return record && record->data && record->data->empty();
    });

    const std::vector<std::uint8_t> oversized(1024 * 1024 + 1, 1); // Exceeds the existing Beacon value contract, not the unbounded Almanac batch contract.
    const auto invalid = beacon->update(std::span<const std::uint8_t>(oversized));
    CHECK(!invalid && invalid.error().code == comet::Error::Code::Input && invalid.error().effect == comet::Error::Effect::Unapplied);
    CHECK(observer->select().find(identity.uuid)->data->empty());
    const auto next = beacon->update(std::span<const std::uint8_t>(data));
    CHECK(next && next->identity == identity && next->order == empty->order + 1);
    eventually([&observer, &identity] {
        const auto record = observer->select().find(identity.uuid);
        return record && *record->data == std::vector<std::uint8_t>{0, 0, 0};
    });
    CHECK(*frozen.find(identity.uuid)->data == std::vector<std::uint8_t>{4});

    beacon->close();
    CHECK(beacon->wait(3s));
    eventually([&observer] { return observer->select().size() == 0; });
    const auto closed = beacon->update(std::span<const std::uint8_t>(data));
    CHECK(!closed && closed.error().code == comet::Error::Code::Closed && closed.error().effect == comet::Error::Effect::Unapplied);
    comet::Beacon absent; // The empty-handle branch rejects before transferring any borrowed payload.
    const auto missing = absent.update(std::span<const std::uint8_t>(data));
    CHECK(!missing && missing.error().code == comet::Error::Code::Closed && missing.error().effect == comet::Error::Effect::Unapplied);
    CHECK(client.value.exceptions() == 0);
}
} // namespace beaming

} // namespace

/// Runs client connection, handle, callback, and lifetime cases.
int main() {
    try {
        const auto started = std::chrono::steady_clock::now(); // Bind completed scenarios to one monotonic timeline without changing any deadline.
        // Preserve the exact scenario list and deadlines, while retaining the failing scenario in native logs.
        for (const auto& [name, action] : std::array<std::pair<const char*, void (*)()>, 28>{
                 std::pair{"reader-maps", &reading::maps},
                 std::pair{"reader-captures", &reading::captures},
                 std::pair{"beacon-spans", &beaming::spans},
                 std::pair{"captures", &captures},
                 std::pair{"watching", &watching},
                 std::pair{"choosing", &choosing},
                 std::pair{"inputs", &inputs},
                 std::pair{"cleanup", &cleanup},
                 std::pair{"queued", &queued},
                 std::pair{"shared", &shared},
                 std::pair{"authentication", &authentication},
                 std::pair{"prepared_secret", &preparedSecret},
                 std::pair{"observers", &observers},
                 std::pair{"beacons", &beacons},
                 std::pair{"publications", &publications},
                 std::pair{"scheduling", &scheduling},
                 std::pair{"publications_closed", &publicationsClosed},
                 std::pair{"publications_relocation", &publicationsRelocation},
                 std::pair{"publications_pending", &publicationsPending},
                 std::pair{"publication_inputs", &publicationInputs},
                 std::pair{"deferred", &deferred},
                 std::pair{"closing_beacon", &closingBeacon},
                 std::pair{"beacon_relocation", &beaconRelocation},
                 std::pair{"relocating", &relocating},
                 std::pair{"failover", &failover},
                 std::pair{"callbacks", &callbacks},
                 std::pair{"assignment", &assignment},
                 std::pair{"lifetime", &lifetime}}) {
            std::cout << "COMET-CASE " << name << std::endl;
            action();
            std::cout << "COMET-TIMING " << name << ' ' << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count() << ' ' << astra::test::checks.hits.load(std::memory_order_relaxed) << std::endl;
        }
        std::cout << "comet client tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
