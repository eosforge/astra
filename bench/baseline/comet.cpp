// Adapt the shared application baseline workload to the public Comet C++ SDK.
#include "workload.hpp"
#include <comet/client.hpp>

namespace {
/// Use only public Comet APIs with the same logical objects and shared-client counts as the Redis adapter.
class Adapter {
public:
    /// Borrow configuration through destruction and construct real registration/publication handles rather than writing Star internals.
    explicit Adapter(const Workload::Options& options) : options_(options) {

        Workload::check(!options.catalog || options.ttl >= (options.seconds + 120) * 1000U, "Catalog TTL must cover setup, sampling and drain; SDK does not renew");
        const Workload::Route route(options); // Pin each Client to one endpoint, with local writers on every Star in a topology of at least three nodes.
        for (std::size_t index = 0; index < options.clients * 2; ++index) {
            comet::Client::Options settings; // The first half are producers and the second half consumers; both disable business TLS/authentication.
            settings.endpoints = {index < options.clients ? route.producer(index) : route.consumer(index - options.clients)};
            settings.auth = false;
            settings.tls = false;
            settings.readers = 128;
            clients_.push_back(take(comet::Client::open(std::move(settings))));
        }
        for (std::size_t record = 0; record < options.records; ++record) {
            auto& client = clients_[record % options.clients]; // Assign a fixed producer so each object has only one writer.
            auto value = Workload::content(options.bytes, record, 1);
            if (options.catalog) {
                publishers_.push_back(take(client.publisher(scope(record % options.groups))));
                static_cast<void>(take(publishers_.back().update("key" + std::to_string(record), std::move(value), std::chrono::milliseconds(options.ttl), std::chrono::milliseconds(options.ttl / 3))));
            } else {
                beacons_.push_back(take(client.beacon(scope(record % options.groups), std::vector<std::uint8_t>(options.attr, 17), std::move(value), std::chrono::milliseconds(options.ttl), std::chrono::milliseconds(options.ttl / 3))));
            }
        }

        // A consumer Client may own multiple subscriptions; independent HTTP/2 streams are not independent TCP connections.

        for (std::size_t watcher = 0; watcher < options.groups * options.fanout; ++watcher) {
            auto& client = clients_[options.clients + watcher % options.clients];
            if (options.catalog) {
                subscribers_.push_back(take(client.subscriber(scope(watcher / options.fanout))));
            } else {
                observers_.push_back(take(client.observer(scope(watcher / options.fanout))));
            }
        }
    }

    /// Request every core to stop before waiting; retain handles and views until drainage, including exception paths.
    ~Adapter() {
        for (auto& client : clients_) {
            client.close();
        }
        for (auto& client : clients_) {
            if (!client.wait(std::chrono::seconds(10))) {
                std::terminate();
            }
        }
    }

    /// Return only after the server acknowledges the write; application versions live in the shared payload while the SDK owns Catalog protocol versions.
    void write(std::size_t record, std::uint64_t, std::vector<std::uint8_t> value) {
        if (options_.catalog) {
            static_cast<void>(take(publishers_[record].update("key" + std::to_string(record), std::move(value), std::chrono::milliseconds(options_.ttl))));
        } else {
            static_cast<void>(take(beacons_[record].update(std::move(value))));
        }
    }

    /// Traverse public read-only Views without adding newer changed callbacks to the old-SDK comparison.
    void scan(std::size_t watcher, auto&& receive) {
        if (options_.catalog) {
            const auto view = subscribers_[watcher].watch();
            Workload::check(!view.error(), "Comet Subscriber error");
            view.each([&](std::string_view, const comet::Subscriber::Record& value) { receive(std::span<const std::uint8_t>(*value.value)); });
        } else {
            const auto view = observers_[watcher].select(); // Check Attr length in the hot path and its complete contents after the timed window.
            Workload::check(!view.error(), "Comet Observer error");
            view.each([&](std::string_view, const comet::Observer::Record& value) {
                Workload::check(value.attr->size() == options_.attr, "Comet Attr length mismatch");
                receive(std::span<const std::uint8_t>(*value.data));
            });
        }
    }

    /// Any asynchronous SDK error invalidates the sample.
    void verify() {

        // Fixed Attr data is outside write timing, but final verification must compare bytes rather than length alone.
        for (const auto& observer : observers_) {
            observer.select().each([&](std::string_view, const comet::Observer::Record& value) { Workload::check(value.attr->size() == options_.attr && std::ranges::all_of(*value.attr, [](auto byte) { return byte == 17; }), "Comet final Attr mismatch"); });
        }

        for (const auto& client : clients_) {
            Workload::check(client.exceptions() == 0, "Comet asynchronous exception");
        }
    }

private:
    /// Borrow validated configuration until the shared workload and all adapter activity finish.
    const Workload::Options& options_;
    /// Separate shared network cores for producers and consumers.
    std::vector<comet::Client> clients_;
    /// Own the Catalog writer handles assigned to the workload records.
    std::vector<comet::Publisher> publishers_;
    /// Keep ordinary automatic lease renewal enabled.
    std::vector<comet::Beacon> beacons_;
    /// Each scope has fanout independent subscriptions.
    std::vector<comet::Subscriber> subscribers_;
    /// Own Ephemeris subscriptions used to scan complete registration views.
    std::vector<comet::Observer> observers_;

    /// Align Scope names with old Type/Part names; zero-based group numbers isolate fixture data.
    static comet::Scope scope(std::size_t group) {
        return {"Baseline", "Group" + std::to_string(group)};
    }

    /// Move successful results out by value and preserve SDK errors without implicit retries.
    template <class Result>
    static typename Result::value_type take(Result result) {
        if (!result) {
            throw std::runtime_error("Comet error " + std::to_string(static_cast<int>(result.error().code)));
        }
        return std::move(*result);
    }
};
} // namespace

/// Use a separate process to isolate newer BoringSSL symbols from the old SDK's OpenSSL symbols.
int main(int count, char** arguments) {
    try {
        Workload::run<Adapter>(Workload::parse(count, arguments));
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
