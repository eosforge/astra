// Adapt the shared application baseline workload to the legacy Redis C++ SDK in a separate process.
#include "workload.hpp"

#include <verdandi/catalog/catalog.hpp>
#include <verdandi/registration/registration.hpp>
#include <verdandi/registration/selector.hpp>

namespace {
/// Adapt the frozen SDK's public API without altering threads, scripts or Pub/Sub behavior.
class Adapter {
    /// Store the complete binary payload in one field.
    using Registration = verdandi::registration::registration<verdandi::fields, verdandi::fields>;
    /// Borrow the projection instead of copying a full snapshot.
    using Selector = verdandi::registration::selector<verdandi::fields, verdandi::fields>;

public:
    /// The outer runner owns and resets this exclusive Redis instance for each scenario.
    explicit Adapter(const Workload::Options& options) : options_(options) {

        for (std::size_t index = 0; index < options.clients * 2; ++index) {
            verdandi::redis_configuration settings; // Record the connection-pool limit explicitly; the SDK determines idle and Pub/Sub connections.
            settings.addresses = {options.endpoint};
            settings.timeout = std::chrono::seconds(5);
            settings.pool.max_connections = 32;
            clients_.push_back(take(verdandi::client::open(settings)));
            if (options.catalog) {
                verdandi::catalog_configuration configuration; // Disable local SQLite checkpoints to compare shared in-memory semantics.
                configuration.zone = "Baseline";
                catalogs_.push_back(take(verdandi::catalog::client::open(clients_.back(), configuration)));
            } else {
                verdandi::registrationConfiguration configuration; // Default coalescing to zero; the comparison can explicitly restore the old SDK's default window.
                configuration.zone = "Baseline";
                configuration.selector.view_publish_interval = std::chrono::milliseconds(options.legacy);
                configuration.policy.attr_value_max_bytes = options.attr;
                configuration.policy.data_value_max_bytes = options.bytes;
                configuration.policy.record_max_bytes = 65536;
                registrations_.push_back(take(verdandi::registration::client::open(clients_.back(), configuration)));
            }
        }
        for (std::size_t record = 0; record < options.records; ++record) {
            const auto value = fields(Workload::content(options.bytes, record, 1)); // Use the same initial payload, with only the old protocol's field wrapper added.
            if (options.catalog) {
                paths_.push_back(take(verdandi::catalog::path::create(group(record % options.groups), "key" + std::to_string(record))));
                publishers_.push_back(take(verdandi::catalog::publisher::create(catalogs_[record % options.clients])));
                static_cast<void>(take(publishers_.back().replace(paths_.back(), verdandi::catalog::kind::map, value)));
            } else {
                verdandi::registration::options settings; // Match Comet TTL/automatic renewal and start the application version at one.
                settings.type = group(record % options.groups);
                settings.ttl = std::chrono::milliseconds(options.ttl);
                settings.version = 1;
                records_.push_back(take(Registration::create(registrations_[record % options.clients], settings)));
                accepted(records_.back().publish(fields(std::vector<std::uint8_t>(options.attr, 17)), value));
            }
        }

        // Each watcher is an independent Selector/Subscriber, not another callback on the same object.

        for (std::size_t watcher = 0; watcher < options.groups * options.fanout; ++watcher) {
            const auto client = options.clients + watcher % options.clients; // Consumer clients use separate pools from producers.
            if (options.catalog) {
                verdandi::catalog::subscription subscription;
                subscription.parts = {group(watcher / options.fanout)};
                subscribers_.push_back(take(verdandi::catalog::subscriber::create(catalogs_[client], std::move(subscription))));
                entries_.emplace_back();
                for (std::size_t record = watcher / options.fanout; record < options.records; record += options.groups) {
                    entries_.back().push_back(subscribers_.back()->find(paths_[record]));
                    Workload::check(static_cast<bool>(entries_.back().back()), "Missing legacy Entry");
                }
            } else {
                selectors_.push_back(take(Selector::create(registrations_[client], {group(watcher / options.fanout)})));
            }
        }
    }

    /// Drain domain clients before closing root transport; member RAII also handles partial initialization failure.
    ~Adapter() {
        for (auto& client : catalogs_) {
            static_cast<void>(client.close());
        }
        for (auto& client : registrations_) {
            static_cast<void>(client.close());
        }
        for (auto& client : clients_) {
            static_cast<void>(client.close());
        }
    }

    /// The server owns protocol versions; the shared payload carries application versions for end-to-end checks.
    void write(std::size_t record, std::uint64_t, std::vector<std::uint8_t> value) {
        const auto encoded = fields(value); // Include the old Fields API's real encoding and copying costs.
        if (options_.catalog) {
            static_cast<void>(take(publishers_[record].replace(paths_[record], verdandi::catalog::kind::map, encoded)));
        } else {
            accepted(records_[record].update(encoded));
        }
    }

    /// Borrow the candidate set and return an empty selection to avoid detached-record copies; decode Catalog through public Entry.
    void scan(std::size_t watcher, auto&& receive) {
        if (options_.catalog) {
            for (const auto& entry : entries_[watcher]) {
                const auto loaded = take(entry->load<verdandi::fields>()); // Read one immutable state rather than combining separate observations.

                if (loaded.value && loaded.state == verdandi::catalog::status::present) {
                    receive(bytes(*loaded.value));
                }
            }
        } else {
            const auto result = selectors_[watcher]->one([&](auto& candidates) -> verdandi::result<std::optional<verdandi::registration::choice>> {
                for (std::size_t index = 0; index < candidates.size(); ++index) {
                    const auto value = candidates.get(index); // Borrow only within the current transaction callback.
                    Workload::check(value.has_value(), "Invalid legacy candidate");
                    Workload::check(bytes(value->attr()).size() == options_.attr, "Legacy Attr length mismatch");
                    receive(bytes(value->data()));
                }
                return std::optional<verdandi::registration::choice>{};
            });
            if (!result) {
                const auto diagnostic = selectors_[watcher]->try_error(); // Retain SDK diagnostics and do not retry or suppress unavailable results.
                throw std::runtime_error(result.error().message() + (diagnostic ? " / " + diagnostic->message() : " / no queued diagnostic"));
            }
        }
    }

    /// Background synchronization or renewal errors invalidate the sample, including reconnect/recovery failures.
    void verify() {

        // Verify complete fixed Attr bytes after the window, matching Comet without adding hot-path scans.
        for (const auto& selector : selectors_) {
            static_cast<void>(take(selector->one([&](auto& candidates) -> verdandi::result<std::optional<verdandi::registration::choice>> {
                for (std::size_t index = 0; index < candidates.size(); ++index) {
                    const auto value = candidates.get(index); // Borrow the current transaction's fixed Attr value.
                    Workload::check(value.has_value(), "Invalid final legacy candidate");
                    const auto attr = bytes(value->attr()); // Do not copy the payload owned by Fields.
                    Workload::check(attr.size() == options_.attr && std::ranges::all_of(attr, [](auto byte) { return byte == 17; }), "Legacy final Attr mismatch");
                }
                return std::optional<verdandi::registration::choice>{};
            })));
        }

        for (auto& value : records_) {
            Workload::check(!value.try_error(), "Legacy registration diagnostic");
        }
        for (auto& value : selectors_) {
            Workload::check(!value->try_error(), "Legacy Selector diagnostic");
        }
        for (auto& value : subscribers_) {
            Workload::check(!value->try_error(), "Legacy Subscriber diagnostic");
        }
    }

private:
    /// Borrow the same validated configuration used by the Comet comparison adapter.
    const Workload::Options& options_;
    /// The root connection pool is destroyed last.
    std::vector<verdandi::client> clients_;
    /// Own legacy Catalog clients for the configured producer and consumer connections.
    std::vector<verdandi::catalog::client> catalogs_;
    /// Own legacy registration clients until every registration and selector is drained.
    std::vector<verdandi::registration::client> registrations_;
    /// Keep legacy Catalog paths stable for publishers and subscriptions.
    std::vector<verdandi::catalog::path> paths_;
    /// Own legacy Catalog publishers for the configured records.
    std::vector<verdandi::catalog::publisher> publishers_;
    /// Retain the registration records and their renewal ownership for the workload lifetime.
    std::vector<Registration> records_;
    /// Unique pointers own the old SDK's nonmovable objects.
    std::vector<std::unique_ptr<Selector>> selectors_;
    /// Own Catalog subscriptions whose complete snapshots feed workload scans.
    std::vector<std::unique_ptr<verdandi::catalog::subscriber>> subscribers_;
    /// Cache public stable Entry objects, without a private-data bypass.
    std::vector<std::vector<std::shared_ptr<verdandi::catalog::entry>>> entries_;

    /// Type and Part use the same group name; its ASCII initial satisfies old protocol rules.
    static std::string group(std::size_t index) {
        return "Group" + std::to_string(index);
    }

    /// Fields wraps one body field without introducing JSON/base64 overhead.
    static verdandi::fields fields(std::span<const std::uint8_t> value) {
        const auto source = std::as_bytes(value);
        return {{"body", verdandi::bytes(source.begin(), source.end())}};
    }

    /// The returned span borrows Fields and cannot outlive it.
    static std::span<const std::uint8_t> bytes(const verdandi::fields& value) {
        const auto found = value.find("body"); // Require exactly one field; do not create missing entries silently.
        Workload::check(found != value.end() && value.size() == 1, "Malformed legacy Fields");
        return {reinterpret_cast<const std::uint8_t*>(found->second.data()), found->second.size()};
    }

    /// Preserve SDK error text without retries that could hide request failures.
    template <class Result>
    static typename Result::value_type take(Result result) {
        if (!result) {
            throw std::runtime_error(result.error().message());
        }
        return std::move(*result);
    }

    /// Handle void and value results separately to avoid dereferencing void in templates.
    static void accepted(verdandi::result<void> result) {
        if (!result) {
            throw std::runtime_error(result.error().message());
        }
    }
};
} // namespace

/// Run the old SDK in its own executable with the same exit-status failure contract as Comet.
int main(int count, char** arguments) {
    try {
        Workload::run<Adapter>(Workload::parse(count, arguments));
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
