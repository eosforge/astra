// Verify public SDK linkage and owned client shutdown from a relocated installation.
#include <comet/client.hpp>

#include <chrono>
#include <iostream>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace {
/// Check an externally visible outcome without including private implementation or test headers.
bool require(bool value, const char* reason, int& hits) {
    if (!value) {
        std::cerr << reason << '\n';
        return false;
    }
    ++hits;
    return true;
}
} // namespace

/// Consume the exact installed archive; the caller owns a reserved, non-listening loopback endpoint.
int main(int count, char** arguments) {

    static_assert(std::is_copy_constructible_v<comet::Client>);
    static_assert(!std::is_copy_constructible_v<comet::Reader>);
    static_assert(std::is_copy_constructible_v<comet::Observer::Item>);
    // Successful checks count actual API observations, never process starts.
    auto hits = 0;
    if (!require(count == 2, "missing owned endpoint", hits)) {
        return 1;
    }
    const auto invalid = comet::Client::open({});
    if (!require(!invalid && invalid.error().code == comet::Error::Code::Input, "empty configuration accepted", hits)) {
        return 1;
    }

    // Empty public handles must reject operations without starting hidden work.
    comet::Beacon beacon;
    const auto updated = beacon.update(comet::Value{});
    if (!require(!updated && updated.error().code == comet::Error::Code::Closed, "empty Beacon update accepted", hits)) {
        return 1;
    }
    comet::Observer observer;
    const auto selected = observer.one([](const comet::Observer::Pool& pool) -> std::optional<comet::Observer::Item> { return pool.find("missing"); });
    if (!require(!selected && selected.error().code == comet::Error::Code::Closed, "empty Observer selection accepted", hits)) {
        return 1;
    }
    comet::Reader reader;
    if (!require(!reader.watch([](comet::Reader::Map) {}), "empty Reader watch accepted", hits)) {
        return 1;
    }
    comet::Subscriber subscriber;
    if (!require(!subscriber.watch([](std::string, std::optional<comet::Value>) {}), "empty Subscriber watch accepted", hits)) {
        return 1;
    }
    beacon.destroy();
    observer.stop();
    reader.stop();
    subscriber.stop();

    // A real owned core must drain after close; no admission or deployed service is used.
    comet::Client::Options options;
    options.auth = false;
    options.tls = false;
    options.endpoints = {arguments[1]};
    auto client = comet::Client::open(std::move(options));
    if (!require(client.has_value(), "installed client initialization failed", hits)) {
        return 1;
    }
    client->close();
    if (!require(client->wait(std::chrono::seconds(5)), "installed client did not drain", hits)) {
        return 1;
    }
    std::cout << "ASTRA-DELIVERY {\"contract\":\"DELIVERY-SDK\",\"hits\":" << hits << "}\n";
    return 0;
}
