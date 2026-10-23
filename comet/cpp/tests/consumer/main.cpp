// Consume installed public SDK headers and linkage as an independent downstream application.
#include <comet/client.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <type_traits>

// Standalone consumer checks public types, linking, and TLS. endpoint is a reserved nonlistening loopback port; invalid is a missing CA path.
int main(int count, char** arguments) {

    static_assert(std::is_copy_constructible_v<comet::Client>);
    static_assert(!std::is_copy_constructible_v<comet::Reader>);
    static_assert(std::is_copy_constructible_v<comet::Observer::Item>);
    static_assert(std::is_same_v<decltype(std::declval<comet::Beacon&>().update(comet::Value{})), comet::Result<comet::Beacon::Receipt>>);

    // Empty handles verify complete public declarations and linking without creating extra network work for package checks.
    comet::Beacon beacon;
    comet::Reader reader;
    comet::Subscriber subscriber;
    comet::Observer observer;
    if (beacon.tick(std::chrono::milliseconds(1), [] { return comet::Value{}; }) || beacon.changed([](comet::Beacon::State) {}) || reader.watch([](comet::Reader::Map) {}) || subscriber.watch([](std::string, std::optional<comet::Value>) {}) || reader.changed([](comet::Reader::View) {}) || subscriber.changed([](comet::Subscriber::View) {})) {
        return 1;
    }
    const auto selected = observer.one([](const comet::Observer::Pool& pool) -> std::optional<comet::Observer::Item> {
        pool.each([](comet::Observer::Item item) { static_cast<void>(item.record()); });
        return pool.find("missing");
    });
    if (selected || selected.error().code != comet::Error::Code::Closed) {
        return 1;
    }
    beacon.destroy();
    reader.stop();
    subscriber.stop();
    observer.stop();
    if (count != 3) {
        return 1;
    }
    const auto invalid = comet::Client::open({}); // Empty endpoints must fail explicitly while resolving actual SDK entries and private dependencies.
    if (invalid || invalid.error().code != comet::Error::Code::Input) {
        return 1;
    }

    comet::Client::Options options; // Anonymous with default TLS; package CMake embeds the public CA.
    options.auth = false;
    options.endpoints = {arguments[1]};
    auto encrypted = comet::Client::open(options); // Reach actual root-provider validation beyond empty-argument rejection.
    if (!encrypted) {
        return 1;
    }
    encrypted->close();
    if (!encrypted->wait(std::chrono::seconds(5))) {
        return 1;
    }

    options.ca = std::filesystem::path(arguments[2]); // Explicit external paths take priority; read failure must not silently fall back to embedded CA.
    const auto missing = comet::Client::open(options);
    if (missing || missing.error().code != comet::Error::Code::Input) {
        return 1;
    }
    options.ca.clear();
    options.tls = false; // Explicitly disabling public TLS still permits local creation and full cleanup without affecting internal linking.
    auto plaintext = comet::Client::open(std::move(options));
    if (!plaintext) {
        return 1;
    }
    plaintext->close();
    return plaintext->wait(std::chrono::seconds(5)) ? 0 : 1;
}
