// Observe public SDK state transitions in the real-process recovery fixture.
#include <comet/client.hpp>

#include <charconv>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {
using namespace std::chrono_literals;

/// Reads test-private secret files only, 1..4096 bytes; APISECRET never enters arguments or output.
std::vector<std::uint8_t> secret(const std::filesystem::path& path) {

    const auto size = std::filesystem::file_size(path);
    if (!std::filesystem::is_regular_file(path) || size == 0 || size > 4096) {
        throw std::runtime_error("Invalid private fixture file");
    }
    std::ifstream input(path, std::ios::binary);
    std::vector<std::uint8_t> result(static_cast<std::size_t>(size));
    if (!input.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(size)) || input.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("Cannot read private fixture file");
    }
    return result;
}

/// Success and failure close SDK and drain this process's in-flight work; owns only this test's Client.
struct Cleanup {
    /// Borrows main's Client, which outlives this guard.
    comet::Client& client;

    ~Cleanup() {
        client.close();
        if (!client.wait(5s)) {
            std::terminate();
        }
    }
};
} // namespace

/// Native SDK process probe uses no Pulsar or Polaris Stub or server code; business payloads contain public test data only.
int main(int count, char** arguments) {

    try {
        if (count != 7) {
            throw std::runtime_error("Expected endpoint, CA file, secret file, sector, spectrum, target version");
        }
        const std::string_view requested(arguments[6]); // Expected final complete authority version; strict positive decimal input.
        std::uint64_t target{};
        const auto parsed = std::from_chars(requested.data(), requested.data() + requested.size(), target);
        if (parsed.ec != std::errc{} || parsed.ptr != requested.data() + requested.size() || target == 0) {
            throw std::runtime_error("Invalid target version");
        }

        std::mutex mutex; // Callbacks update small completion state only; never await SDK under this lock.
        std::condition_variable changed;
        bool complete{};
        comet::Client::Options options; // Actual public TLS and Comet login, without node private keys or administrative credentials.
        options.endpoints = {arguments[1]};
        options.ca = arguments[2];
        options.key = "integration";
        options.secret = secret(arguments[3]);
        auto opened = comet::Client::open(std::move(options));
        if (!opened) {
            throw std::runtime_error("Cannot create native Client");
        }
        auto client = std::move(*opened);
        const Cleanup cleanup{client}; // Callback-borrowed mutex and locals outlive guard cleanup.
        comet::Reader::Options reading;
        reading.changed = [&](comet::Reader::View view) {
            if (view.state() != comet::Reader::State::Ready || !view.version()) {
                return;
            }
            const auto value = view.find("key"); // Outputs bounded test-configured hexadecimal only; never reads internal credential scopes.
            constexpr std::string_view digits = "0123456789abcdef";
            std::string encoded;
            if (value) {
                if (value->size() > 64) {
                    throw std::runtime_error("Unexpected probe payload size");
                }
                for (const auto byte : *value) {
                    encoded.push_back(digits[byte >> 4]);
                    encoded.push_back(digits[byte & 15]);
                }
            }
            std::cout << "{\"event\":\"view\",\"version\":" << *view.version() << ",\"present\":" << (value ? "true" : "false") << ",\"value\":\"" << encoded << "\"}" << std::endl;
            const std::lock_guard lock(mutex);
            complete = *view.version() >= target;
            changed.notify_all();
        };
        auto reader = client.reader({arguments[4], arguments[5]}, {}, std::move(reading));
        if (!reader) {
            throw std::runtime_error("Cannot create native Reader");
        }
        {
            std::unique_lock lock(mutex);
            if (!changed.wait_for(lock, 160s, [&] { return complete; })) {
                throw std::runtime_error("Native Reader did not reach complete target");
            }
        }
        reader->close();
        if (!reader->wait(5s) || client.exceptions() != 0) {
            throw std::runtime_error("Native Reader cleanup or callback failed");
        }
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
