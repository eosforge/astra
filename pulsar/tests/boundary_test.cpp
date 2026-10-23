// Verify public Pulsar configuration limits and atomic Ledger refusal boundaries.
#include "pulsar_test.hpp"
#include "server.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace astra;

namespace {
/// Emit a scenario only after its exact outcome and unchanged-state checks succeed.
void observed(std::string_view name) {
    std::cout << "PULSAR-BOUNDARY {\"case\":\"" << name << "\"}\n";
}

/// Borrow owned arguments only during the pure parser call.
Result<Server::Config> parse(const std::vector<std::string>& arguments) {
    std::vector<std::string_view> views(arguments.begin(), arguments.end());
    return Server::Config::parse(views);
}

/// Supply the three mandatory options without reading credentials or creating a database.
std::vector<std::string> arguments() {
    return {"--listen=127.0.0.1:7443", "--pulse-listen=127.0.0.1:7444", "--galaxy=alpha"};
}

/// Check malformed arguments against fixed contract limits, independently of parser internals.
void configuration() {

    /// One replacement or appended optional argument, with an independent public scenario name.
    struct Input {
        /// Stable scenario identity, never derived from an observed error message.
        std::string_view name;
        /// Index three appends an optional argument; lower indices replace a mandatory option.
        std::size_t index;
        /// Owned bytes, including explicit boundary-length values.
        std::string value;
    };

    const std::vector<Input> invalid{
        {"argument-bare", 3, "plain"},
        {"argument-short", 3, "-x"},
        {"argument-unknown", 3, "--unknown=value"},
        {"argument-duplicate", 3, "--galaxy=alpha"},
        {"argument-missing-value", 3, "--state"},
        {"argument-empty-value", 3, "--state="},
        {"argument-disguised-value", 3, "--state=--galaxy"},
        {"argument-large-value", 3, "--state=" + std::string(4097, 'x')},
        {"listener-wildcard-v4", 0, "--listen=0.0.0.0:7443"},
        {"listener-wildcard-v6", 1, "--pulse-listen=[::]:7444"},
        {"listener-hostname", 0, "--listen=localhost:7443"},
        {"listener-invalid-ip", 1, "--pulse-listen=999.0.0.1:7444"},
        {"listener-invalid-port", 0, "--listen=127.0.0.1:65536"},
        {"listener-collision", 1, "--pulse-listen=127.0.0.1:7443"},
        {"galaxy-large", 2, "--galaxy=" + std::string(65, 'g')},
        {"galaxy-invalid", 2, "--galaxy=bad/name"},
        {"initialize-number", 3, "--init=1"},
        {"initialize-case", 3, "--init=True"},
    };
    for (const auto& input : invalid) {
        auto values = arguments();
        if (input.index == values.size()) {
            values.push_back(input.value);
        } else {
            values[input.index] = input.value;
        }
        const auto result = parse(values);
        CHECK(!result && result.error().code == Status::Code::Configuration);
        observed(input.name);
    }
    for (unsigned missing = 0; missing != 3; ++missing) {
        auto values = arguments();
        values.erase(values.begin() + missing);
        const auto result = parse(values);
        CHECK(!result && result.error().code == Status::Code::Configuration);
        observed("required-" + std::to_string(missing));
    }
    for (const std::string option : {"max-members", "max-starts"}) {
        for (const std::string value : {"0", "-1", "+1", "a", "1a", "1.0", "18446744073709551616"}) {
            auto values = arguments();
            values.push_back("--" + option + '=' + value);
            const auto result = parse(values);
            CHECK(!result && result.error().code == Status::Code::Configuration);
            observed(option + "-invalid-" + value);
        }
        auto values = arguments();
        values.push_back("--" + option + '=' + (option == "max-members" ? "4097" : "1000001"));
        const auto result = parse(values);
        CHECK(!result && result.error().code == Status::Code::Configuration);
        observed(option + "-overflow");
    }

    const auto defaults = parse(arguments());
    CHECK(defaults && defaults->listen.text() == "127.0.0.1:7443" && defaults->pulseListen.text() == "127.0.0.1:7444");
    CHECK(defaults->galaxy == "alpha" && defaults->identity == "identity" && defaults->state == "state/pulsar.db");
    CHECK(defaults->maximum == 64 && defaults->starts == 65536 && !defaults->initialize);
    observed("defaults");

    const auto mixed = parse({"--listen", "127.0.0.1:7443", "--pulse-listen=127.0.0.1:7444", "--galaxy", "alpha",
                              "--identity", "local identity", "--state=local database", "--init=true", "--max-members=4096", "--max-starts=1000000"});
    CHECK(mixed && mixed->listen == defaults->listen && mixed->pulseListen == defaults->pulseListen && mixed->galaxy == "alpha");
    CHECK(mixed->identity == "local identity" && mixed->state == "local database" && mixed->initialize);
    CHECK(mixed->maximum == 4096 && mixed->starts == 1'000'000);
    observed("mixed-maximum");

    auto values = arguments();
    values.insert(values.end(), {"--max-members=1", "--max-starts=1", "--init=false"});
    const auto minimum = parse(values);
    CHECK(minimum && minimum->maximum == 1 && minimum->starts == 1 && !minimum->initialize);
    observed("minimum");

    values = arguments();
    values[2] = "--galaxy=" + std::string(64, 'g');
    values.insert(values.end(), {"--identity=" + std::string(4096, 'i'), "--state=" + std::string(4096, 's')});
    const auto limits = parse(values);
    CHECK(limits && limits->galaxy == std::string(64, 'g'));
    CHECK(limits->identity == std::filesystem::path(std::string(4096, 'i')) && limits->state == std::filesystem::path(std::string(4096, 's')));
    observed("text-limits");

    for (const std::string host : {"127.0.0.1", "[::1]"}) {
        const auto ports = parse({"--listen=" + host + ":0", "--pulse-listen=" + host + ":0", "--galaxy=alpha"});
        CHECK(ports && ports->listen == ports->pulseListen && ports->listen.port == 0 && !ports->listen.wildcard);
        observed(host == "127.0.0.1" ? "ephemeral-v4" : "ephemeral-v6");
    }
    const auto leading = parse({"--listen=127.0.0.1:1", "--pulse-listen=127.0.0.1:65535", "--galaxy=alpha", "--max-members=0002", "--max-starts=0003"});
    CHECK(leading && leading->maximum == 2 && leading->starts == 3 && leading->listen.port == 1 && leading->pulseListen.port == 65535);
    observed("numeric-boundaries");
    const auto help = Server::Config::help();
    CHECK(help.starts_with("Usage: pulsar ") && help.find("--max-members=N") != std::string_view::npos && help.find("--max-starts=N") != std::string_view::npos);
    observed("help");
}

/// Invalid constructor options must fail before creating or locking a database file.
void constructors(const std::filesystem::path& root, const std::string& authority) {

    /// Deliberately invalid independent constructor inputs, with finite accepted limits as controls.
    struct Input {
        /// Public case name and separately controlled identity inputs.
        std::string name, galaxy, authority;
        /// Per-role and retained-start capacities use their documented units.
        std::size_t members, starts;
    };

    const std::vector<Input> invalid{
        {"ledger-galaxy-empty", "", authority, 2, 4},
        {"ledger-galaxy-large", std::string(65, 'g'), authority, 2, 4},
        {"ledger-galaxy-invalid", "bad/name", authority, 2, 4},
        {"ledger-authority-empty", "alpha", "", 2, 4},
        {"ledger-authority-short", "alpha", std::string(63, 'a'), 2, 4},
        {"ledger-authority-large", "alpha", std::string(65, 'a'), 2, 4},
        {"ledger-authority-invalid", "alpha", std::string(64, 'z'), 2, 4},
        {"ledger-members-zero", "alpha", authority, 0, 4},
        {"ledger-members-large", "alpha", authority, 4097, 4},
        {"ledger-starts-zero", "alpha", authority, 2, 0},
        {"ledger-starts-large", "alpha", authority, 2, 1'000'001},
    };
    for (const auto& input : invalid) {
        const auto path = root / (input.name + ".db");
        bool refused = false;
        try {
            Ledger ledger(path, input.galaxy, input.authority, input.members, input.starts, true);
        } catch (const std::runtime_error& error) {
            refused = std::string_view(error.what()) == "Invalid registration database configuration";
        }
        CHECK(refused && !std::filesystem::exists(path));
        observed(input.name);
    }
    CHECK(std::filesystem::is_empty(root));
    for (const bool maximum : {false, true}) {
        const auto path = root / (maximum ? "maximum.db" : "minimum.db");
        {
            Ledger ledger(path, "alpha", authority, maximum ? 4096 : 1, maximum ? 1'000'000 : 1, true);
            CHECK(std::filesystem::is_regular_file(path));
        }
        // Reopening confirms that a completed constructor returned its exclusive ownership.
        Ledger restored(path, "alpha", authority, maximum ? 4096 : 1, maximum ? 1'000'000 : 1);
        observed(maximum ? "ledger-maximum" : "ledger-minimum");
    }
}

/// Reject malformed/new conflicting candidates without publishing a prefix or consuming their retry key.
void registration(const std::filesystem::path& path, const std::string& authority) {

    auto original = test::member(1);
    original.epoch.value = 1;
    auto expected = test::member(2);
    expected.epoch.value = 1;
    const std::string first(32, 'a'), next(32, 'b');
    {
        Ledger ledger(path, "alpha", authority, 4, 16, true);
        CHECK(ledger.registerMember(test::member(1), first, [&](const Member& value, const auto&) { CHECK(value == original); }));
        const auto frozen = ledger.snapshot(original);
        CHECK(frozen && frozen->size() == 1 && frozen->at(original.principal.text()) == original);

        for (const std::string name : {"input-epoch", "input-galaxy", "input-short-key", "input-long-key", "record-group", "record-id", "record-role", "record-address",
                                       "collision-id", "collision-address", "replacement-role", "replacement-address", "replacement-id"}) {
            auto candidate = test::member(name.starts_with("replacement-") ? 1 : 2);
            auto request = next;
            auto error = Status::Code::Configuration;
            if (name == "input-epoch") {
                candidate.epoch.value = 1;
            } else if (name == "input-galaxy") {
                candidate.galaxy = "other";
            } else if (name == "input-short-key" || name == "input-long-key") {
                request.resize(name == "input-short-key" ? 31 : 33, 'b');
            } else if (name == "record-group") {
                candidate.group.clear();
            } else if (name == "record-id") {
                candidate.id.clear();
            } else if (name == "record-role") {
                candidate.role = static_cast<Member::Role>(255);
            } else if (name == "record-address") {
                candidate.address.port = 0;
            } else {
                error = Status::Code::Conflict;
                if (name == "collision-id") {
                    candidate.id = original.id;
                } else if (name == "collision-address") {
                    candidate.address = original.address;
                } else if (name == "replacement-role") {
                    candidate.id = "replacement";
                    candidate.role = Member::Role::Polaris;
                } else if (name == "replacement-address") {
                    candidate.id = "replacement";
                    candidate.address = expected.address;
                }
            }
            unsigned prepared = 0;
            const auto result = ledger.registerMember(candidate, request, [&](const auto&, const auto&) { ++prepared; });
            CHECK(!result && result.error().code == error && prepared == 0);
            CHECK(ledger.current(original) && ledger.snapshot(original) == frozen);
            CHECK(frozen->size() == 1 && frozen->at(original.principal.text()) == original);
            observed(name);
        }
        CHECK(ledger.registerMember(test::member(2), next, [&](const Member& value, const auto& members) {
            CHECK(value == expected && members.size() == 2 && members.at(original.principal.text()) == original);
        }));
        CHECK(ledger.current(original) && ledger.current(expected));
        CHECK(frozen->size() == 1 && frozen->at(original.principal.text()) == original);
        observed("healthy-after-refusals");
    }
    Ledger restored(path, "alpha", authority, 4, 16);
    CHECK(restored.current(original) && restored.current(expected));
    CHECK(restored.registerMember(test::member(2), next, [&](const Member& value, const auto& members) { CHECK(value == expected && members.size() == 2); }));
    CHECK(restored.snapshot(expected)->size() == 2);
    observed("restored-after-refusals");
}
} // namespace

/// Execute deterministic public boundaries using only this executable's owned temporary files.
int main() {
    try {
        test::Directory directory;
        configuration();
        const std::string authority(64, 'a');
        constructors(directory.path, authority);
        registration(directory.path / "registration.db", authority);
        std::cout << "PULSAR-BOUNDARY {\"complete\":true}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
