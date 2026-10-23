// Exhaust bounded durable registration histories against independent identity, request and capacity registers.
#include "ledger.hpp"
#include "pulsar_test.hpp"

#include <array>
#include <iostream>
#include <map>
#include <optional>
#include <vector>

namespace {
// Model entries contain only observable identity generations and caller-chosen IDs.
struct Entry {
    /// Keep the model member identity associated with one synthetic principal.
    std::string id;
    /// Track that model identity's admission epoch independently of ledger internals.
    std::uint64_t epoch{};
};

// Ordinary registers describe idempotent receipts and the first successful request for each principal.
struct Model {
    /// Map synthetic principals to their current independently modeled admissions.
    std::map<unsigned, Entry> members;
    /// Retain idempotency requests with their principal and epoch for replay expectations.
    std::map<std::string, std::pair<unsigned, std::uint64_t>> requests;
    /// Remember the first accepted idempotency request for each of the two synthetic principals.
    std::array<std::optional<std::string>, 2> first;
};

/// Actual registration effects captured before publishing their public trace.
struct Outcome {
    /// Reopen is the only input without a registration result.
    std::string_view status = "reopen";
    /// The production prepare callback was entered.
    bool prepared{};
    /// The controlled prepare exception escaped without committing.
    bool threw{};
    /// Complete native callback arguments, independent of the expected model.
    std::optional<std::pair<astra::Member, astra::Ledger::Members>> callback;
};

/// Preserve every textual field as JSON, including unexpected control characters.
void text(std::string_view value) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::cout << '"';
    for (const char character : value) {
        const auto code = static_cast<unsigned>(static_cast<unsigned char>(character));
        if (character == '"' || character == '\\') {
            std::cout << '\\' << character;
        } else if (code < 32) {
            std::cout << "\\u00" << digits[code >> 4] << digits[code & 15];
        } else {
            std::cout << character;
        }
    }
    std::cout << '"';
}

/// Encode the complete public Member; endpoint flags, role and group cannot disappear in projection.
void record(const astra::Member& value) {
    std::cout << '[';
    text(value.galaxy);
    std::cout << ',';
    text(value.id);
    std::cout << ',';
    text(value.principal.text());
    std::cout << ",[";
    text(value.address.host);
    std::cout << ',' << value.address.port << ',' << (value.address.ipv6 ? "true" : "false") << ',' << (value.address.wildcard ? "true" : "false") << "]," << value.epoch.value << ',';
    switch (value.role) {
    case astra::Member::Role::Star:
        text("star");
        break;
    case astra::Member::Role::Planet:
        text("planet");
        break;
    case astra::Member::Role::Polaris:
        text("polaris");
        break;
    case astra::Member::Role::Astrolabe:
        text("astrolabe");
        break;
    default:
        text("invalid");
        break;
    }
    std::cout << ',';
    text(value.group);
    std::cout << ']';
}

/// Read a complete native immutable directory in its public canonical key order.
void view(const astra::Ledger::Members& values) {
    std::cout << '[';
    bool comma = false;
    for (const auto& [key, value] : values) {
        std::cout << (comma ? "," : "") << '[';
        text(key);
        std::cout << ',';
        record(value);
        std::cout << ']';
        comma = true;
    }
    std::cout << ']';
}

/// A refused credential has no directory; an empty directory is a distinct value.
void view(const std::shared_ptr<const astra::Ledger::Members>& value) {
    if (value) {
        view(*value);
    } else {
        std::cout << "null";
    }
}

// Convert an independent register to public fixture values, without calling a ledger transition or validator.
astra::Member member(unsigned principal, const Entry& entry) {
    auto value = astra::test::member(principal + 1);
    value.id = entry.id;
    value.epoch.value = entry.epoch;
    return value;
}

// Materialize the complete expected directory from the two independent identity registers.
astra::Ledger::Members directory(const Model& model) {
    astra::Ledger::Members result;
    for (const auto& [principal, entry] : model.members) {
        auto value = member(principal, entry);
        result.emplace(value.principal.text(), std::move(value));
    }
    return result;
}

/// Serialize only actual callback, credential, query and captured-root observations.
void observe(const astra::Ledger& ledger, unsigned operation, const Outcome& outcome, const Model& model, const auto& credentials, const auto& frozen) {
    std::cout << "{\"operation\":" << operation << ",\"outcome\":";
    text(outcome.status);
    std::cout << ",\"prepared\":" << (outcome.prepared ? "true" : "false") << ",\"threw\":" << (outcome.threw ? "true" : "false") << ",\"prepare\":";
    if (outcome.callback) {
        std::cout << '[';
        record(outcome.callback->first);
        std::cout << ',';
        view(outcome.callback->second);
        std::cout << ']';
    } else {
        std::cout << "null";
    }
    std::cout << ",\"credentials\":[";
    for (std::size_t i = 0; i < credentials.size(); ++i) {
        const auto& value = credentials[i];
        std::cout << (i ? "," : "") << '[';
        record(value);
        std::cout << ',' << (ledger.current(value) ? "true" : "false") << ',';
        view(ledger.snapshot(value));
        std::cout << ']';
    }
    std::cout << "],\"queries\":[";
    for (unsigned principal = 0; principal < 2; ++principal) {
        const auto found = model.members.find(principal);
        const auto value = member(principal, found == model.members.end() ? Entry{"unregistered", 1} : found->second);
        std::cout << (principal ? "," : "") << '[';
        record(value);
        std::cout << ',';
        view(ledger.snapshot(value));
        std::cout << ']';
    }
    std::cout << "],\"frozen\":[";
    for (std::size_t i = 0; i < frozen.size(); ++i) {
        std::cout << (i ? "," : "");
        view(frozen[i].first);
    }
    std::cout << "]}";
}

// Verify complete current membership, every prior credential and every frozen directory across reopen.
void verify(const astra::Ledger& ledger, const Model& model, const auto& credentials, const auto& frozen) {
    const auto expected = directory(model);
    for (const auto& value : credentials) {
        const auto found = expected.find(value.principal.text());
        const bool current = found != expected.end() && found->second == value;
        CHECK(ledger.current(value) == current);
        const auto view = ledger.snapshot(value);
        CHECK(static_cast<bool>(view) == current);
        if (view) {
            CHECK(*view == expected);
        }
    }
    for (unsigned principal = 0; principal < 2; ++principal) {
        const auto found = model.members.find(principal);
        const auto value = member(principal, found == model.members.end() ? Entry{"unregistered", 1} : found->second);
        const auto view = ledger.snapshot(value);
        CHECK(static_cast<bool>(view) == (found != model.members.end()));
        if (view) {
            CHECK(*view == expected);
        }
    }
    for (const auto& [view, expectedView] : frozen) {
        CHECK(*view == expectedView);
    }
}

// A two-slot domain checks new generations, old receipts, invalid requests, prepare rollback and disk reopen.
void history(const std::filesystem::path& path, unsigned number, unsigned capacity) {
    const auto open = [&](bool initialize) {
        return std::make_unique<astra::Ledger>(path, "alpha", std::string(64, 'a'), capacity, 2, initialize);
    };
    auto ledger = open(true);
    Model model;
    std::vector<astra::Member> credentials;
    std::vector<std::pair<std::shared_ptr<const astra::Ledger::Members>, astra::Ledger::Members>> frozen;
    std::cout << "ASTRA-MODEL {\"model\":\"ledger-state-v1\",\"event\":\"history\",\"value\":{\"ordinal\":" << (capacity - 1) * 343 + number << ",\"capacity\":" << capacity << ",\"states\":[";
    for (unsigned depth = 0; depth < 3; ++depth) {
        const auto operation = number % 7;
        number /= 7;
        Outcome outcome;
        if (operation == 6) {
            ledger.reset();
            ledger = open(false);
        } else {
            const unsigned principal = operation == 1 || operation == 3 ? 1 : 0;
            auto proposed = member(principal, {"attempt-" + std::to_string(depth), 0});
            const bool retry = operation == 2 || operation == 3;
            const auto request = retry ? model.first[principal].value_or("")
                                       : std::string(operation == 4 ? 31 : 32, static_cast<char>('a' + depth * 2 + principal));
            const auto previous = model.members.find(principal);
            bool accepted = false;
            Entry expected;
            if (retry) {
                if (!request.empty()) {
                    const auto& receipt = model.requests.at(request);
                    accepted = previous != model.members.end() && previous->second.epoch == receipt.second;
                    if (accepted) {
                        expected = previous->second;
                    }
                }
            } else if (operation != 4) {
                accepted = model.requests.size() < 2 && (previous != model.members.end() || model.members.size() < capacity);
                expected = {proposed.id, previous == model.members.end() ? 1 : previous->second.epoch + 1};
            }
            astra::Member committed;
            astra::Result<void> result;
            try {
                result = ledger->registerMember(proposed, request, [&](const auto& value, const auto& view) {
                    outcome.prepared = true;
                    outcome.callback.emplace(value, view);
                    auto intended = model;
                    intended.members[principal] = expected;
                    CHECK(value == member(principal, expected) && view == directory(intended));
                    if (operation == 5) {
                        throw std::bad_alloc{};
                    }
                    committed = value;
                });
            } catch (const std::bad_alloc&) {
                outcome.threw = true;
            }
            outcome.status = outcome.threw ? "throw" : result ? "ok"
                                                              : astra::Status::name(result.error().code);
            CHECK(outcome.prepared == accepted);
            CHECK(outcome.threw == (accepted && operation == 5));
            if (!outcome.threw) {
                CHECK(result.has_value() == accepted);
            }
            if (accepted && !outcome.threw) {
                model.members[principal] = expected;
                if (!retry) {
                    model.requests.emplace(request, std::pair(principal, expected.epoch));
                    if (!model.first[principal]) {
                        model.first[principal] = request;
                    }
                }
                credentials.push_back(committed);
                frozen.emplace_back(ledger->snapshot(committed), directory(model));
                CHECK(frozen.back().first);
            }
        }
        verify(*ledger, model, credentials, frozen);
        std::cout << (depth ? "," : "");
        observe(*ledger, operation, outcome, model, credentials, frozen);
    }
    // Every terminal state is also checked through actual close/reopen, including rejected and rolled-back histories.
    ledger.reset();
    ledger = open(false);
    verify(*ledger, model, credentials, frozen);
    std::cout << "],\"reopened\":";
    observe(*ledger, 6, Outcome{}, model, credentials, frozen);
    std::cout << "}}\n";
}
} // namespace

// Enumerate 2 * 7^3 histories without pruning; native SQLite errors, concurrency and power loss are separate fault domains.
int main() {
    try {
        std::cout << "ASTRA-MODEL {\"model\":\"ledger-state-v1\",\"event\":\"start\",\"value\":{\"principals\":[1,2],\"capacities\":[1,2],\"starts\":2,\"operations\":7,\"depth\":3,\"histories\":686,\"pruning\":0}}\n";
        for (unsigned capacity : {1U, 2U}) {
            for (unsigned number = 0; number < 343; ++number) {
                astra::test::Directory owned;
                history(owned.path / "state.db", number, capacity);
            }
        }
        std::cout << "PULSAR-MODEL histories=686 transitions=2058 depth=3 operations=7 capacities=1,2 pruning=0\n";
        std::cout << "ASTRA-MODEL {\"model\":\"ledger-state-v1\",\"event\":\"finish\",\"value\":{\"histories\":686,\"transitions\":2058,\"reopens\":686}}\n";
        std::cout.flush();
        CHECK(std::cout.good());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
