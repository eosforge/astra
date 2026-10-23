// Verify durable membership transactions, endpoint validation, and capacity accounting.
#include "database_fault.hpp"
#include "ledger.hpp"
#include "pulsar_test.hpp"

#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>

using namespace astra;

#if defined(__linux__)
namespace astra::test {
/// Verify native constructor refusal and cleanup before other SQLite fixtures initialize.
void ledgerFault(const std::filesystem::path& root, const std::string& authority);
} // namespace astra::test
#endif

namespace {
/// Test-only connection observes or corrupts this fixture database; it is not a production administration entry point.
class SQL {
public:
    /// Opens only an already initialized database; failure cannot create a file.
    explicit SQL(const std::filesystem::path& path) {
        if (sqlite3_open_v2(path.c_str(), &database_, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
            sqlite3_close_v2(database_);
            throw std::runtime_error("Cannot open owned test database");
        }
    }

    ~SQL() {
        sqlite3_close_v2(database_);
    }

    SQL(const SQL&) = delete;

    SQL& operator=(const SQL&) = delete;

    /// Static test SQL must succeed before checking the resulting behavior.
    void execute(const char* sql) {
        CHECK(sqlite3_exec(database_, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    /// Bind the complete member body with an explicit byte length, preserving embedded NULs.
    void replace(std::string_view body) {
        sqlite3_stmt* statement{};
        const auto prepared = sqlite3_prepare_v2(database_, "UPDATE members SET body=?", -1, &statement, nullptr);
        const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> owner(statement, sqlite3_finalize);
        CHECK(prepared == SQLITE_OK);
        CHECK(sqlite3_bind_blob(statement, 1, body.data(), static_cast<int>(body.size()), SQLITE_STATIC) == SQLITE_OK);
        CHECK(sqlite3_step(statement) == SQLITE_DONE);
    }

    /// Returns owned scalar text, including hex(epoch) for full-width representation checks.
    std::string value(const char* sql) {

        sqlite3_stmt* statement{};
        const auto prepared = sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr);
        const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> owner(statement, sqlite3_finalize);
        CHECK(prepared == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW);
        const auto* data = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
        CHECK(data);
        const std::string result(data, static_cast<std::size_t>(sqlite3_column_bytes(statement, 0)));
        CHECK(sqlite3_step(statement) == SQLITE_DONE);
        return result;
    }

private:
    /// Own the test SQLite connection; null before successful opening.
    sqlite3* database_{};
};

/// Requires an actual exception, not a short circuit or empty result.
template <class Action>
void rejects(Action&& action) {

    bool rejected{};
    try {
        action();
    } catch (const std::exception&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Concurrent identical startup requests append once. Each thread owns a result slot; assertions run after joining.
static void concurrentRetry(const std::filesystem::path& path, const std::string& authority) {

    Ledger ledger(path, "alpha", authority, 2, 4, true);

    std::array<bool, 8> success{};

    std::array<Id, 8> ids{};

    std::vector<std::jthread> clients;

    for (std::size_t i = 0; i < success.size(); ++i) {
        clients.emplace_back([&, i] {
            try {

                auto candidate = test::member(1);
                candidate.id = "attempt-" + std::to_string(i);
                success[i] = ledger.registerMember(candidate, std::string(32, 'a'), [&](const Member& member, const auto&) { ids[i] = member.id; }).has_value();
            } catch (...) {
                success[i] = false;
            }
        });
    }
    clients.clear();

    for (std::size_t i = 0; i < success.size(); ++i) {
        CHECK(success[i] && ids[i] == ids.front());
    }
}

/// Initialization, exclusive service ownership, and known-format checks must reject invalid targets without treating them as new clusters.
void initialization(const std::filesystem::path& root, const std::string& authority) {

    const auto path = root / "initialization.db";
    rejects([&] { Ledger missing(path, "alpha", authority, 2, 4); });
    CHECK(!std::filesystem::exists(path));
    {
        Ledger initialized(path, "alpha", authority, 2, 4, true);
        rejects([&] { Ledger locked(path, "alpha", authority, 2, 4); });
    }

    rejects([&] { Ledger duplicate(path, "alpha", authority, 2, 4, true); });
    rejects([&] { Ledger galaxy(path, "other", authority, 2, 4); });
    rejects([&] { Ledger signer(path, "alpha", std::string(64, 'b'), 2, 4); });
    {
        Ledger restored(path, "alpha", authority, 2, 4);
    }

    const auto empty = root / "empty.db";
    { std::ofstream output(empty); }
    rejects([&] { Ledger invalid(empty, "alpha", authority, 2, 4); });
    const auto legacy = root / "legacy.db";
    {
        std::ofstream output(legacy);
        output << "ASTRA-PULSAR-JOURNAL-1\n";
    }
    rejects([&] { Ledger invalid(legacy, "alpha", authority, 2, 4); });
    const auto link = root / "linked.db";
    std::filesystem::create_symlink(path, link);
    rejects([&] { Ledger invalid(link, "alpha", authority, 2, 4); });
    const auto directory = root / "directory.db";
    std::filesystem::create_directory(directory);
    rejects([&] { Ledger invalid(directory, "alpha", authority, 2, 4); });
    rejects([&] { Ledger invalid(root / "missing-parent/state.db", "alpha", authority, 2, 4, true); });
    const auto sidecar = root / "sidecar.db";
    {
        std::ofstream output(sidecar.string() + "-journal");
        output << "owned recovery evidence";
    }
    rejects([&] { Ledger invalid(sidecar, "alpha", authority, 2, 4, true); });
    CHECK(!std::filesystem::exists(sidecar) && std::filesystem::file_size(sidecar.string() + "-journal") != 0);
}

/// Check idempotency, replacement, snapshot lifetime, capacity, and preparation failure across restart of the same database.
void registration(const std::filesystem::path& path, const std::string& authority) {

    // Callback execution alone does not establish durable commit.
    Member committed;
    std::size_t count{};
    const auto prepare = [&](const Member& member, const auto& members) { committed = member; count = members.size(); };
    const std::string first(32, 'a'), second(32, 'b'), next(32, 'c');
    {
        Ledger ledger(path, "alpha", authority, 2, 4, true);
        CHECK(ledger.registerMember(test::member(1), first, prepare));
        const auto original = committed;
        const auto snapshot = ledger.snapshot(original);
        CHECK(snapshot && snapshot->size() == 1);
        CHECK(ledger.registerMember(test::member(2), second, prepare));
        CHECK(ledger.registerMember(test::member(1), first, prepare));
        CHECK(count == 2 && committed == original && snapshot->size() == 1);

        auto changed = test::member(1);
        changed.group = "other";
        CHECK(!ledger.registerMember(changed, first, prepare));
        CHECK(!ledger.registerMember(test::member(2), first, prepare));
        CHECK(!ledger.registerMember(test::member(3), std::string(32, 'd'), prepare));
        CHECK(!ledger.registerMember(test::member(3), std::string(31, 'd'), prepare));
        changed.group = "default";
        changed.id = "replacement";
        rejects([&] { static_cast<void>(ledger.registerMember(changed, next, [](const auto&, const auto&) { throw std::bad_alloc{}; })); });
        CHECK(ledger.current(original));
        SQL sql(path);
        CHECK(sql.value("SELECT count(*) FROM starts") == "2");
        CHECK(ledger.registerMember(changed, next, prepare));
        CHECK(committed.epoch.value == 2 && ledger.current(committed) && !ledger.current(original));
        CHECK(!ledger.registerMember(test::member(1), first, prepare));
        CHECK(sql.value("SELECT hex(epoch) FROM starts ORDER BY epoch DESC LIMIT 1") == "0000000000000002");
        CHECK(sql.value("PRAGMA journal_mode") == "delete");
    }

    Ledger restored(path, "alpha", authority, 2, 4);
    auto retry = test::member(1);
    retry.id = "ignored-new-suggestion";
    CHECK(restored.registerMember(retry, next, prepare));
    CHECK(committed.id == "replacement" && committed.epoch.value == 2 && count == 2);
    CHECK(!restored.registerMember(test::member(1), first, prepare));

    CHECK(restored.registerMember(test::member(3, Member::Role::Polaris), std::string(32, 'd'), prepare));
    CHECK(!restored.registerMember(test::member(4, Member::Role::Astrolabe), std::string(32, 'e'), prepare));
}

/// Persistent format 1 remains compatible across Protobuf string/bytes changes, retaining identity, epochs, and startup deduplication.
void encoding(const std::filesystem::path& path, const std::string& authority) {

    const auto candidate = test::member(1); // Candidates must start at epoch zero; Ledger allocates the committed epoch.
    auto original = candidate;
    original.epoch.value = 1;
    const std::string request(32, 'a');
    {
        Ledger ledger(path, "alpha", authority, 2, 4, true);
        CHECK(ledger.registerMember(candidate, request, [](const auto&, const auto&) {}));
    }
    {
        SQL sql(path);
        proto::orbit::v1::Member persisted;
        CHECK(persisted.ParseFromString(sql.value("SELECT body FROM members")));
        CHECK(persisted.principal() == original.principal.text());
        persisted.set_principal(original.principal.text());
        sql.replace(persisted.SerializeAsString());
    }
    {
        Ledger restored(path, "alpha", authority, 2, 4);
        CHECK(restored.current(original));
        CHECK(restored.registerMember(candidate, request, [&](const Member& member, const auto&) { CHECK(member == original); }));
        auto next = candidate;
        next.id = "next-process";
        CHECK(restored.registerMember(next, std::string(32, 'b'), [&](const Member& member, const auto&) { CHECK(member.epoch.value == original.epoch.value + 1); }));
    }

    // Body/primary-key mismatch must still fail after encoding conversion.
    {
        SQL sql(path);
        proto::orbit::v1::Member persisted;
        CHECK(persisted.ParseFromString(sql.value("SELECT body FROM members")));
        persisted.set_principal(std::string(64, 'f'));
        sql.replace(persisted.SerializeAsString());
    }
    rejects([&] { Ledger invalid(path, "alpha", authority, 2, 4); });
}

/// Real VFS write/sync failure must prevent identity publication and further issuance; reopening recovers the old identity.
void ioFailure(const std::filesystem::path& path, const std::string& authority, int error, bool sync, bool main = false, bool persistent = false) {

    test::Fault fault;
    Member original, candidate;
    const auto prepare = [&](const Member& member, const auto&) { candidate = member; };
    {
        Ledger ledger(path, "alpha", authority, 2, 4, true);
        CHECK(ledger.registerMember(test::member(1), std::string(32, 'a'), prepare));
        original = candidate;
        auto changed = test::member(1);
        changed.id = "uncommitted";
        fault.arm(error, sync, main, persistent ? 0U : 1U);
        CHECK(!ledger.registerMember(changed, std::string(32, 'b'), prepare));
        CHECK(fault.hits() >= 1 && ledger.current(original) && !ledger.current(candidate));
        if (!persistent) {
            CHECK(fault.hits() == 1);
        }
        CHECK(!ledger.registerMember(test::member(1), std::string(32, 'a'), prepare));
        fault.clear(); // Repair the injected fault only after issuance stops, then close and recover the real file.
    }

    Ledger restored(path, "alpha", authority, 2, 4);
    CHECK(restored.current(original));
    CHECK(restored.registerMember(test::member(1), std::string(32, 'a'), prepare));
    CHECK(candidate == original);
    auto changed = test::member(1);
    changed.id = "recovered";
    CHECK(restored.registerMember(changed, std::string(32, 'b'), prepare));
    CHECK(candidate.epoch.value == 2 && restored.current(candidate));
}

/// Exercise every native write/sync ordinal for a new identity and a replacement, including persistent rollback faults.
void ioMatrix(const std::filesystem::path& root, const std::string& authority) {

    // Fix the domain before observation: two transitions, every real write/sync, four error classes and two durations.
    std::cout << "PULSAR-FAULT {\"event\":\"start\",\"transitions\":2,\"limit\":128,\"durations\":2}\n";
    std::size_t cases{};
    for (const bool replace : {false, true}) {
        auto original = test::member(1);
        original.epoch.value = 1;
        auto proposed = test::member(replace ? 1 : 2);
        proposed.id = "next-process";
        auto expected = proposed;
        expected.epoch.value = replace ? 2 : 1;
        const Ledger::Members before{{original.principal.text(), original}};
        auto after = before;
        after.insert_or_assign(expected.principal.text(), expected);

        for (const bool sync : {false, true}) {
            unsigned calls{};
            {
                test::Fault fault;
                Ledger ledger(root / ("io-baseline-" + std::to_string(replace) + '-' + std::to_string(sync) + ".db"), "alpha", authority, 2, 4, true);
                CHECK(ledger.registerMember(test::member(1), std::string(32, 'a'), [](const auto&, const auto&) {}));
                fault.watch(sync);
                CHECK(ledger.registerMember(proposed, std::string(32, 'b'), [&](const Member& member, const auto& view) { CHECK(member == expected && view == after); }));
                calls = fault.calls();
                CHECK(calls > 0 && calls <= 128 && fault.hits() == 0);
                CHECK(ledger.snapshot(expected) && *ledger.snapshot(expected) == after);
            }
            std::cout << "PULSAR-FAULT {\"event\":\"baseline\",\"replace\":" << replace << ",\"sync\":" << sync << ",\"calls\":" << calls << "}\n";

            for (const int error : {SQLITE_IOERR_WRITE, SQLITE_FULL, SQLITE_NOMEM, SQLITE_IOERR_FSYNC}) {
                if (sync != (error == SQLITE_IOERR_FSYNC)) {
                    continue;
                }
                for (const bool persistent : {false, true}) {
                    for (unsigned ordinal = 0; ordinal < calls; ++ordinal) {
                        std::cout << "PULSAR-FAULT {\"event\":\"attempt\",\"case\":" << cases << ",\"replace\":" << replace << ",\"sync\":" << sync << ",\"error\":" << error << ",\"persistent\":" << persistent << ",\"ordinal\":" << ordinal << "}\n";
                        const auto path = root / ("io-point-" + std::to_string(cases) + ".db");
                        unsigned hits{};
                        {
                            test::Fault fault;
                            Ledger ledger(path, "alpha", authority, 2, 4, true);
                            CHECK(ledger.registerMember(test::member(1), std::string(32, 'a'), [](const auto&, const auto&) {}));
                            const auto held = ledger.snapshot(original);
                            CHECK(held && *held == before);
                            unsigned prepared{};
                            fault.arm(error, sync, false, persistent ? 0U : 1U, ordinal);
                            const auto result = ledger.registerMember(proposed, std::string(32, 'b'), [&](const Member& member, const auto& view) {
                                ++prepared;
                                CHECK(member == expected && view == after);
                            });
                            hits = fault.hits();
                            CHECK(!result && result.error().code == Status::Code::Transport);
                            CHECK(prepared == 1 && hits >= 1 && fault.calls() > ordinal && fault.position() == ordinal);
                            CHECK(persistent || hits == 1);
                            CHECK(ledger.current(original) && !ledger.current(expected) && *held == before);
                            CHECK(ledger.snapshot(original) == held);
                            // Poisoned writers reject committed retries without preparing another receipt.
                            const auto retry = ledger.registerMember(test::member(1), std::string(32, 'a'), [&](const auto&, const auto&) { ++prepared; });
                            CHECK(!retry && retry.error().code == Status::Code::Transport && prepared == 1);
                            fault.clear();
                        }

                        // Durability is uncertain: reopening must expose one whole transaction, never a mixed root.
                        Ledger restored(path, "alpha", authority, 2, 4);
                        const bool committed = restored.current(expected);
                        const auto view = restored.snapshot(committed ? expected : original);
                        CHECK(view && *view == (committed ? after : before));
                        SQL sql(path);
                        CHECK(sql.value("SELECT count(*) FROM starts") == (committed ? "2" : "1"));
                        CHECK(sql.value("SELECT count(*) FROM members") == (committed && !replace ? "2" : "1"));
                        CHECK(restored.registerMember(proposed, std::string(32, 'b'), [&](const Member& member, const auto& directory) { CHECK(member == expected && directory == after); }));
                        CHECK(restored.current(expected) && *restored.snapshot(expected) == after);
                        CHECK(sql.value("SELECT count(*) FROM starts") == "2");
                        std::cout << "PULSAR-FAULT {\"event\":\"point\",\"case\":" << cases++ << ",\"replace\":" << replace << ",\"sync\":" << sync << ",\"error\":" << error << ",\"persistent\":" << persistent << ",\"ordinal\":" << ordinal << ",\"hits\":" << hits << ",\"committed\":" << committed << "}\n";
                    }
                }
            }
        }
    }
    CHECK(cases > 0 && std::cout.good());
    std::cout << "PULSAR-FAULT {\"event\":\"complete\",\"cases\":" << cases << "}\n";
}

/// Deferred-FK COMMIT failure does not prove rollback; explicitly roll back both tables and disable new registration.
void commitFailure(const std::filesystem::path& path, const std::string& authority) {

    Member original, candidate;
    {
        Ledger ledger(path, "alpha", authority, 2, 4, true);
        CHECK(ledger.registerMember(test::member(1), std::string(32, 'a'), [&](const Member& member, const auto&) { original = member; }));
        SQL sql(path);
        sql.execute("CREATE TABLE failure (principal TEXT REFERENCES members(principal) DEFERRABLE INITIALLY DEFERRED)");
        sql.execute("CREATE TRIGGER commit_failure AFTER INSERT ON starts BEGIN INSERT INTO failure VALUES('missing'); END");
        CHECK(!ledger.registerMember(test::member(2), std::string(32, 'b'), [&](const Member& member, const auto&) { candidate = member; }));
        CHECK(ledger.current(original) && !ledger.current(candidate));
        CHECK(sql.value("SELECT count(*) FROM members") == "1" && sql.value("SELECT count(*) FROM starts") == "1");
        CHECK(sql.value("SELECT count(*) FROM failure") == "0");
        sql.execute("DROP TRIGGER commit_failure");
        sql.execute("DROP TABLE failure");
        CHECK(!ledger.registerMember(test::member(2), std::string(32, 'b'), [](const auto&, const auto&) {}));
    }
    Ledger restored(path, "alpha", authority, 2, 4);
    CHECK(restored.current(original) && !restored.current(candidate));
}

/// An external file lock drives SQLite to BUSY; current-identity reads must remain independent of registration and disk locks.
void busy(const std::filesystem::path& path, const std::string& authority) {

    Ledger ledger(path, "alpha", authority, 2, 4, true);
    Member original;
    CHECK(ledger.registerMember(test::member(1), std::string(32, 'a'), [&](const Member& member, const auto&) { original = member; }));
    SQL sql(path);
    sql.execute("BEGIN EXCLUSIVE");
    // Synchronize at the precommit preparation boundary and retain the registration thread's actual result or exception.
    std::promise<void> prepared;
    std::promise<bool> outcome;
    auto waiting = prepared.get_future();
    auto result = outcome.get_future();
    const auto begin = Steady::now();
    std::jthread writer([&] {
        try {
            outcome.set_value(ledger.registerMember(test::member(2), std::string(32, 'b'), [&](const auto&, const auto&) { prepared.set_value(); }).has_value());
        } catch (...) {
            outcome.set_exception(std::current_exception());
        }
    });
    CHECK(waiting.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
    CHECK(ledger.current(original) && ledger.snapshot(original)->size() == 1);
    CHECK(result.wait_for(std::chrono::seconds(3)) == std::future_status::ready && !result.get());
    CHECK(Steady::now() - begin < std::chrono::seconds(4));
    sql.execute("ROLLBACK");
}

/// Mutate independent copies; recovery rejects unknown schema, missing idempotency evidence, and unsigned epoch corruption.
void corruption(const std::filesystem::path& root, const std::string& authority) {

    constexpr std::array mutations{
        "CREATE TABLE extra (value TEXT)",
        "CREATE INDEX unexpected ON starts(epoch)",
        "PRAGMA ignore_check_constraints=ON; UPDATE metadata SET format=2",
        "UPDATE metadata SET authority='wrong'",
        "DELETE FROM starts",
        "PRAGMA ignore_check_constraints=ON; UPDATE members SET body=x'ff'",
        "PRAGMA ignore_check_constraints=ON; UPDATE starts SET request=x'00'",
        "UPDATE starts SET epoch=x'0000000000000000'",
        "UPDATE starts SET epoch=x'7fffffffffffffff'",
        "UPDATE starts SET epoch=x'8000000000000000'",
        "UPDATE starts SET epoch=x'ffffffffffffffff'"};

    std::size_t index{};
    for (const auto mutation : mutations) {
        const auto path = root / ("corrupt-" + std::to_string(index++) + ".db");
        {
            Ledger ledger(path, "alpha", authority, 2, 4, true);
            CHECK(ledger.registerMember(test::member(1), std::string(32, 'a'), [](const auto&, const auto&) {}));
        }
        {
            SQL sql(path);
            sql.execute(mutation);
        }
        rejects([&] { Ledger invalid(path, "alpha", authority, 2, 4); });
        CHECK(std::filesystem::file_size(path) > 0);
    }

    const auto path = root / "physical.db";
    { Ledger ledger(path, "alpha", authority, 2, 4, true); }
    {
        std::fstream output(path, std::ios::in | std::ios::out | std::ios::binary);
        output.put('\xff');
    }
    rejects([&] { Ledger invalid(path, "alpha", authority, 2, 4); });
}

/// Reach the configured history limit, retain valid retries, and reject a forged maximum lacking its startup chain.
void exhaustion(const std::filesystem::path& path, const std::string& authority) {
    const std::array requests{std::string(32, 'a'), std::string(32, 'b'), std::string(32, 'c'), std::string(32, 'd')};
    Member committed;
    {
        Ledger ledger(path, "alpha", authority, 2, requests.size(), true);
        for (std::size_t index = 0; index < requests.size(); ++index) {
            auto candidate = test::member(1);
            candidate.id = "generation-" + std::to_string(index + 1);
            CHECK(ledger.registerMember(candidate, requests[index], [&](const Member& local, const auto& view) {
                committed = local;
                CHECK(local.epoch.value == index + 1 && view.size() == 1);
            }));
        }
    }
    {
        Ledger restored(path, "alpha", authority, 2, requests.size());
        CHECK(restored.current(committed));
        const auto snapshot = restored.snapshot(committed);
        CHECK(snapshot && snapshot->size() == 1 && committed.epoch.value == requests.size());
        unsigned prepared{};
        const auto prepare = [&](const Member& local, const auto& view) {
            ++prepared;
            CHECK(local == committed && view.size() == 1);
        };
        CHECK(restored.registerMember(test::member(1), requests.back(), prepare));
        CHECK(prepared == 1 && restored.snapshot(committed) == snapshot);
        auto next = test::member(1);
        next.id = "generation-5";
        const auto refused = restored.registerMember(next, std::string(32, 'x'), prepare);
        CHECK(!refused && refused.error().code == Status::Code::Capacity);
        CHECK(refused.error().message == "Startup history capacity reached");
        CHECK(prepared == 1 && restored.current(committed) && restored.snapshot(committed) == snapshot);
        const auto other = restored.registerMember(test::member(2), std::string(32, 'y'), prepare);
        CHECK(!other && other.error().code == Status::Code::Capacity && prepared == 1);
        CHECK(!restored.registerMember(test::member(1), requests.front(), prepare));
        CHECK(prepared == 1);
        CHECK(restored.registerMember(test::member(1), requests.back(), prepare));
        CHECK(prepared == 2 && restored.snapshot(committed) == snapshot);
    }
    committed.epoch.value = std::numeric_limits<std::uint64_t>::max();
    auto record = Identity::encode(committed);
    record.set_principal(committed.principal.text());
    {
        SQL sql(path);
        sql.replace(record.SerializeAsString());
        sql.execute("DELETE FROM starts WHERE epoch<>x'0000000000000004'");
        sql.execute("UPDATE starts SET epoch=x'ffffffffffffffff'");
        CHECK(sql.value("SELECT hex(epoch) FROM starts") == "FFFFFFFFFFFFFFFF");
    }
    bool refused{};
    try {
        Ledger invalid(path, "alpha", authority, 2, requests.size());
    } catch (const std::runtime_error& error) {
        CHECK(std::string_view(error.what()) == "Invalid or unavailable Pulsar SQLite database");
        refused = true;
    }
    CHECK(refused);
    std::cout << "PULSAR-EPOCH {\"history_limit\":4,\"successor_refused\":true,\"retry_preserved\":true,\"forged_maximum_refused\":true}\n";
}
} // namespace

int main() {

    try {
        test::Directory directory;
        const std::string authority(64, 'a');
#if defined(__linux__)
        test::ledgerFault(directory.path, authority);
#endif
        exhaustion(directory.path / "exhaustion.db", authority);
        initialization(directory.path, authority);
        registration(directory.path / "registration.db", authority);
        encoding(directory.path / "encoding.db", authority);
        concurrentRetry(directory.path / "concurrent.db", authority);
        commitFailure(directory.path / "commit.db", authority);
        busy(directory.path / "busy.db", authority);
        corruption(directory.path, authority);
        // Exercise common SQLite write errors and a separate xSync persistence failure.
        for (const int error : {SQLITE_IOERR_WRITE, SQLITE_FULL, SQLITE_NOMEM}) {
            ioFailure(directory.path / ("fault-" + std::to_string(error) + ".db"), authority, error, false);
        }
        ioFailure(directory.path / "sync.db", authority, SQLITE_IOERR_FSYNC, true);
        ioFailure(directory.path / "main-sync.db", authority, SQLITE_IOERR_FSYNC, true, true);
        ioFailure(directory.path / "rollback.db", authority, SQLITE_IOERR_WRITE, false, true, true);
        ioMatrix(directory.path, authority);
        std::cout << "PASS SQLite admission initialization, transactions, retry, fault recovery, bounds and read isolation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
