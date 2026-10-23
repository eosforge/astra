// Verify Ledger constructor cleanup with native file refusal and SQLite's supported allocation-fault interface.
#include "ledger.hpp"
#include "pulsar_test.hpp"

#include <sqlite3.h>

#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>

using namespace astra;

namespace {
/// Scope one refusal to the calling constructor thread; every other native operation is forwarded.
struct Fault {
    /// Select the native boundary reached by the owned constructor.
    enum class Mode {
        /// Forward every call to its real implementation.
        None,
        /// Refuse the first successful descriptor metadata query.
        File,
        /// Make the first owned statement preparation encounter real SQLite allocation failure.
        Query,
        /// Fail the metadata insertion after schema creation has begun its native transaction.
        Metadata,
    };
    /// Selected boundary, withdrawn before unwinding can invoke another operation.
    Mode mode{};
    /// Permit allocation refusal only while the selected native prepare call is active.
    bool allocation{};
    /// Preserve SQLite's failure contract instead of fabricating a partial statement handle.
    bool empty{};
    /// Native descriptor whose constructor must close after metadata refusal.
    int descriptor{-1};
    /// Actual refusal count, including any native SQLite retry within the same operation.
    unsigned failures{};
    /// Actual result of disabling this connection's lookaside cache.
    int configured{SQLITE_MISUSE};
    /// Original SQLite preparation result, never replaced by a synthetic status.
    int result{SQLITE_OK};
};

/// Keep refusal state local to the constructor thread without affecting unrelated SQLite users.
thread_local Fault fault;

/// Preserve the complete native allocation table, including its own initialization and shutdown callbacks.
sqlite3_mem_methods native;

/// Refuse only allocation requests made inside the selected native statement preparation.
void* allocate(int size) noexcept {
    if (fault.allocation) {
        ++fault.failures;
        return nullptr;
    }
    return native.xMalloc(size);
}

/// Preserve SQLite's original buffer on failure; its caller retains the native cleanup obligation.
void* resize(void* data, int size) noexcept {
    if (fault.allocation) {
        ++fault.failures;
        return nullptr;
    }
    return native.xRealloc(data, size);
}

/// Install SQLite's documented test allocator only while no database or worker owns its global configuration.
class Memory {
public:
    /// Capture and wrap the existing implementation without replacing C++ or process-wide allocation.
    Memory() {
        CHECK(sqlite3_shutdown() == SQLITE_OK);
        CHECK(sqlite3_config(SQLITE_CONFIG_GETMALLOC, &native) == SQLITE_OK);
        CHECK(native.xMalloc && native.xRealloc);
        auto wrapped = native;
        wrapped.xMalloc = allocate;
        wrapped.xRealloc = resize;
        CHECK(sqlite3_config(SQLITE_CONFIG_MALLOC, &wrapped) == SQLITE_OK);
    }

    /// Restore native behavior on assertion failures as well as normal completion.
    ~Memory() {
        fault = {};
        if (!restored_) {
            static_cast<void>(sqlite3_shutdown());
            static_cast<void>(sqlite3_config(SQLITE_CONFIG_MALLOC, &native));
        }
    }

    /// Prove restoration before the existing independently threaded Ledger suite begins.
    void restore() {
        fault = {};
        CHECK(sqlite3_shutdown() == SQLITE_OK);
        CHECK(sqlite3_config(SQLITE_CONFIG_MALLOC, &native) == SQLITE_OK);
        restored_ = true;
    }

    /// Keep configuration restoration under one owner.
    Memory(const Memory&) = delete;
    /// Prevent overwriting an active native configuration scope.
    Memory& operator=(const Memory&) = delete;

private:
    /// Avoid reconfiguring SQLite again after explicit successful restoration.
    bool restored_{};
};
} // namespace

extern "C" int __real_fstat(int descriptor, struct stat* info);
extern "C" int __real_sqlite3_open_v2(const char* path, sqlite3** database, int flags, const char* vfs);
extern "C" int __real_sqlite3_prepare_v3(sqlite3* database, const char* text, int bytes, unsigned flags, sqlite3_stmt** statement, const char** tail);

/// Observe a valid owned descriptor before returning one explicit metadata-read refusal.
extern "C" int __wrap_fstat(int descriptor, struct stat* info) {
    const auto result = __real_fstat(descriptor, info);
    if (fault.mode == Fault::Mode::File && result == 0) {
        fault.mode = Fault::Mode::None;
        fault.descriptor = descriptor;
        ++fault.failures;
        errno = EIO;
        return -1;
    }
    return result;
}

/// Disable this selected connection's lookaside before any statement can borrow its slots.
extern "C" int __wrap_sqlite3_open_v2(const char* path, sqlite3** database, int flags, const char* vfs) {
    const auto result = __real_sqlite3_open_v2(path, database, flags, vfs);
    if (result == SQLITE_OK && (fault.mode == Fault::Mode::Query || fault.mode == Fault::Mode::Metadata)) {
        fault.configured = sqlite3_db_config(*database, SQLITE_DBCONFIG_LOOKASIDE, nullptr, 0, 0);
    }
    return result;
}

/// Make the actual SQLite parser report allocation failure, preserving its result and statement contract.
extern "C" int __wrap_sqlite3_prepare_v3(sqlite3* database, const char* text, int bytes, unsigned flags, sqlite3_stmt** statement, const char** tail) {
    if (fault.mode != Fault::Mode::Query && !(fault.mode == Fault::Mode::Metadata && std::string_view(text) == "INSERT INTO metadata VALUES(1,1,?,?)")) {
        return __real_sqlite3_prepare_v3(database, text, bytes, flags, statement, tail);
    }
    fault.mode = Fault::Mode::None;
    fault.allocation = true;
    const auto result = __real_sqlite3_prepare_v3(database, text, bytes, flags, statement, tail);
    fault.allocation = false;
    fault.result = result;
    fault.empty = *statement == nullptr;
    return result;
}

namespace astra::test {
/// Require each constructor refusal to clean up and leave an existing durable member recoverable.
void ledgerFault(const std::filesystem::path& root, const std::string& authority) {
    Memory memory;
    for (const auto mode : {Fault::Mode::File, Fault::Mode::Query}) {
        const auto path = root / (mode == Fault::Mode::File ? "metadata-refusal.db" : "prepare-memory.db");
        Member committed;
        {
            Ledger ledger(path, "alpha", authority, 2, 4, true);
            CHECK(ledger.registerMember(member(1), std::string(32, 'f'), [&](const Member& local, const auto&) { committed = local; }));
        }
        fault = {};
        fault.mode = mode;
        bool refused{};
        try {
            Ledger ledger(path, "alpha", authority, 2, 4);
        } catch (const std::runtime_error& error) {
            CHECK(std::string_view(error.what()) == "Invalid or unavailable Pulsar SQLite database");
            refused = true;
        }
        CHECK(refused);
        CHECK(fault.mode == Fault::Mode::None && !fault.allocation);
        if (mode == Fault::Mode::File) {
            CHECK(fault.failures == 1 && fault.descriptor >= 0);
            errno = 0;
            CHECK(::fcntl(fault.descriptor, F_GETFD) == -1 && errno == EBADF);
        } else {
            CHECK(fault.configured == SQLITE_OK);
            CHECK(fault.failures > 0 && fault.result == SQLITE_NOMEM);
            CHECK(fault.empty);
        }
        const auto failures = fault.failures;
        fault = {};
        {
            Ledger recovered(path, "alpha", authority, 2, 4);
            CHECK(recovered.current(committed));
            const auto snapshot = recovered.snapshot(committed);
            CHECK(snapshot && snapshot->size() == 1);
            unsigned prepared{};
            CHECK(recovered.registerMember(member(1), std::string(32, 'f'), [&](const Member& local, const auto& view) {
                ++prepared;
                CHECK(local == committed && view.size() == 1);
            }));
            CHECK(prepared == 1 && recovered.snapshot(committed) == snapshot);
        }
        std::cout << "PULSAR-LEDGER-BOUNDARY {\"case\":\"" << (mode == Fault::Mode::File ? "metadata-refusal" : "prepare-memory") << "\",\"refusals\":" << failures << "}\n";
    }
    const auto path = root / "initialization-memory.db";
    fault = {};
    fault.mode = Fault::Mode::Metadata;
    bool refused{};
    try {
        Ledger ledger(path, "alpha", authority, 2, 4, true);
    } catch (const std::runtime_error& error) {
        CHECK(std::string_view(error.what()) == "Invalid or unavailable Pulsar SQLite database");
        refused = true;
    }
    CHECK(refused && std::filesystem::is_regular_file(path));
    CHECK(fault.mode == Fault::Mode::None && !fault.allocation);
    CHECK(fault.configured == SQLITE_OK && fault.failures > 0 && fault.result == SQLITE_NOMEM && fault.empty);
    const auto failures = fault.failures;
    fault = {};
    {
        sqlite3* database{};
        const auto opened = sqlite3_open_v2(path.c_str(), &database, SQLITE_OPEN_READWRITE, nullptr);
        const std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> owner(database, sqlite3_close_v2);
        CHECK(opened == SQLITE_OK);
        CHECK(sqlite3_get_autocommit(database) != 0);
        sqlite3_stmt* statement{};
        const auto prepared = sqlite3_prepare_v3(database, "SELECT count(*) FROM sqlite_schema WHERE type='table'", -1, 0, &statement, nullptr);
        const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(statement, sqlite3_finalize);
        CHECK(prepared == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW);
        CHECK(sqlite3_column_int(statement, 0) == 0);
        CHECK(sqlite3_step(statement) == SQLITE_DONE);
    }
    {
        Ledger recovered(root / "initialization-recovered.db", "alpha", authority, 2, 4, true);
        Member committed;
        CHECK(recovered.registerMember(member(1), std::string(32, 'r'), [&](const Member& local, const auto&) { committed = local; }));
        CHECK(recovered.current(committed));
    }
    CHECK(std::filesystem::is_regular_file(path));
    std::cout << "PULSAR-LEDGER-BOUNDARY {\"case\":\"initialization-rollback\",\"refusals\":" << failures << "}\n";
    memory.restore();
    std::cout << "PULSAR-LEDGER-BOUNDARY {\"complete\":true}\n";
}
} // namespace astra::test
