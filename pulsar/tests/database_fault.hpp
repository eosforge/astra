// Inject SQLite failure paths into isolated ledger tests without changing production database behavior.
#pragma once

#include <sqlite3.h>

namespace astra::test {
/// Test-only VFS forwards real disk I/O and injects write/sync errors. Production has no fault switch.
class Fault {
public:
    /// Requires an existing default VFS and one injector per process. All test connections must close before destruction.
    Fault();

    /// Restores the default VFS and unregisters this test name.
    ~Fault();

    /// A registered process-wide VFS has one owner and cannot be copied.
    Fault(const Fault&) = delete;

    /// Do not replace a live VFS owner through assignment.
    Fault& operator=(const Fault&) = delete;

    /// Observe matching real calls without changing their results; reset ordinal and failure counters.
    void watch(bool sync = false, bool main = false);

    /// Fail after skip matching calls; repeat=0 persists through rollback, otherwise failures are finite.
    void arm(int code, bool sync = false, bool main = false, unsigned repeat = 1, unsigned skip = 0);

    /// Return actual matching I/O calls, including recovery calls after the selected failure.
    unsigned calls() const {
        return calls_;
    }

    /// Return the first failed call's zero-based ordinal; inspect only after hits() becomes nonzero.
    unsigned position() const {
        return position_;
    }

    /// Records whether injection reached the intended disk path.
    unsigned hits() const {
        return hits_;
    }

    /// Stops persistent injection so the same file can be recovered after closing the tested connection.
    void clear() {
        error_ = SQLITE_OK;
    }

private:
    /// SQLite-allocated wrapper followed by the original VFS's sqlite3_file storage, without a separate allocation.
    struct File {

        /// SQLite-visible file prefix whose method table dispatches through this wrapper.
        sqlite3_file outer;
        /// Borrows the real file object in the same SQLite allocation.
        sqlite3_file* inner;

        /// True only for SQLITE_OPEN_MAIN_DB, excluding journals from main-only faults.
        bool main;
    };

    /// Process-local injector; outlives every fault-injected connection.
    inline static Fault* active_{};

    /// Borrows the default VFS restored when the injector is destroyed.
    sqlite3_vfs* parent_;

    /// Registered copy forwarding every callback except wrapped file creation.
    sqlite3_vfs copy_{};
    /// Pending error, zero for none. All SQLite calls run on one test thread.
    int error_{};

    /// Select sync calls when true and write calls when false.
    bool sync_{};
    /// Restricts failure to the main database, after rollback-journal persistence.
    bool main_{};
    /// Remaining failures; zero means persistent failure until clear.
    unsigned repeat_ = 1;

    /// Number of calls on which the configured error was actually returned.
    unsigned hits_{};
    /// Matching calls since watch/arm, independent of whether injection is enabled.
    unsigned calls_{};
    /// Successful matching calls preceding the first injected failure.
    unsigned skip_{};
    /// Matching-call ordinal at the first injected failure.
    unsigned position_{};

    /// Borrow the underlying VFS file from a SQLite-owned wrapper allocation.
    static sqlite3_file* file(sqlite3_file* value) {
        return reinterpret_cast<File*>(value)->inner;
    }

    /// Count matching calls and inject at the requested ordinal without allocating in a C callback.
    static int failure(sqlite3_file* file, bool sync);

    /// Forwards the DELETE-mode v1 file interface with SQLite's native ABI and units.
    static const sqlite3_io_methods methods_;

    /// Open through the original VFS, retaining its status and installing the forwarding table when cleanup is needed.
    static int open(sqlite3_vfs*, const char* name, sqlite3_file* value, int flags, int* output);
};
} // namespace astra::test
