// Implement the isolated SQLite test VFS and fault counters.
#include "database_fault.hpp"

#include "check.hpp"

#include <stdexcept>

namespace astra::test {
const sqlite3_io_methods Fault::methods_ = {
    1,
    /// Closes the inner file; SQLite then frees the wrapper storage.
    [](sqlite3_file* value) { return file(value)->pMethods->xClose(file(value)); },

    [](sqlite3_file* value, void* buffer, int amount, sqlite3_int64 offset) { return file(value)->pMethods->xRead(file(value), buffer, amount, offset); },
    /// Consumes a fault before writing; otherwise forwards the original bytes and offset.
    [](sqlite3_file* value, const void* buffer, int amount, sqlite3_int64 offset) {
        const auto error = failure(value, false);
        return error ? error : file(value)->pMethods->xWrite(file(value), buffer, amount, offset);
    },

    [](sqlite3_file* value, sqlite3_int64 size) { return file(value)->pMethods->xTruncate(file(value), size); },
    /// Preserves SQLite's sync level; never reports failed persistence as successful.
    [](sqlite3_file* value, int flags) {
        const auto error = failure(value, true);
        return error ? error : file(value)->pMethods->xSync(file(value), flags);
    },

    [](sqlite3_file* value, sqlite3_int64* size) { return file(value)->pMethods->xFileSize(file(value), size); },

    [](sqlite3_file* value, int mode) { return file(value)->pMethods->xLock(file(value), mode); },

    [](sqlite3_file* value, int mode) { return file(value)->pMethods->xUnlock(file(value), mode); },

    [](sqlite3_file* value, int* held) { return file(value)->pMethods->xCheckReservedLock(file(value), held); },

    [](sqlite3_file* value, int operation, void* argument) { return file(value)->pMethods->xFileControl(file(value), operation, argument); },

    [](sqlite3_file* value) { return file(value)->pMethods->xSectorSize(file(value)); },
    /// Forwards actual device capabilities without inventing atomic-write guarantees.
    [](sqlite3_file* value) { return file(value)->pMethods->xDeviceCharacteristics(file(value)); },
    /// Version 1 excludes WAL/shared memory and mmap, matching the tested DELETE mode.
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};

Fault::Fault() : parent_(sqlite3_vfs_find(nullptr)) {
    CHECK(parent_ && !active_);
    // Preserve non-file callbacks and private data; xOpen still receives the original parent VFS.
    copy_ = *parent_;
    copy_.zName = "astra-ledger-fault";
    copy_.szOsFile = parent_->szOsFile + static_cast<int>(sizeof(File));
    copy_.xOpen = open;
    active_ = this;
    if (sqlite3_vfs_register(&copy_, 1) != SQLITE_OK) {
        active_ = nullptr;
        throw std::runtime_error("Cannot install owned SQLite test VFS");
    }
}

Fault::~Fault() {
    sqlite3_vfs_register(parent_, 1);
    sqlite3_vfs_unregister(&copy_);
    active_ = nullptr;
}

void Fault::watch(bool sync, bool main) {
    sync_ = sync;
    main_ = main;
    error_ = SQLITE_OK;
    calls_ = 0;
    hits_ = 0;
    position_ = 0;
}

void Fault::arm(int code, bool sync, bool main, unsigned repeat, unsigned skip) {
    CHECK(code != SQLITE_OK);
    watch(sync, main);
    repeat_ = repeat;
    skip_ = skip;
    error_ = code;
}

int Fault::failure(sqlite3_file* file, bool sync) {
    if (active_->sync_ == sync && (!active_->main_ || reinterpret_cast<File*>(file)->main) && ++active_->calls_ > active_->skip_ && active_->error_) {
        if (active_->hits_ == 0) {
            active_->position_ = active_->calls_ - 1;
        }
        ++active_->hits_;
        const auto error = active_->error_;
        if (active_->repeat_ && --active_->repeat_ == 0) {
            active_->error_ = SQLITE_OK;
        }
        return error;
    }
    return SQLITE_OK;
}

int Fault::open(sqlite3_vfs*, const char* name, sqlite3_file* value, int flags, int* output) {
    // Wrapper and inner file share SQLite's allocation while preserving sqlite3_file alignment.
    static_assert(sizeof(File) % alignof(sqlite3_file) == 0);
    auto* wrapper = reinterpret_cast<File*>(value);
    wrapper->main = (flags & SQLITE_OPEN_MAIN_DB) != 0;
    wrapper->inner = reinterpret_cast<sqlite3_file*>(reinterpret_cast<char*>(value) + sizeof(File));
    const auto error = active_->parent_->xOpen(active_->parent_, name, wrapper->inner, flags, output);
    if (error == SQLITE_OK || wrapper->inner->pMethods) {
        wrapper->outer.pMethods = &methods_;
    }
    return error;
}
} // namespace astra::test
