// Persist member identities and endpoint claims with explicit transaction and capacity boundaries.
#include "ledger.hpp"

#include "identity.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <fcntl.h>
#include <limits>
#include <set>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace astra {

/// Ledger-only SQL ownership. One writer lock protects runtime SQL; current-identity reads use an immutable view outside SQLite.
struct Ledger::Database {
    /// Create the fixed schema only on explicit initialization; exact SQL also rejects unknown schemas or extra objects.
    static constexpr std::array<std::string_view, 3> schema{
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=1), galaxy TEXT NOT NULL, authority TEXT NOT NULL) STRICT",
        "CREATE TABLE members (principal TEXT PRIMARY KEY CHECK(length(principal)=64), body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 1024)) STRICT, WITHOUT ROWID",
        "CREATE TABLE starts (request BLOB PRIMARY KEY CHECK(length(request)=32), principal TEXT NOT NULL REFERENCES members(principal), epoch BLOB NOT NULL CHECK(length(epoch)=8), UNIQUE(principal,epoch)) STRICT, WITHOUT ROWID"};

    /// Fixed errors exclude SQL, paths, and raw SQLite diagnostics.
    static void require(bool condition) {
        if (!condition) {
            throw std::runtime_error("Invalid or unavailable Pulsar SQLite database");
        }
    }

    /// Owns one regular-file descriptor for an authorized database or separate service lock.
    struct File {

        /// Own the native ledger descriptor until its RAII wrapper closes it.
        int value;

        File(const std::filesystem::path& path, int flags) : value(::open(path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW, 0600)) {

            /// Check the opened inode; reject FIFO, directory, and symlink state files.
            struct stat info{};
            if (value < 0 || ::fstat(value, &info) != 0 || !S_ISREG(info.st_mode)) {
                if (value >= 0) {
                    ::close(value);
                }
                require(false);
            }
        }

        /// Close releases flock. Keep the lock file so separate inodes cannot split the lock domain.
        ~File() {
            ::close(value);
        }

        File(const File&) = delete;

        File& operator=(const File&) = delete;
    };

    /// Owns the connection even if later construction fails; all statements must be destroyed first.
    struct Connection {
        /// sqlite3_open_v2 can return a handle requiring closure even on failure.
        sqlite3* value{};

        Connection() = default;

        ~Connection() {
            sqlite3_close_v2(value);
        }

        Connection(const Connection&) = delete;

        Connection& operator=(const Connection&) = delete;
    };

    /// RAII statement for static SQL, with typed parameters and no dynamic SQL concatenation.
    class Query {
    public:
        /// Borrows the connection and NUL-terminated static SQL; preparation failure leaves no statement behind.
        Query(sqlite3* database, const char* sql) {

            const auto code = sqlite3_prepare_v3(database, sql, -1, 0, &statement_, nullptr);
            if (code != SQLITE_OK) {
                sqlite3_finalize(statement_);
                require(false);
            }
        }

        ~Query() {
            sqlite3_finalize(statement_);
        }

        Query(const Query&) = delete;

        Query& operator=(const Query&) = delete;

        /// Borrows value until statement destruction; parameters are separate from SQL, with one-based positions.
        void text(int index, std::string_view value) {
            require(value.size() <= 2048 && sqlite3_bind_text(statement_, index, value.data(), static_cast<int>(value.size()), SQLITE_STATIC) == SQLITE_OK);
        }

        /// Bind explicit byte lengths so startup keys containing NUL are preserved.
        void blob(int index, std::string_view value) {
            require(value.size() <= 2048 && sqlite3_bind_blob(statement_, index, value.data(), static_cast<int>(value.size()), SQLITE_STATIC) == SQLITE_OK);
        }

        /// Returns whether a row is available. DONE is normal completion; all other results throw fixed errors.
        bool next() {

            const auto code = sqlite3_step(statement_);
            require(code == SQLITE_ROW || code == SQLITE_DONE);
            return code == SQLITE_ROW;
        }

        /// Column UTF-8 view, valid until the next step or finalization.
        std::string_view text(int column) const {
            return bytes(column, SQLITE_TEXT);
        }

        /// Column BLOB view; parse or copy before advancing the statement.
        std::string_view blob(int column) const {
            return bytes(column, SQLITE_BLOB);
        }

        /// For small PRAGMA/metadata integers only; never narrows identity epochs.
        sqlite3_int64 integer(int column) const {
            require(sqlite3_column_type(statement_, column) == SQLITE_INTEGER);
            return sqlite3_column_int64(statement_, column);
        }

    private:
        /// Zero-based column with exactly the expected storage type; no implicit conversion on mismatch.
        std::string_view bytes(int column, int type) const {
            require(sqlite3_column_type(statement_, column) == type);

            const auto data = static_cast<const char*>(sqlite3_column_blob(statement_, column));
            const auto size = sqlite3_column_bytes(statement_, column);
            require(size >= 0 && (data || size == 0));
            return {data ? data : "", static_cast<std::size_t>(size)};
        }

        /// Own the prepared SQLite statement; null means preparation has not succeeded.
        sqlite3_stmt* statement_{};
    };

    /// Static SQL, including transaction control and PRAGMA; excludes application data and credentials.
    void execute(const char* sql) {
        require(sqlite3_exec(connection.value, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    /// Explicitly roll back a failed transaction; COMMIT errors do not imply rollback has already occurred.
    bool rollback() noexcept {
        return sqlite3_get_autocommit(connection.value) != 0 || sqlite3_exec(connection.value, "ROLLBACK", nullptr, nullptr, nullptr) == SQLITE_OK;
    }

    /// Fixed-width big-endian BLOB preserves the full uint64 range and unsigned index ordering without SQLite REAL conversion.
    static std::array<char, 8> epoch(std::uint64_t value) {

        std::array<char, 8> result{};
        for (unsigned index = 0; index < result.size(); ++index) {
            result[index] = static_cast<char>((value >> (56 - index * 8)) & 255);
        }
        return result;
    }

    /// Decodes an eight-byte big-endian epoch; rejects other widths and zero.
    static std::uint64_t epoch(std::string_view value) {
        require(value.size() == 8);

        std::uint64_t result{};
        for (const char byte : value) {
            result = (result << 8) | static_cast<unsigned char>(byte);
        }
        require(result != 0);
        return result;
    }

    /// Opens or explicitly initializes a database without creating parent directories, overwriting files, or importing legacy stores.
    Database(const std::filesystem::path& path, std::string_view galaxy, std::string_view authority, bool initialize) : lock(path.string() + ".lock", O_RDWR | O_CREAT) {

        require(::flock(lock.value, LOCK_EX | LOCK_NB) == 0);
        // Check potential sidecars too; do not initialize beside residual recovery material.
        if (initialize) {
            for (const auto suffix : {"-journal", "-wal", "-shm"}) {
                require(std::filesystem::symlink_status(path.string() + suffix).type() == std::filesystem::file_type::not_found);
            }
        }
        // Initialization uses O_EXCL; normal startup cannot create a missing state file.
        const File file(path, O_RDWR | (initialize ? O_CREAT | O_EXCL : 0));
        /// Reject empty existing files and verify the path still refers to the opened inode after SQLite opens it.
        struct stat info{};
        require(::fstat(file.value, &info) == 0 && (initialize || info.st_size > 0));
        require(sqlite3_libversion_number() == 3053004 && sqlite3_threadsafe() != 0);
        require(sqlite3_open_v2(path.c_str(), &connection.value, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOFOLLOW, nullptr) == SQLITE_OK);
        /// Inspect the final path without following symlinks; state files require a trusted deployment directory.
        struct stat actual{};
        require(::lstat(path.c_str(), &actual) == 0 && S_ISREG(actual.st_mode) && actual.st_dev == info.st_dev && actual.st_ino == info.st_ino);
        require(sqlite3_busy_timeout(connection.value, 1000) == SQLITE_OK);
        sqlite3_limit(connection.value, SQLITE_LIMIT_LENGTH, 4096);
        sqlite3_limit(connection.value, SQLITE_LIMIT_SQL_LENGTH, 16384);
        // Verify SQLite's actual defensive setting, not merely the configuration call.
        int defensive{};
        require(sqlite3_db_config(connection.value, SQLITE_DBCONFIG_DEFENSIVE, 1, &defensive) == SQLITE_OK && defensive == 1);
        execute("PRAGMA trusted_schema=OFF");
        execute("PRAGMA foreign_keys=ON");
        if (initialize) {
            execute("PRAGMA journal_mode=DELETE");
        }
        execute("PRAGMA synchronous=EXTRA");
        {
            // Existing databases must already use DELETE journaling; recovery must not silently convert another mode.
            Query mode(connection.value, "PRAGMA journal_mode");
            require(mode.next() && mode.text(0) == "delete" && !mode.next());
        }

        for (const auto& [sql, expected] : std::array<std::pair<const char*, int>, 3>{{{"PRAGMA synchronous", 3}, {"PRAGMA foreign_keys", 1}, {"PRAGMA trusted_schema", 0}}}) {
            Query setting(connection.value, sql);
            require(setting.next() && setting.integer(0) == expected && !setting.next());
        }

        if (initialize) {
            execute("BEGIN IMMEDIATE");
            try {
                for (const auto sql : schema) {
                    execute(sql.data());
                }
                // Commit metadata bindings and schema in one transaction so partial initialization cannot pass recovery.
                Query metadata(connection.value, "INSERT INTO metadata VALUES(1,1,?,?)");
                metadata.text(1, galaxy);
                metadata.text(2, authority);
                require(!metadata.next());
                execute("COMMIT");
            } catch (...) {
                static_cast<void>(rollback());
                throw;
            }
            // Sync the new database and its parent directory. Preserve failures for inspection instead of recreating files.
            const auto parent = path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
            const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            const bool synced = ::fsync(file.value) == 0 && directory >= 0 && ::fsync(directory) == 0;
            if (directory >= 0) {
                ::close(directory);
            }
            require(synced);
        }

        // Validate physical integrity, known format, and identity bindings without schema migration or destructive repair.
        Query check(connection.value, "PRAGMA quick_check");
        require(check.next() && check.text(0) == "ok" && !check.next());
        Query foreign(connection.value, "PRAGMA foreign_key_check");
        require(!foreign.next());
        Query objects(connection.value, "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name");
        for (const auto index : {1U, 0U, 2U}) {
            require(objects.next() && objects.text(0) == schema[index]);
        }
        require(!objects.next());
        Query metadata(connection.value, "SELECT id,format,galaxy,authority FROM metadata");
        require(metadata.next() && metadata.integer(0) == 1 && metadata.integer(1) == 1 && metadata.text(2) == galaxy && metadata.text(3) == authority && !metadata.next());
    }

    /// The lock outlives the connection, preventing another issuer from taking over before closure.
    File lock;
    /// Sole write connection. NOMUTEX disables only SQLite's internal mutex; Ledger still serializes every SQL operation.
    Connection connection;
};

Ledger::Ledger(const std::filesystem::path& path, std::string galaxy, std::string authority, std::size_t maximum, std::size_t starts, bool initialize) : galaxy_(std::move(galaxy)), maximum_(maximum), maximumStarts_(starts) {

    if (!Member::validName(galaxy_) || !Principal::parse(authority) || maximum == 0 || maximum > 4096 || starts == 0 || starts > 1'000'000) {
        throw std::runtime_error("Invalid registration database configuration");
    }
    database_ = std::make_unique<Database>(path, galaxy_, authority, initialize);
    restore();
}

Ledger::~Ledger() = default;

Result<void> Ledger::validate(const Member& member, std::string_view requestId, const Members& view) const {

    if (!member.validate() || member.galaxy != galaxy_ || requestId.size() != 32) {
        return Status::configuration("Invalid registration record");
    }
    if (starts_.contains(requestId)) {
        return Status::conflict("Startup request already committed");
    }
    if (starts_.size() >= maximumStarts_) {
        return Status::capacity("Startup history capacity reached");
    }

    const auto principal = member.principal.text();
    // Locate the current deployment record by principal, not the new process ID.
    const auto old = view.find(principal);
    // Unknown deployments start at epoch zero; every new registration must use exactly the next epoch.
    const auto previous = old == view.end() ? 0 : old->second.epoch.value;
    if (previous == std::numeric_limits<std::uint64_t>::max() || member.epoch.value != previous + 1 || (old != view.end() && (old->second.role != member.role || old->second.address != member.address || old->second.id == member.id))) {
        return Status::conflict("Invalid deployment replacement");
    }

    // Enforce separate member quotas per role.
    std::size_t roleCount = 0;
    for (const auto& [key, current] : view) {
        if (current.role == member.role) {
            ++roleCount;
        }
        if (key != principal && (current.id == member.id || current.address == member.address)) {
            return Status::conflict("Member identity or endpoint already used");
        }
    }
    if (old == view.end() && roleCount >= maximum_) {
        return Status::capacity("Member capacity reached");
    }
    return {};
}

Result<void> Ledger::registerMember(Member candidate, std::string_view requestId, const std::function<void(const Member&, const Members&)>& prepare) {

    // Serialize registration validation and disk commit; current-credential reads use a separate immutable view.
    std::lock_guard lock(mutex_);
    if (!writable_) {
        return Status::transport("Registration database requires recovery");
    }
    if (requestId.size() != 32 || candidate.epoch.value != 0 || candidate.galaxy != galaxy_) {
        return Status::configuration("Invalid registration input");
    }

    const auto principal = candidate.principal.text();

    const auto view = members_.load();

    const auto old = view->find(principal);
    if (const auto start = starts_.find(requestId); start != starts_.end()) {
        if (old == view->end() || start->second.principal != principal || start->second.epoch != old->second.epoch.value || old->second.role != candidate.role || old->second.group != candidate.group || old->second.address != candidate.address) {
            return Status::conflict("Startup request no longer matches current deployment");
        }

        // Idempotent retries preserve identity but return the current directory, without caching old responses.
        prepare(old->second, *view);
        return {};
    }
    if (old != view->end() && old->second.epoch.value == std::numeric_limits<std::uint64_t>::max()) {
        return Status::conflict("Member epoch exhausted");
    }
    candidate.epoch.value = old == view->end() ? 1 : old->second.epoch.value + 1;
    if (auto valid = validate(candidate, requestId, *view); !valid) {
        return valid;
    }

    // Prepare a replacement directory without publishing it if response preparation or disk commit fails.
    auto replacement = std::make_shared<Members>(*view);
    replacement->insert_or_assign(principal, candidate);
    // Prepare the node handle and complete response before commit; no map-node allocation or response serialization afterward.
    std::map<std::string, Start, std::less<>> pending;
    pending.emplace(std::string(requestId), Start{principal, candidate.epoch.value});

    auto node = pending.extract(pending.begin());
    // Persistent format 1 retains 64-character principal digests, independently of the 32-byte wire representation.
    // Commit the current member and separate startup-request index in one SQLite transaction.
    auto record = Identity::encode(candidate);
    record.set_principal(principal);
    // Serialize the member before response preparation; no allocation or member serialization after successful COMMIT.
    const auto payload = record.SerializeAsString();
    prepare(candidate, *replacement);
    if (!commit(candidate, requestId, payload)) {
        return Status::transport("Registration durability is uncertain; restart required");
    }
    starts_.insert(std::move(node));
    members_.store(std::move(replacement));
    return {};
}

bool Ledger::current(const Member& member) const {
    return static_cast<bool>(snapshot(member));
}

std::shared_ptr<const Ledger::Members> Ledger::snapshot(const Member& member) const {

    // Use one immutable snapshot throughout credential verification.
    const auto snapshot = members_.load();

    const auto found = snapshot->find(member.principal.text());
    return found != snapshot->end() && found->second == member ? snapshot : nullptr;
}

bool Ledger::commit(const Member& member, std::string_view request, std::string_view payload) {

    // Prepare statements and bindings before COMMIT, leaving no fallible preparation between durable commit and memory publication.
    Database::require(!payload.empty() && payload.size() <= 1024);
    const auto principal = member.principal.text();
    const auto epoch = Database::epoch(member.epoch.value);
    try {
        Database::Query current(database_->connection.value, "INSERT INTO members(principal,body) VALUES(?,?) ON CONFLICT(principal) DO UPDATE SET body=excluded.body");
        current.text(1, principal);
        current.blob(2, payload);
        Database::Query startup(database_->connection.value, "INSERT INTO starts(request,principal,epoch) VALUES(?,?,?)");
        startup.blob(1, request);
        startup.text(2, principal);
        startup.blob(3, {epoch.data(), epoch.size()});

        // Both tables commit together or preserve the old state. Response and container nodes are already prepared.
        database_->execute("BEGIN IMMEDIATE");
        Database::require(!current.next());
        Database::require(!startup.next());
        database_->execute("COMMIT");
        return true;
    } catch (...) {
        // Stop registration even after successful rollback; this connection cannot resolve an uncertain durable COMMIT result.
        // Both statements are destroyed before rollback so active statements cannot obstruct rollback or restart recovery.
        writable_ = false;
        static_cast<void>(database_->rollback());
        return false;
    }
}

void Ledger::restore() {

    // One recovery transaction prevents mixing members and startup records from different disk states.
    database_->execute("BEGIN");
    try {
        // Reject identities and endpoint aliases reused across deployments before publishing the recovered view.
        auto recovered = std::make_shared<Members>();
        std::set<Id> ids;
        std::set<Endpoint> addresses;

        std::array<std::size_t, 4> counts{};
        Database::Query members(database_->connection.value, "SELECT principal,body FROM members ORDER BY principal");
        while (members.next()) {
            // Parse and copy borrowed row data before the next step.
            const auto principal = members.text(0);
            const auto body = members.blob(1);
            Database::require(principal.size() == 64 && !body.empty() && body.size() <= 1024);
            proto::orbit::v1::Member record;
            Database::require(record.ParseFromArray(body.data(), static_cast<int>(body.size())));
            // Format 1 stores the canonical text digest matching the primary key. Convert only in memory; do not rewrite during recovery.
            const auto digest = Principal::parse(record.principal());
            Database::require(digest && record.principal() == principal);
            record.set_principal(digest->bytes.data(), digest->bytes.size());
            const auto member = decodeMember(record);
            Database::require(member && member->galaxy == galaxy_ && member->principal.text() == principal);
            Database::require(++counts[static_cast<std::size_t>(member->role)] <= maximum_ && ids.insert(member->id).second && addresses.insert(member->address).second);
            Database::require(recovered->emplace(principal, *member).second);
        }

        // Retain every startup epoch from one through the current epoch. Check overflow before incrementing; never convert epoch BLOBs to signed INTEGER.
        std::string previous;
        std::uint64_t sequence{};
        std::size_t deployments{};
        Database::Query starts(database_->connection.value, "SELECT request,principal,epoch FROM starts ORDER BY principal,epoch");
        while (starts.next()) {

            const auto request = starts.blob(0);
            const auto principal = starts.text(1);
            const auto epoch = Database::epoch(starts.blob(2));
            const auto member = recovered->find(principal);
            Database::require(request.size() == 32 && member != recovered->end() && starts_.size() < maximumStarts_);
            if (previous != principal) {
                Database::require(previous.empty() || sequence == recovered->at(previous).epoch.value);
                previous = principal;
                sequence = 0;
                ++deployments;
            }
            Database::require(sequence != std::numeric_limits<std::uint64_t>::max() && epoch == sequence + 1 && epoch <= member->second.epoch.value);
            sequence = epoch;
            Database::require(starts_.emplace(std::string(request), Start{std::string(principal), epoch}).second);
        }
        Database::require(deployments == recovered->size() && (previous.empty() || sequence == recovered->at(previous).epoch.value));
        database_->execute("COMMIT");
        members_.store(std::move(recovered));
    } catch (...) {
        static_cast<void>(database_->rollback());
        throw;
    }
}
} // namespace astra
