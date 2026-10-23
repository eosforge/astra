// Verify copy-on-write SDK table updates and retained snapshot isolation.
#include "check.hpp"
#include "table.hpp"

#include <array>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
/// Uses actual owned payloads to verify old roots; synthetic logical lengths trigger overflow without huge allocations.
struct Record {
    /// Estimated payload object and shared-control-block cost for test records.
    static constexpr std::size_t overhead = sizeof(std::string) + 32;
    /// Normal records are non-null; old roots retain payload independently.
    std::shared_ptr<const std::string> value;
    /// Normally value->size(); overflow cases may use SIZE_MAX.
    std::size_t length{};

    /// Same logical-byte measurement entry as actual records in all three domains.
    std::size_t bytes() const noexcept {
        return length;
    }
};

/// Tests private owned pages without network or business versions.
using Table = comet::detail::Table<Record>;

/// Returns a record with independent payload; callers may retain weak references to observe candidate release.
Record record(std::string value) {
    const auto length = value.size(); // Save actual length before moving the string.
    return {std::make_shared<const std::string>(std::move(value)), length};
}

/// Choose first and last pages of all four bitmap words without assuming implementation-specific Key hashes.
std::vector<std::string> boundaries() {

    constexpr std::array<std::size_t, 8> targets{0, 63, 64, 127, 128, 191, 192, 255}; // Crosses 64-bit boundaries and includes the highest page.
    std::array<std::string, targets.size()> found{};                                  // Retain the first nonempty matching Key per target only.
    std::size_t remaining = found.size();                                             // Remaining pages in the bounded search; stop when all are found.
    for (unsigned attempt = 0; attempt < 262144 && remaining != 0; ++attempt) {
        auto key = "boundary-" + std::to_string(attempt); // Uses the same string_view hash as Table to locate pages.
        const auto slot = std::hash<std::string_view>{}(key) & 255;
        for (std::size_t index = 0; index < targets.size(); ++index) {
            if (targets[index] == slot && found[index].empty()) {
                found[index] = std::move(key);
                --remaining;
                break;
            }
        }
    }
    CHECK(remaining == 0);
    return {found.begin(), found.end()};
}

/// Cross-word publication, final-entry deletion, and empty-page reuse must preserve edge pages and old roots.
void pages() {

    const auto keys = boundaries(); // Eight independent pages cover all four bitmap words.
    Table current;                  // Initially no pages; storage includes the root only.
    CHECK(current.footprint() == sizeof(Table));
    Table::Draft initial(current);
    for (const auto& key : keys) {
        initial.set(key, record("before"));
    }
    current = std::move(initial).finish();
    const auto old = current;              // Later replacement and clearing must preserve this shared root.
    const auto retained = old.footprint(); // Original-root charges must remain stable too.
    CHECK(current.size() == keys.size());

    Table::Draft changed(current);
    for (std::size_t index = 0; index < keys.size(); ++index) {
        if (index % 2 == 0) {
            changed.erase(keys[index]);
        } else {
            changed.set(keys[index], record("after"));
        }
    }
    Table::Draft moved(std::move(changed)); // Moving a candidate transfers its bitmap, charges, and pages together.
    current = std::move(moved).finish();
    CHECK(current.size() == keys.size() / 2);
    for (std::size_t index = 0; index < keys.size(); ++index) {
        CHECK(old.find(keys[index]) && *old.find(keys[index])->value == "before");
        const auto* item = current.find(keys[index]); // Borrows the current complete root only, not beyond reassignment.
        CHECK(index % 2 == 0 ? item == nullptr : item && *item->value == "after");
    }
    CHECK(old.footprint() == retained);

    Table::Draft cleared(current);
    for (const auto& key : keys) {
        cleared.erase(key); // Also covers no-op deletion of a missing Key.
    }
    current = std::move(cleared).finish();
    CHECK(current.size() == 0 && current.bytes() == 0 && current.footprint() == sizeof(Table));
    Table::Draft reused(current);
    reused.set(keys.back(), record("temporary"));
    reused.erase(keys.back()); // Insertion followed by deletion in one candidate must return empty-page and bucket charges at publication.
    current = std::move(reused).finish();
    CHECK(current.footprint() == sizeof(Table));
}

/// Compare repeated changes with an independent ordered map; large shrinkage must leave neither empty-bucket charges nor changed old roots.
void contents() {

    Table current;                               // Paged table under test.
    std::map<std::string, std::string> expected; // Independent reference model, without reproducing paging or space-accounting algorithms.
    for (unsigned round = 0; round < 24; ++round) {
        const auto old = current;               // Retain old roots every batch to require owned COW.
        const auto previous = expected;         // Reference for checking old roots remain unchanged.
        const auto footprint = old.footprint(); // Repeated old-root measurements must stay stable.
        Table::Draft draft(current);
        for (unsigned index = 0; index < 192; ++index) {
            auto key = "entry-" + std::to_string((round * 73 + index) % 768); // Fixed sequence covers repeated replacement and deletion.
            if ((round + index) % 4 == 0) {
                draft.erase(key);
                expected.erase(key);
            } else {
                auto value = std::to_string(round) + ":" + std::to_string(index);
                draft.set(key, record(value));
                expected.insert_or_assign(std::move(key), std::move(value));
            }
        }
        current = std::move(draft).finish();
        CHECK(current.size() == expected.size() && old.size() == previous.size() && old.footprint() == footprint);
        std::size_t bytes{}; // Sum logical size independently from visible entries, without cached-field access.
        std::size_t count{}; // Check traversal has no missing, duplicate, or residual entries.
        current.each([&](std::string_view key, const Record& item) {
            CHECK(expected.at(std::string(key)) == *item.value);
            bytes += key.size() + item.value->size();
            ++count;
        });
        CHECK(bytes == current.bytes() && count == expected.size() && current.footprint() >= bytes + sizeof(Table));
        for (const auto& [key, value] : previous) {
            CHECK(old.find(key) && *old.find(key)->value == value);
        }
    }

    Table::Draft cleared(current);
    for (const auto& [key, value] : expected) {
        static_cast<void>(value); // Deletion needs only reference-map Keys.
        cleared.erase(key);
    }
    current = std::move(cleared).finish();
    CHECK(current.footprint() == sizeof(Table));
}

/// Insertion borrows input only until return and must own names; replacement, repeated deletion, and reinsertion preserve accounting.
void keys() {

    Table current; // Empty root must not own the caller's reusable name buffer.
    Table::Draft draft(current);
    std::string key(256, 'a'); // Long Key exceeds SSO; immediately overwrite and free the same buffer.
    const auto original = key; // Independent reference name for later lookups.
    draft.set(key, record("first"));
    key.assign("short");
    draft.set(key, record("second"));
    key.clear();
    key.shrink_to_fit();
    current = std::move(draft).finish();
    const auto old = current; // New batches must not change old-root names or payloads.
    CHECK(current.size() == 2 && *current.find(original)->value == "first" && *current.find("short")->value == "second");

    Table::Draft changed(current);
    changed.set(original, record("updated"));
    changed.set(original, record("final")); // Repeated replacement on an exclusive page changes neither record count nor duplicate charges.
    changed.erase(original);
    changed.erase(original); // Missing Delete on an exclusive page must not underflow counts.
    changed.set(original, record("restored"));
    current = std::move(changed).finish();
    CHECK(current.size() == 2 && current.bytes() == original.size() + 8 + 5 + 6);
    CHECK(*current.find(original)->value == "restored" && *old.find(original)->value == "first");
}

/// Discarded candidates and length overflow leak no temporary payload and preserve published contents and charges.
void rollback() {

    Table current;
    Table::Draft initial(current);
    initial.set("key", record("retained"));
    current = std::move(initial).finish();
    const auto footprint = current.footprint(); // Both failures must preserve this complete root.
    std::weak_ptr<const std::string> temporary; // Does not extend candidate payload lifetime.
    {
        Table::Draft abandoned(current);
        auto value = record("temporary");
        temporary = value.value;
        abandoned.set("key", std::move(value));
    }
    CHECK(temporary.expired() && *current.find("key")->value == "retained" && current.footprint() == footprint);
    bool rejected{}; // Catch expected accounting overflow only; the test entry reports other exceptions.
    try {
        Table::Draft failed(current);
        auto value = record("bounded allocation");
        value.length = std::numeric_limits<std::size_t>::max();
        failed.set("overflow", std::move(value));
    } catch (const std::length_error&) {
        rejected = true;
    }
    CHECK(rejected && !current.find("overflow") && current.size() == 1 && current.footprint() == footprint);
}
} // namespace

/// Pure owned-dictionary tests create no threads, network work, or tool processes.
int main() {
    try {
        pages();
        contents();
        keys();
        rollback();
        std::cout << "Comet table cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
