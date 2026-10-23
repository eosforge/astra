// Verify pagination of frozen Almanac views and completion positions.
#include "check.hpp"
#include "edition.hpp"

#include <array>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {
using astra::Almanac;
using astra::Edition;

/// Decodes a complete frozen batch into comparable results; completion fields belong only to the last page.
std::map<std::string, std::optional<std::string>> consume(Edition& edition, proto::comet::v1::Mode mode, std::size_t minimum = 1) {

    std::map<std::string, std::optional<std::string>> records; // Unique keys per batch; overwrite cannot hide duplicates.
    std::size_t pages{};
    while (!edition.complete()) {
        auto page = edition.next("star-test"); // Each page owns encoding without writable aliases into Edition.
        CHECK(page.mode() == mode && page.ByteSizeLong() <= 8 * 1024 * 1024);
        if (page.complete()) {
            CHECK(page.has_version() && page.version() == edition.version() && page.instance() == "star-test");
        } else {
            CHECK(!page.has_version() && page.instance().empty() && !page.changes().empty());
        }
        for (const auto& change : page.changes()) {
            CHECK(!records.contains(change.key()));
            if (change.action_case() == proto::comet::v1::AlmanacChange::kValue) {
                records.emplace(change.key(), change.value());
            } else {
                CHECK(mode == proto::comet::v1::MODE_APPLY && change.action_case() == proto::comet::v1::AlmanacChange::kErase);
                records.emplace(change.key(), std::nullopt);
            }
        }
        ++pages;
        CHECK(pages <= 1024);
    }
    CHECK(pages >= minimum);
    bool failed{}; // Repeated complete-frame construction cannot impersonate progress.
    try {
        static_cast<void>(edition.next("star-test"));
    } catch (const std::logic_error&) {
        failed = true;
    }
    CHECK(failed);
    return records;
}

/// Absent Scope, exact miss, and present empty values differ; empty baselines still complete.
void empty() {

    Edition absent;
    CHECK(consume(absent, proto::comet::v1::MODE_RESET).empty() && absent.version() == 0);
    Edition missing("key", Almanac::Point{5, {}});
    CHECK(consume(missing, proto::comet::v1::MODE_RESET).empty() && missing.version() == 5);
    Edition zero("key", Almanac::Point{6, std::make_shared<const Almanac::Buffer>()});
    CHECK(consume(zero, proto::comet::v1::MODE_RESET).at("key") == std::optional<std::string>(""));
    Edition caught(Almanac::Replay{9, {}});
    CHECK(consume(caught, proto::comet::v1::MODE_APPLY).empty() && caught.version() == 9);
}

/// Concurrent state changes cannot alter a frozen paged root/version; large records occupy one page.
void snapshots() {

    Almanac book;
    auto draft = book.prepare(1); // 601 rows span count/byte limits, with one valid 1 MiB row above the soft target.
    CHECK(draft.set("large", Almanac::Buffer(1024 * 1024, 7)));
    for (unsigned index = 0; index < 600; ++index) {
        CHECK(draft.set(std::to_string(index), {1}));
    }
    CHECK(book.reset(std::move(draft)));
    Edition edition(*book.view());
    const auto retained = edition.bytes(); // Frozen charge stays fixed despite later values/keys.
    CHECK(book.apply(2, "large", std::nullopt));
    CHECK(book.apply(3, "0", Almanac::Buffer{3}));
    CHECK(book.apply(4, "later", Almanac::Buffer{4}));
    const auto records = consume(edition, proto::comet::v1::MODE_RESET, 4);
    CHECK(records.size() == 601 && records.at("large")->size() == 1024 * 1024);
    CHECK(records.at("0") == std::optional<std::string>(std::string(1, '\1')));
    CHECK(!records.contains("later") && edition.version() == 1 && edition.bytes() == retained);
}

/// Repeated Set/Delete for one key emits only its final action in the frozen interval; later writes form another batch.
void changes() {

    Almanac book;
    CHECK(book.reset(book.prepare(0)));
    CHECK(book.apply(1, "first", Almanac::Buffer{1}));
    CHECK(book.apply(2, "second", Almanac::Buffer{2}));
    CHECK(book.apply(3, "first", std::nullopt));
    CHECK(book.apply(4, "second", Almanac::Buffer{}));
    Edition full(*book.replay(0));
    Edition exact(*book.replay(0), "second");
    Edition unrelated(*book.replay(0), "unknown");
    CHECK(book.apply(5, "first", Almanac::Buffer{5}));
    const auto output = consume(full, proto::comet::v1::MODE_APPLY);
    CHECK(output.size() == 2 && !output.at("first") && output.at("second") == std::optional<std::string>(""));
    const auto point = consume(exact, proto::comet::v1::MODE_APPLY);
    CHECK(point.size() == 1 && point.at("second") == std::optional<std::string>(""));
    CHECK(consume(unrelated, proto::comet::v1::MODE_APPLY).empty());
    CHECK(full.version() == 4 && exact.version() == 4 && unrelated.version() == 4);
}

/// Deliver a frozen multi-page history exactly once while later commits remain outside its version.
void history() {

    Almanac book;
    CHECK(book.reset(book.prepare(1)));
    for (unsigned index = 0; index < 600; ++index) {
        CHECK(book.apply(index + 2, std::to_string(1000 + index), Almanac::Buffer(1024, 7)));
    }
    Edition edition(*book.replay(1));
    CHECK(book.apply(602, "1000", std::nullopt));
    const auto records = consume(edition, proto::comet::v1::MODE_APPLY, 3);
    CHECK(records.size() == 600 && edition.version() == 601);
    const std::optional<std::string> expected = std::string(1024, '\7'); // Literal committed bytes, independent of page construction.
    for (unsigned index = 0; index < 600; ++index) {
        CHECK(records.at(std::to_string(1000 + index)) == expected);
    }
}

/// Split 257 small history items at the row limit while retaining their original bytes and version.
void dense() {

    Almanac book;
    CHECK(book.reset(book.prepare(0)));
    for (unsigned index = 0; index < 257; ++index) {
        CHECK(book.apply(index + 1, std::to_string(1000 + index), Almanac::Buffer{7}));
    }
    Edition edition(*book.replay(0));
    CHECK(book.apply(258, "1000", Almanac::Buffer{9}));
    CHECK(book.apply(259, "later", Almanac::Buffer{8}));
    unsigned offset{};
    for (const unsigned count : {256U, 1U}) {
        const auto page = edition.next("star-test");
        CHECK(page.mode() == proto::comet::v1::MODE_APPLY && page.changes_size() == static_cast<int>(count));
        CHECK(page.ByteSizeLong() < 256 * 1024 && page.complete() == (count == 1));
        CHECK(page.has_version() == page.complete());
        CHECK(page.complete() ? page.version() == 257 && page.instance() == "star-test" : page.instance().empty());
        for (const auto& change : page.changes()) {
            CHECK(change.key() == std::to_string(1000 + offset++));
            CHECK(change.has_value() && change.value() == std::string(1, '\7'));
        }
    }
    CHECK(offset == 257 && edition.complete() && edition.version() == 257);
    std::cout << "ASTRA-EDITION dense pages=2 rows=257 first=256 last=1\n";
}

/// Exercise the encoder's aggregate hard budget with a native replay beyond Almanac's legal key domain.
void budget() {

    constexpr std::size_t hard = 8 * 1024 * 1024;
    const auto key = std::make_shared<const std::string>(hard - 105, 'a'); // A fixed native boundary input, including the serving envelope's reserved bytes.
    const auto value = std::make_shared<const Almanac::Buffer>();
    for (const bool tail : {false, true}) {
        Almanac::Replay replay{2, {{key, value, 1}}};
        if (tail) {
            replay.changes.push_back({std::make_shared<const std::string>("z"), value, 2});
        }
        Edition edition(std::move(replay));
        const auto retained = edition.bytes();

        if (!tail) {
            const auto page = edition.next("star-test");
            CHECK(page.complete() && page.version() == 2 && page.instance() == "star-test" && page.ByteSizeLong() <= hard);
            CHECK(page.changes_size() == 1 && page.changes(0).key() == *key && page.changes(0).has_value() && page.changes(0).value().empty());
            CHECK(edition.complete() && edition.version() == 2 && edition.bytes() == retained);
            continue;
        }

        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            bool rejected{};
            try {
                static_cast<void>(edition.next("star-test"));
            } catch (const std::length_error& error) {
                CHECK(std::string_view(error.what()) == "Almanac record exceeds message budget");
                rejected = true;
            }
            CHECK(rejected && !edition.complete() && edition.version() == 2 && edition.bytes() == retained);
        }
    }
    std::cout << "ASTRA-EDITION budget accepted=1 rejected=2 preserved=2\n";
}

/// Reject invalid envelope/native point inputs without advancing or completing the frozen edition.
void rejection() {

    Edition good("key", Almanac::Point{7, std::make_shared<const Almanac::Buffer>(1, 1)});
    for (const auto& instance : {std::string{}, std::string(129, 'x')}) {
        bool rejected{};
        try {
            static_cast<void>(good.next(instance));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected && !good.complete() && good.version() == 7);
    }
    CHECK(consume(good, proto::comet::v1::MODE_RESET).at("key") == std::optional<std::string>(std::string(1, '\1')));

    constexpr std::size_t hard = 8 * 1024 * 1024; // The existing page contract includes encoded fields and completion metadata.
    constexpr std::array<std::size_t, 3> sizes{0, hard + 1, hard};
    for (unsigned damaged = 0; damaged < 3; ++damaged) {
        auto key = damaged == 0 ? std::string(hard + 1, 'k') : std::string("key");
        auto value = std::make_shared<const Almanac::Buffer>(sizes[damaged], 1); // Deliberately bypass Almanac's valid-input boundary to exercise encoder defenses.
        Edition edition(std::move(key), Almanac::Point{9, std::move(value)});
        const auto retained = edition.bytes();
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            bool rejected{};
            try {
                static_cast<void>(edition.next("star-test"));
            } catch (const std::length_error&) {
                rejected = true;
            }
            CHECK(rejected && !edition.complete() && edition.version() == 9 && edition.bytes() == retained);
        }
    }
}
} // namespace

int main() {
    try {
        empty();
        snapshots();
        changes();
        history();
        dense();
        budget();
        rejection();
        std::cout << "PASS frozen Almanac stream editions\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
