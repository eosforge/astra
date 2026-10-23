// Serialize native state outside allocation injection; no reference transitions are shared.
#pragma once
#include <chrono>
#include <cstddef>
#include <iostream>
#include <map>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>

namespace astra::test::allocation {
/// Preserve every payload byte and distinguish a missing pointer from an empty value.
inline void bytes(std::ostream& output, const auto& value) {
    if (!value) {
        output << "null";
        return;
    }
    output << '[';
    for (std::size_t index = 0; index < value->size(); ++index) {
        output << (index ? "," : "") << static_cast<unsigned>((*value)[index]);
    }
    output << ']';
}

/// Encode keys losslessly; Ephemeris identities contain binary bytes rather than text.
void key(std::ostream& output, std::string_view value);

/// Copy only actual native fields, without reconstructing expected records or deadlines.
inline void record(std::ostream& output, const auto& row) {
    output << '[';
    if constexpr (requires { row.attr; }) {
        bytes(output, row.attr);
        output << ',';
        bytes(output, row.data);
        output << ',' << row.deadline.time_since_epoch().count() << ',' << row.update << ',' << row.renewal << ',' << row.ttl << ',' << row.generation;
    } else {
        output << row.version << ',';
        bytes(output, row.value);
        output << ',';
        if (row.deadline) {
            output << row.deadline->time_since_epoch().count();
        } else {
            output << "null";
        }
    }
    output << ']';
}

/// Canonicalize only key enumeration; retain the complete source position, count and records.
inline void source(std::ostream& output, const auto& root) {

    std::map<std::tuple<std::string, std::string, std::string>, std::string> rows;
    root.each([&rows](const auto& scope, const auto& name, const auto& row) {
        std::ostringstream value;
        record(value, row);
        rows.emplace(std::tuple{scope.sector, scope.spectrum, name}, value.str());
    });
    output << '[' << root.position() << ',' << root.size() << ",[";
    bool separator{};
    for (const auto& [address, row] : rows) {
        const auto& [sector, spectrum, name] = address;
        output << (separator ? "," : "") << "[\"" << sector << "\",\"" << spectrum << "\",";
        key(output, name);
        output << ',' << row << ']';
        separator = true;
    }
    output << "]]";
}

/// Observe immutable public roots, including every byte and the independent content cursor.
inline void view(std::ostream& output, const auto& root) {

    std::map<std::string, std::string> rows;
    root.each([&rows](const auto& name, const auto& row) {
        std::ostringstream value;
        value << '[';
        if constexpr (requires { row.attr; }) {
            bytes(value, row.attr);
            value << ',';
            bytes(value, row.data);
        } else {
            value << row.version << ',';
            bytes(value, row.value);
        }
        value << ']';
        rows.emplace(name, value.str());
    });
    output << '[' << root.version() << ',' << root.size() << ",[";
    bool separator{};
    for (const auto& [name, row] : rows) {
        output << (separator ? "," : "") << '[';
        key(output, name);
        output << ',' << row << ']';
        separator = true;
    }
    output << "]]";
}

/// Preserve actual source event order and distinguish complete records, renewals and endings.
inline const char* form(auto value) {
    using Form = decltype(value);
    switch (value) {
    case Form::Record:
        return "record";
    case Form::Data:
        return "data";
    case Form::Renew:
        return "renew";
    case Form::Erase:
        return "erase";
    }
    throw std::logic_error("Unknown allocation-trace source form");
}

/// Exporting source/history does not advance expiry or read current projection state implicitly.
inline std::string current(auto& state) {

    std::ostringstream output;
    output << '[';
    source(output, state.source());
    output << ",[";
    const auto events = state.events(0);
    if (!events) {
        throw std::runtime_error("Allocation trace lacks complete source history");
    }
    bool separator{};
    for (const auto& event : *events) {
        output << (separator ? "," : "") << '[' << event.position << ",\"" << form(event.form) << "\",\"" << event.name->scope->sector << "\",\"" << event.name->scope->spectrum << "\",";
        key(output, event.name->key);
        output << ',';
        if (event.record) {
            record(output, *event.record);
        } else {
            output << "null";
        }
        output << ']';
        separator = true;
    }
    output << "]]";
    return output.str();
}

/// Read public scopes only after their prescribed healthy recovery or completed operation.
inline void complete(std::ostream& output, auto& state, const auto& initial, const auto& target) {

    const auto first = state.capture(initial);
    const auto second = state.capture(target);
    if (!first || !second) {
        throw std::runtime_error("Allocation trace cannot capture recovered projections");
    }
    output << '[' << current(state) << ',';
    view(output, *first);
    output << ',';
    view(output, *second);
    output << ']';
}
} // namespace astra::test::allocation
