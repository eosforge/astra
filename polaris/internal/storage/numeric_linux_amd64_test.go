//go:build linux && amd64 && cgo

// Exercise full-width authority versions, integer quotas and encoded length guards with native SQLite and literal expectations.
package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestNumeric emits actual values; an independent receiver supplies the complete expected vector sequence and range assumptions.
func TestNumeric(t *testing.T) {
	check := verification(t, "STORAGE-NUMERIC")
	record := func(value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("STORAGE-NUMERIC " + string(data))
	}
	check(runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && strconv.IntSize == 64 && reflect.TypeOf(Version(0)).Kind() == reflect.Uint64 && reflect.TypeOf(time.Duration(0)).Kind() == reflect.Int64 && reflect.TypeOf(Change{}).Size() == 56, "storage representations must match the declared 64-bit target")
	record(map[string]any{"kind": "representation", "int": strconv.IntSize, "version": reflect.TypeOf(Version(0)).Bits(), "duration": reflect.TypeOf(time.Duration(0)).Bits(), "change_bytes": reflect.TypeOf(Change{}).Size()})
	dependencies := map[string]string{}
	for _, name := range []string{"runtime/malloc.go", "internal/goarch/goarch.go", "internal/goarch/zgoarch_amd64.go", "internal/goos/goos.go", "internal/goos/zgoos_linux.go"} {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", name))
		check(err == nil, "allocator range assumptions must retain actual existing Go toolchain source")
		digest := sha256.Sum256(data)
		dependencies[name] = hex.EncodeToString(digest[:])
	}
	check(runtime.Version() == "go1.27.2", "numerical assumptions require the pinned Go runtime")
	record(map[string]any{"kind": "runtime", "version": runtime.Version(), "files": dependencies})
	defaults := Default()
	record(map[string]any{"kind": "defaults", "value": defaults})
	check(defaults.valid(), "default limits must remain valid")
	for _, field := range []struct {
		name             string
		minimum, maximum int64
		set              func(*Limits, int64)
	}{
		{"scopes", 1, 16384, func(limits *Limits, value int64) { limits.Scopes = value }},
		{"records", 1, 1 << 20, func(limits *Limits, value int64) { limits.Records = value }},
		{"bytes", 1, 1 << 30, func(limits *Limits, value int64) { limits.Bytes, limits.Total = value, 4<<30 }},
		{"total", 1, 4 << 30, func(limits *Limits, value int64) { limits.Bytes, limits.Total = 1, value }},
		{"history", 0, 65536, func(limits *Limits, value int64) { limits.History = value }},
		{"backlog", 0, 64 << 20, func(limits *Limits, value int64) { limits.Backlog = value }},
		{"timeout", 1, 30_000_000_000, func(limits *Limits, value int64) { limits.Timeout = time.Duration(value) }},
		{"wal", 1 << 20, 4 << 30, func(limits *Limits, value int64) { limits.WAL = value }},
	} {
		for index, value := range []int64{math.MinInt64, -1, 0, field.minimum - 1, field.minimum, field.maximum, field.maximum + 1, math.MaxInt64} {
			limits := Default()
			field.set(&limits, value)
			accepted := limits.valid()
			check(accepted == (value >= field.minimum && value <= field.maximum), "integer limit changed its exact inclusive range")
			record(map[string]any{"kind": "limit", "field": field.name, "index": index, "input": value, "accepted": accepted})
		}
	}
	for _, pair := range [][2]int64{{1, 1}, {1, 2}, {2, 1}, {1 << 30, 1 << 30}, {1 << 30, (1 << 30) - 1}} {
		limits := Default()
		limits.Bytes, limits.Total = pair[0], pair[1]
		accepted := limits.valid()
		check(accepted == (pair[1] >= pair[0]), "global byte limit must cover the complete per-scope allowance")
		record(map[string]any{"kind": "total", "bytes": pair[0], "total": pair[1], "accepted": accepted})
	}

	// Literal BLOB vectors cross both signed boundaries; SQLite must sort their actual stored bytes as unsigned versions.
	store, _, _ := fixture(t, Default()) // Public opening registers the private SQLite driver before the auxiliary numeric connection.
	versions := []struct {
		value uint64
		hex   string
	}{
		{0, "0000000000000000"}, {1, "0000000000000001"}, {2, "0000000000000002"},
		{1<<31 - 1, "000000007fffffff"}, {1 << 31, "0000000080000000"}, {1<<32 - 1, "00000000ffffffff"},
		{1 << 32, "0000000100000000"}, {1<<63 - 1, "7fffffffffffffff"}, {1 << 63, "8000000000000000"},
		{1<<64 - 2, "fffffffffffffffe"}, {1<<64 - 1, "ffffffffffffffff"},
	}
	path := filepath.Join(t.TempDir(), "numbers.db")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	orm, connection, err := database(t.Context(), path, true)
	check(err == nil && orm != nil && connection != nil, "native SQLite numeric boundary must open")
	t.Cleanup(func() { check(connection.Close() == nil, "native numeric connection must close") })
	check(orm.Exec("CREATE TABLE numbers (version BLOB PRIMARY KEY CHECK(length(version)=8)) STRICT, WITHOUT ROWID").Error == nil, "numeric BLOB schema must be real SQLite")
	for index := len(versions) - 1; index >= 0; index-- {
		vector := versions[index]
		wanted, err := hex.DecodeString(vector.hex)
		check(err == nil && len(wanted) == 8, "literal version fixture must be eight bytes")
		value, err := Version(vector.value).Value()
		check(err == nil && bytes.Equal(value.([]byte), wanted), "version encoding narrowed or changed its byte order")
		decoded := Version(19)
		check(decoded.Scan(wanted) == nil && uint64(decoded) == vector.value, "full-width version must survive a native scan")
		check(orm.Exec("INSERT INTO numbers(version) VALUES(?)", Version(vector.value)).Error == nil, "native unsigned version insert must succeed")
		record(map[string]any{"kind": "codec", "input": vector.value, "hex": hex.EncodeToString(value.([]byte)), "decoded": uint64(decoded)})
	}
	rows, err := connection.QueryContext(t.Context(), "SELECT version,typeof(version),length(version) FROM numbers ORDER BY version")
	check(err == nil, "native unsigned ordering query must open")
	index := 0
	for rows.Next() {
		var version Version
		var kind string
		var length int64
		check(rows.Scan(&version, &kind, &length) == nil && index < len(versions), "native unsigned row must scan completely")
		check(uint64(version) == versions[index].value && kind == "blob" && length == 8, "SQLite reordered, coerced or narrowed an unsigned version")
		record(map[string]any{"kind": "ordered", "index": index, "version": uint64(version), "type": kind, "bytes": length})
		index++
	}
	check(rows.Err() == nil && rows.Close() == nil && index == len(versions), "complete native BLOB order must finish without a partial suffix")
	for index, input := range []any{nil, int64(1), uint64(math.MaxUint64), float64(1), "00000000", []byte{}, make([]byte, 7), make([]byte, 9)} {
		version := Version(math.MaxUint64)
		err := version.Scan(input)
		check(errors.Is(err, ErrCorrupt) && version == Version(math.MaxUint64), "bad SQLite dynamic types must preserve the caller's full-width version")
		record(map[string]any{"kind": "scan-rejection", "index": index, "retained": uint64(version), "corrupt": errors.Is(err, ErrCorrupt)})
	}

	// One immutable literal header is valid; forged counts and lengths must be rejected before narrowing or allocation.
	for _, count := range []uint64{0, 1, 2, 1 << 31, 1 << 32, (1 << 32) + 1, 1 << 63, math.MaxUint64} {
		data := binary.BigEndian.AppendUint64([]byte("AB02"), count)
		data = append(data, 0, 1, 0, 0, 0, 0, 0, 'k')
		entries, err := (Change{Version: 7, Value: data}).Entries()
		accepted := err == nil
		check(accepted == (count == 1) && (accepted || entries == nil && errors.Is(err, ErrInput)), "forged batch cardinality must not wrap or return a prefix")
		if accepted {
			check(len(entries) == 1 && entries[0].Version == 7 && entries[0].Key == "k" && !entries[0].Erase && len(entries[0].Value) == 0, "healthy literal batch must preserve its complete entry")
		}
		record(map[string]any{"kind": "batch-count", "input": count, "accepted": accepted, "entries": len(entries)})
	}
	for _, length := range []uint32{0, 1, 1 << 20, 1 << 31, math.MaxUint32} {
		data := binary.BigEndian.AppendUint64([]byte("AB02"), 1)
		data = binary.BigEndian.AppendUint16(data, 1)
		data = binary.BigEndian.AppendUint32(data, length)
		data = append(data, 0, 'k')
		entries, err := (Change{Version: 7, Value: data}).Entries()
		accepted := err == nil
		check(accepted == (length == 0) && (accepted || entries == nil && errors.Is(err, ErrInput)), "encoded unsigned length must be checked against actual bytes before int conversion")
		record(map[string]any{"kind": "batch-length", "input": length, "accepted": accepted, "entries": len(entries)})
	}

	// Public subscription admission accounts configured budgets, not physical allocations proportional to their maximums.
	for _, limit := range []int64{math.MinInt64, -1, 0, 1, 16 << 20, (16 << 20) + 1, math.MaxInt64} {
		for _, items := range []int{math.MinInt64, -1, 0, 1, 65536, 65537, math.MaxInt64} {
			feed, err := store.Subscribe(limit, items)
			accepted := err == nil
			check(accepted == (limit >= 1 && limit <= 16<<20 && items >= 1 && items <= 65536), "subscription capacity conversion changed its exact ranges")
			budget := store.feedBytes
			if accepted {
				check(feed != nil && budget == limit && feed.limit == limit && feed.items == items, "accepted subscription changed quota or leaked an old reservation")
				feed.Close()
			} else {
				check(feed == nil && errors.Is(err, ErrInput) && budget == 0, "invalid subscription must not allocate or reserve capacity")
			}
			check(store.feedBytes == 0 && len(store.feeds) == 0, "every subscription vector must release its complete reservation")
			record(map[string]any{"kind": "subscription", "limit": limit, "items": items, "accepted": accepted, "reserved": budget})
		}
	}
	feeds := make([]*Feed, 0, 8)
	for index := 1; index <= 8; index++ {
		feed, err := store.Subscribe(16<<20, 1)
		check(err == nil && store.feedBytes == int64(index)*(16<<20), "aggregate feed budget must count each admitted maximum exactly once")
		feeds = append(feeds, feed)
		record(map[string]any{"kind": "budget", "count": index, "bytes": store.feedBytes})
	}
	feed, err := store.Subscribe(1, 1)
	check(feed == nil && errors.Is(err, ErrCapacity) && store.feedBytes == 128<<20, "one byte beyond aggregate admission must refuse without wrapping or leaking")
	for _, feed := range feeds {
		feed.Close()
	}
	check(store.feedBytes == 0 && len(store.feeds) == 0, "aggregate reservations must return to exact zero")
	for _, limit := range []int64{130, 131, 262} {
		for _, items := range []int{1, 2} {
			feed, err := store.Subscribe(limit, items)
			check(err == nil, "bounded byte-accounting fixture must admit")
			capacity := min(items, int(limit/131))
			for step := 1; step <= 3; step++ {
				store.notify.Lock()
				feed.push(&Event{Scope: Scope{"n", "x"}, Change: Change{Version: 1, Key: "k"}})
				store.notify.Unlock()
				queued, charged := 0, int64(0)
				if step <= capacity {
					queued, charged = step, int64(step*131)
				}
				check(len(feed.queue) == queued && feed.bytes == charged && (feed.err == nil) == (step <= capacity), "feed boundary must preserve exact cost or poison and release the complete queue")
				check(step <= capacity || errors.Is(feed.err, ErrCapacity), "overload must retain its stable numeric refusal")
				record(map[string]any{"kind": "feed-cost", "limit": limit, "items": items, "step": step, "bytes": feed.bytes, "queued": len(feed.queue), "refused": errors.Is(feed.err, ErrCapacity)})
			}
			feed.Close()
		}
	}

	// Reach high but internally consistent persisted versions without pretending to run billions of commits.
	for _, target := range []uint64{1<<31 - 1, 1 << 31, 1<<32 - 1, 1 << 32, 1<<63 - 1, 1 << 63, math.MaxUint64} {
		store, path, binding := fixture(t, Default())
		scope := Scope{"numeric", fmt.Sprint(target)}
		version, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "absent", Erase: true})
		check(err == nil && version == 1, "high-version fixture must start with a real durable authority scope")
		check(store.write.Exec("DELETE FROM history").Error == nil, "high-version fixture must explicitly retire its unavailable old receipts")
		check(store.write.Exec("UPDATE scopes SET version=?,retained=0,backlog=0", Version(target-1)).Error == nil, "high-version fixture must seed an internally consistent persisted predecessor")
		version, err = store.Commit(t.Context(), scope, Change{Version: Version(target), Key: "k", Value: []byte("v")})
		check(err == nil && uint64(version) == target, "high-version successor must preserve its full-width receipt")
		replay, err := store.Since(t.Context(), scope, Version(target-1))
		check(err == nil && uint64(replay.Version) == target && len(replay.Changes) == 1 && uint64(replay.Changes[0].Version) == target && replay.Changes[0].Key == "k" && bytes.Equal(replay.Changes[0].Value, []byte("v")), "high-version retained history must be complete and exact")
		version, err = store.Commit(t.Context(), scope, Change{Version: Version(target), Key: "k", Value: []byte("v")})
		check(err == nil && uint64(version) == target, "high-version identical retry must not increment or narrow")
		version, err = store.Commit(t.Context(), scope, Change{Version: 0, Key: "k"})
		check(version == 0 && errors.Is(err, ErrInput), "wrapped zero must not become a valid authority version")
		check(store.Close() == nil, "full-width authority fixture must close before reopening")
		reopened, err := Open(t.Context(), path, binding, Default(), false)
		check(err == nil && reopened != nil, "full-width authority state must survive actual reopen validation")
		snapshot, err := reopened.Load(t.Context(), scope)
		check(err == nil && uint64(snapshot.Version) == target && len(snapshot.Records) == 1 && snapshot.Records[0].Key == "k" && bytes.Equal(snapshot.Records[0].Value, []byte("v")), "reopened full-width snapshot must contain the complete durable result")
		check(reopened.Close() == nil, "reopened numeric connection must drain")
		record(map[string]any{"kind": "authority-version", "target": target, "version": uint64(snapshot.Version), "records": len(snapshot.Records), "key": snapshot.Records[0].Key, "value": string(snapshot.Records[0].Value)})
	}

	// A batch cardinality above 128 remains representable; the numerical check must not impose an artificial transaction cap.
	data := binary.BigEndian.AppendUint64([]byte("AB02"), 129)
	for index := range 129 {
		key := fmt.Sprintf("k%03d", index)
		data = binary.BigEndian.AppendUint16(data, uint16(len(key)))
		data = binary.BigEndian.AppendUint32(data, 0)
		data = append(data, 0)
		data = append(data, key...)
	}
	entries, err := (Change{Version: 17, Value: data}).Entries()
	check(err == nil && len(entries) == 129 && entries[0].Key == "k000" && entries[128].Key == "k128" && entries[128].Version == 17, "batch cardinality must retain all entries beyond the unrelated 128 threshold")
	record(map[string]any{"kind": "batch-wide", "entries": len(entries), "last": entries[128].Key, "version": uint64(entries[128].Version)})
}
