// Verify Linux/amd64 integer representations, complete-width epochs and exact format/capacity boundaries.
package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// TestNumeric keeps actual input/output witnesses; full-rule acceptance also requires independent loop and format evidence.
func TestNumeric(t *testing.T) {
	check := counter(t, "ADMISSION-NUMERIC")
	record := func(value any) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"kind": "numeric", "value": value})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("ADMISSION-NUMERIC " + string(data))
	}
	check(strconv.IntSize == 64, "numeric qualification requires the declared 64-bit target")
	check(reflect.TypeOf(orbit.Member{}.Epoch).Kind() == reflect.Uint64, "wire epoch lost its unsigned representation")
	check(reflect.TypeOf(time.Duration(0)).Kind() == reflect.Int64, "duration lost its signed nanosecond representation")
	record(map[string]any{"kind": "representation", "int": strconv.IntSize, "epoch": reflect.TypeOf(orbit.Member{}.Epoch).Bits(), "duration": reflect.TypeOf(time.Duration(0)).Bits()})
	identity := identity(t)
	for _, capacity := range []int{-1 << 63, -1, 0, 1, 16384, 16385, 1<<63 - 1} {
		value, err := NewDirectory(identity, "alpha", orbit.Role_ROLE_POLARIS, capacity)
		accepted := err == nil
		check(accepted == (capacity == 1 || capacity == 16384), "capacity boundary was truncated or wrapped")
		maximum := 0
		if accepted {
			maximum = value.maximum
			check(maximum == capacity && len(value.Members()) == 0, "accepted capacity changed representation or published members")
		} else {
			check(value == nil && errors.Is(err, ErrIdentity), "rejected capacity published resources or changed its error")
		}
		record(map[string]any{"kind": "capacity", "input": capacity, "accepted": accepted, "maximum": maximum})
	}
	epochs := []uint64{1, 2, 1<<31 - 1, 1 << 31, 1<<32 - 1, 1 << 32, 1<<63 - 1, 1 << 63, 1<<64 - 2, 1<<64 - 1}
	for _, install := range []bool{false, true} {
		for _, old := range epochs {
			for _, next := range epochs {
				value, err := NewDirectory(identity, "alpha", orbit.Role_ROLE_POLARIS, 1)
				if err != nil {
					t.Fatal(err)
				}
				initial := &orbit.Member{Galaxy: "alpha", Id: []byte(fmt.Sprintf("epoch-%d", old)), Principal: bytes.Repeat([]byte{1}, 32), Advertise: "127.0.0.1:7443", Epoch: old, Role: orbit.Role_ROLE_STAR, Group: "default"}
				candidate := proto.Clone(initial).(*orbit.Member)
				candidate.Id, candidate.Epoch = []byte(fmt.Sprintf("epoch-%d", next)), next
				check(value.Install([]*orbit.Member{initial}) == nil, "full-width baseline epoch was refused")
				if install {
					err = value.Install([]*orbit.Member{candidate})
				} else {
					reply := response(t, candidate)
					_, err = value.Verify(reply.Admission, reply.Signature, orbit.Role_ROLE_STAR)
				}
				check((err == nil) == (install || next >= old) && (err == nil || status.Code(err) == codes.Unauthenticated), "epoch comparison narrowed or changed its refusal")
				view := value.Members()
				check(len(view) == 1, "epoch transition changed directory capacity")
				want := initial
				if next > old {
					want = candidate
				}
				check(proto.Equal(view[0], want), "epoch transition changed a committed identity")
				current := value.Current(candidate)
				check(current == (next >= old), "current identity narrowed its epoch comparison")
				record(map[string]any{"kind": "epoch", "install": install, "old": old, "next": next, "accepted": err == nil, "epoch": view[0].Epoch, "current": current})
			}
		}
	}
	for _, length := range []int{1, 128, 129} {
		value := member(1, 1, orbit.Role_ROLE_STAR)
		value.Id = bytes.Repeat([]byte{'a'}, length)
		accepted := Valid(value)
		check(accepted == (length <= 128), "member ID byte limit changed")
		record(map[string]any{"kind": "id", "length": len(value.Id), "accepted": accepted})
	}
	for _, port := range []string{"0", "1", "65535", "65536"} {
		endpoint, err := Endpoint("127.0.0.1:" + port)
		check((err == nil) == (port == "1" || port == "65535"), "port range was truncated or wrapped")
		record(map[string]any{"kind": "port", "input": port, "accepted": err == nil, "value": endpoint.Port()})
	}
	for _, length := range []int{1024, 1025} {
		value := member(1, 1, orbit.Role_ROLE_STAR)
		raw, err := proto.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		// A well-formed unknown field pads a valid signed member without changing its public fields.
		padding := protowire.AppendTag(nil, 127, protowire.BytesType)
		padding = protowire.AppendBytes(padding, make([]byte, length-len(raw)-4))
		raw = append(raw, padding...)
		check(len(raw) == length, "signed-size fixture did not reach its declared boundary")
		decoded, err := identity.Verify(raw, sign(t, raw, "proto.orbit.v1.admission\x00"))
		check((err == nil) == (length == 1024), "signed payload byte limit changed")
		if err == nil {
			decoded.ProtoReflect().SetUnknown(nil)
			check(proto.Equal(decoded, value), "maximum signed payload altered known member fields")
		} else {
			check(decoded == nil && errors.Is(err, ErrIdentity), "oversized signed payload escaped with partial data")
		}
		record(map[string]any{"kind": "payload", "length": len(raw), "accepted": err == nil})
	}
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "login.json"} {
		for _, length := range []int{16384, 16385} {
			directory := material(t)
			path := filepath.Join(directory, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, bytes.Repeat([]byte{' '}, length-len(data))...)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			value, err := Load(directory, "127.0.0.1:7443")
			check((err == nil) == (length == 16384), "material byte limit changed")
			check((value != nil) == (err == nil), "material boundary published a partial identity")
			record(map[string]any{"kind": "material", "name": name, "length": len(data), "accepted": err == nil})
		}
	}
}
