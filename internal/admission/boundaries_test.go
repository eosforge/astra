// Verify constructor capacity, signed-directory rejection and identity input rules independently.
package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/orbit"
)

// TestDirectoryConstruction covers construction and rejected verified peers without partial publication.
func TestDirectoryConstruction(t *testing.T) {
	check := counter(t, "ADMISSION-DIRECTORY-BOUNDARIES")
	identity := identity(t)
	for _, role := range []orbit.Role{orbit.Role_ROLE_STAR, orbit.Role_ROLE_POLARIS, orbit.Role_ROLE_ASTROLABE} {
		for _, maximum := range []int{1, 16384} {
			value, err := NewDirectory(identity, "alpha", role, maximum)
			check(err == nil && value != nil && value.maximum == maximum && value.role == role, "valid directory construction changed its limits or role")
			check(!value.Current(nil) && len(value.Members()) == 0, "empty directory published a current identity")
		}
	}
	for scenario := range 6 {
		local, galaxy, role, maximum := identity, "alpha", orbit.Role_ROLE_STAR, 1
		switch scenario {
		case 0:
			local = nil
		case 1:
			galaxy = ""
		case 2:
			role = orbit.Role_ROLE_PLANET
		case 3:
			role = orbit.Role(99)
		case 4:
			maximum = 0
		case 5:
			maximum = 16385
		}
		value, err := NewDirectory(local, galaxy, role, maximum)
		check(value == nil && errors.Is(err, ErrIdentity), "invalid directory construction published resources")
	}
	local := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: orbit.Role_ROLE_STAR, Group: "default"}
	other := proto.Clone(local).(*orbit.Member)
	other.Id, other.Advertise = []byte("other"), "127.0.0.1:7555"
	other.Principal = identity.Principal("alpha", other.Advertise)
	for _, maximum := range []int{1, 2} {
		value, err := NewDirectory(identity, "alpha", orbit.Role_ROLE_STAR, maximum)
		if err != nil {
			t.Fatal(err)
		}
		reply := response(t, local)
		member, err := value.Verify(reply.Admission, reply.Signature, orbit.Role_ROLE_STAR)
		check(err == nil && proto.Equal(member, local) && value.Current(local), "valid signed peer was not published")
		candidate := proto.Clone(other).(*orbit.Member)
		want := codes.ResourceExhausted
		if maximum == 2 {
			candidate.Advertise = local.Advertise
			want = codes.Unauthenticated
		}
		reply = response(t, candidate)
		member, err = value.Verify(reply.Admission, reply.Signature, orbit.Role_ROLE_STAR)
		check(member == nil && status.Code(err) == want, "capacity or verified endpoint alias returned the wrong refusal")
		check(len(value.Members()) == 1 && value.Current(local) && !value.Current(candidate), "rejected verified peer changed the committed directory")
		ctx := context.Background()
		member, err = value.Authorize(ctx, orbit.Role_ROLE_STAR)
		check(member == nil && status.Code(err) == codes.Unauthenticated && value.Current(local), "missing metadata changed or authenticated a directory")
	}
}

// TestDirectoryConflicts rejects independent identity and alias conflicts twice before recovering the same directory.
func TestDirectoryConflicts(t *testing.T) {
	check := counter(t, "ADMISSION-CONFLICTS")
	for _, install := range []bool{false, true} {
		for scenario := range 9 {
			if !install && scenario >= 6 {
				continue
			}
			maximum := 4
			if scenario == 8 {
				maximum = 2
			}
			value := directory(t, orbit.Role_ROLE_POLARIS, maximum)
			apply := func(candidate *orbit.Member) error {
				if install {
					return value.Install([]*orbit.Member{candidate})
				}
				return value.observe(candidate)
			}
			old, fresh := member(1, 1, orbit.Role_ROLE_STAR), member(1, 2, orbit.Role_ROLE_STAR)
			check(value.Install([]*orbit.Member{old}) == nil, "conflict baseline was rejected")
			before := value.Members()
			if scenario == 3 {
				err := apply(proto.Clone(old).(*orbit.Member))
				check(err == nil, "identical identity was rejected before an epoch-only conflict")
				check(slices.EqualFunc(before, value.Members(), func(a, b *orbit.Member) bool { return proto.Equal(a, b) }), "identical identity changed committed members")
			}
			candidate := proto.Clone(fresh).(*orbit.Member)
			var incoming []*orbit.Member
			switch scenario {
			case 0:
				candidate = proto.Clone(old).(*orbit.Member)
				candidate.Group = "other"
			case 1:
				candidate.Role = orbit.Role_ROLE_POLARIS
			case 2:
				candidate.Advertise = "127.0.0.1:7999"
			case 3:
				candidate.Id = bytes.Clone(old.Id)
			case 4:
				candidate = member(2, 1, orbit.Role_ROLE_STAR)
				candidate.Id = bytes.Clone(old.Id)
			case 5:
				candidate = member(2, 1, orbit.Role_ROLE_STAR)
				candidate.Advertise = old.Advertise
			case 6, 7, 8:
				incoming = []*orbit.Member{member(2, 1, orbit.Role_ROLE_STAR), member(3, 1, orbit.Role_ROLE_STAR)}
				if scenario == 6 {
					incoming[1].Principal = bytes.Clone(incoming[0].Principal)
				} else {
					incoming[1].Advertise = incoming[0].Advertise
				}
			}
			if incoming == nil {
				incoming = []*orbit.Member{candidate}
			}
			for range 2 {
				var err error
				if install {
					err = value.Install(incoming)
				} else {
					err = value.observe(candidate)
				}
				check(errors.Is(err, ErrIdentity), "identity or alias conflict was accepted")
				check(slices.EqualFunc(before, value.Members(), func(a, b *orbit.Member) bool { return proto.Equal(a, b) }), "rejected conflict changed committed members")
			}
			if scenario == 3 {
				// Changing only Epoch must reject ID reuse without poisoning an identical retry.
				err := apply(proto.Clone(old).(*orbit.Member))
				check(err == nil, "epoch-only conflict poisoned an identical retry")
				check(slices.EqualFunc(before, value.Members(), func(a, b *orbit.Member) bool { return proto.Equal(a, b) }), "identical retry changed committed members")
			}
			err := apply(fresh)
			check(err == nil, "conflict poisoned subsequent valid replacement")
			check(len(value.Members()) == 1 && proto.Equal(value.Members()[0], fresh), "recovery did not publish the exact replacement")
			if scenario == 3 {
				err = apply(proto.Clone(fresh).(*orbit.Member))
				check(err == nil, "recovered identity was not repeatable")
				check(len(value.Members()) == 1 && proto.Equal(value.Members()[0], fresh), "recovered identity retry changed committed members")
			}
		}
	}
}

// TestAdmissionCredentials verifies signed boundary failures and exact metadata cardinality without partial publication.
func TestAdmissionCredentials(t *testing.T) {
	check := counter(t, "ADMISSION-CREDENTIALS")
	for scenario := range 8 {
		value := directory(t, orbit.Role_ROLE_POLARIS, 4)
		old, fresh := member(1, 1, orbit.Role_ROLE_STAR), member(1, 2, orbit.Role_ROLE_STAR)
		initial := response(t, old)
		got, err := value.Verify(initial.Admission, initial.Signature, orbit.Role_ROLE_STAR)
		check(err == nil && proto.Equal(got, old), "signed baseline was rejected")
		before := value.Members()
		candidate := proto.Clone(fresh).(*orbit.Member)
		if scenario == 1 {
			candidate.Galaxy = "beta"
		} else if scenario == 2 {
			candidate.Role = orbit.Role_ROLE_ASTROLABE
		} else if scenario == 7 {
			candidate = member(2, 1, orbit.Role_ROLE_ASTROLABE)
		}
		reply := response(t, candidate)
		if scenario == 0 {
			reply.Signature[0] ^= 1
		}
		values := metadata.Pairs("astra-admission-bin", string(reply.Admission), "astra-signature-bin", string(reply.Signature))
		switch scenario {
		case 3:
			values.Delete("astra-signature-bin")
		case 4:
			values.Append("astra-signature-bin", string(reply.Signature))
		case 5:
			values.Delete("astra-admission-bin")
		case 6:
			values.Append("astra-admission-bin", string(reply.Admission))
		}
		ctx := metadata.NewIncomingContext(context.Background(), values)
		for range 2 {
			got, err = value.Authorize(ctx, orbit.Role_ROLE_STAR)
			check(got == nil && status.Code(err) == codes.Unauthenticated, "invalid signature, galaxy, role or metadata cardinality was authorized")
			check(slices.EqualFunc(before, value.Members(), func(a, b *orbit.Member) bool { return proto.Equal(a, b) }), "rejected credentials modified directory state")
		}
		recovery := response(t, fresh)
		got, err = value.Verify(recovery.Admission, recovery.Signature, orbit.Role_ROLE_STAR)
		check(err == nil && proto.Equal(got, fresh), "credential refusal poisoned a valid replacement")
		check(len(value.Members()) == 1 && proto.Equal(value.Members()[0], fresh), "credential recovery committed a partial identity")
	}
}

// TestIdentityRules anchors names to an explicit alphabet and checks login, TLS copies and signed format boundaries.
func TestIdentityRules(t *testing.T) {
	check := counter(t, "ADMISSION-IDENTITY-RULES")
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	for value := range 256 {
		input := string([]byte{byte(value)})
		check(Name(input) == strings.ContainsRune(alphabet, rune(value)), "single-byte name differs from the independent alphabet")
	}
	for _, item := range []struct {
		value string
		valid bool
	}{{"", false}, {"a", true}, {strings.Repeat("a", 64), true}, {strings.Repeat("a", 65), false}, {"カ", false}} {
		check(Name(item.value) == item.valid, "name length or character boundary changed")
	}
	for _, data := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte("{"), {0xff},
		[]byte(`{"username":"node","password":17}`),
		[]byte(`{"username":"node","username":"other","password":"x"}`),
		[]byte(`{"username":"node","alias":"x"}`),
		[]byte(`{"username":"node","password":"x","extra":"x"}`),
		[]byte(`{"username":"node","password":""}`),
		[]byte(`{"username":"bad/name","password":"x"}`),
		[]byte(`{"username":"` + strings.Repeat("a", 65) + `","password":"x"}`),
		[]byte(`{"username":"node","password":"` + strings.Repeat("p", 1025) + `"}`),
		[]byte(`{"username":"node","password":"x"`),
		[]byte(`{"username":"node","password":"x"} {}`),
		[]byte(`{"username":"node","password":"x"} null`),
		[]byte(`{42:"value"}`), []byte(`{"username":"node","password":"x"]`),
	} {
		check(errors.Is(new(Identity).login(data), ErrIdentity), "invalid login was accepted")
	}
	for _, data := range []string{`{"username":"node","password":"x"}`, `{"password":"` + strings.Repeat("p", 1024) + `","username":"node"}`} {
		value := new(Identity)
		check(value.login([]byte(data)) == nil && value.Username() == "node", "valid login or maximum password length was rejected")
	}
	identity := identity(t)
	client, server := identity.Client(), identity.Server()
	client.MinVersion, client.ServerName = tls.VersionTLS12, "changed.invalid"
	server.MaxVersion = tls.VersionTLS12
	check(identity.Client().MinVersion == tls.VersionTLS13 && identity.Client().ServerName == "" && identity.Server().MaxVersion == tls.VersionTLS13, "returned TLS configuration aliased scalar options")
	local := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: orbit.Role_ROLE_STAR, Group: "default"}
	for scenario := range 11 {
		member := proto.Clone(local).(*orbit.Member)
		switch scenario {
		case 0:
			member.Galaxy = ""
		case 1:
			member.Group = "bad/name"
		case 2:
			member.Id = nil
		case 3:
			member.Id = bytes.Repeat([]byte("i"), 129)
		case 4:
			member.Id = []byte{0xff}
		case 5:
			member.Epoch = 0
		case 6:
			member.Role = orbit.Role(99)
		case 7:
			member.Principal = nil
		case 8:
			member.Principal = make([]byte, 31)
		case 9:
			member.Advertise = "localhost:7443"
		case 10:
			member.Group = ""
		}
		check(!Valid(member), "invalid structural member became valid")
		reply := response(t, member)
		decoded, err := identity.Verify(reply.Admission, reply.Signature)
		check(decoded == nil && errors.Is(err, ErrIdentity), "valid signature bypassed member format")
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte("x"), 1025)} {
		member, err := identity.Verify(data, sign(t, data, "proto.orbit.v1.admission\x00"))
		check(member == nil && errors.Is(err, ErrIdentity), "signed admission size boundary was bypassed")
	}
}
