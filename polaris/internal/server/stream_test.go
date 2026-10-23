//go:build linux && cgo

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/astra"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// issuer signs public test material on isolated ports; production Pulsar persistence has separate tests.
type issuer struct {
	orbit.UnimplementedAdmissionServer
	identity *admission.Identity
	key      ed25519.PrivateKey
}

// sign uses the production domain so transport/role cases share the same admission encoding.
func (issuer *issuer) sign(member *orbit.Member) *astra.Hello {
	data, err := proto.Marshal(member)
	if err != nil {
		panic(err)
	}
	return &astra.Hello{ProtocolMajor: 1, MaxFrameBytes: 8 << 20, Admission: data, AdmissionSignature: ed25519.Sign(issuer.key, append([]byte("proto.orbit.v1.admission\x00"), data...))}
}

// Register returns the test node's actual deployment binding; receivers still verify TLS and admission signatures.
func (issuer *issuer) Register(_ context.Context, request *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
	member := &orbit.Member{Galaxy: request.Galaxy, Id: []byte("polaris"), Principal: issuer.identity.Principal(request.Galaxy, request.Advertise), Epoch: 1, Advertise: request.Advertise, Role: request.Role, Group: request.Group}
	hello := issuer.sign(member)
	return &orbit.RegistrationResponse{Members: []*orbit.Member{member}, Admission: hello.Admission, Signature: hello.AdmissionSignature}, nil
}

// system owns each case's TLS/gRPC resources, ports, and background-task cleanup.
type system struct {
	store   *storage.Store
	issuer  *issuer
	node    *admission.Node
	streams *Streams
	channel *grpc.ClientConn
	star    *astra.Hello
	manager *astra.Hello
}

// environment uses public identities and a separate SQLite file, completing actual admission before return without system changes.
func environment(t *testing.T, limits storage.Limits) *system {
	t.Helper()
	root := filepath.Join("..", "..", "..", "tests", "fixtures")
	identity, err := admission.Load(filepath.Join(root, "star-a"), "127.0.0.1:7443")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "pulsar", "admission.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("missing public fixture")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &issuer{identity: identity, key: key.(ed25519.PrivateKey)}
	listening, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pulsar := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())))
	orbit.RegisterAdmissionServer(pulsar, issuer)
	go func() { _ = pulsar.Serve(listening) }()
	t.Cleanup(func() { pulsar.Stop(); _ = listening.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	node, err := admission.Open(identity, listening.Addr().String(), "alpha", listener.Addr().String(), "default", orbit.Role_ROLE_POLARIS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := node.Register(ctx); err != nil {
		t.Fatal(err)
	}
	store := fixture(t, limits)
	authority, err := NewAuthority(store, node.Directory(), 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	streams := NewStreams(node, authority)
	rpc := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())), grpc.MaxSendMsgSize(8<<20), grpc.MaxRecvMsgSize(8<<20))
	polaris.RegisterAuthorityServer(rpc, authority)
	polaris.RegisterAlmanacServer(rpc, streams)
	go func() { _ = rpc.Serve(listener) }()
	t.Cleanup(func() { rpc.Stop(); streams.Wait() })
	channel, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(identity.Client())), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = channel.Close() })
	member := &orbit.Member{Galaxy: "alpha", Id: []byte("star"), Principal: identity.Principal("alpha", "127.0.0.1:7447"), Epoch: 1, Advertise: "127.0.0.1:7447", Role: orbit.Role_ROLE_STAR, Group: "default"}
	star := issuer.sign(member)
	member.Id, member.Advertise, member.Principal, member.Role = []byte("manager"), "127.0.0.1:7448", identity.Principal("alpha", "127.0.0.1:7448"), orbit.Role_ROLE_ASTROLABE
	return &system{store: store, issuer: issuer, node: node, streams: streams, channel: channel, star: star, manager: issuer.sign(member)}
}

// connect sends a complete position inventory and reads peer Hello; cases check later installation boundaries.
func (system *system) connect(t *testing.T, inventory *polaris.Inventory) grpc.BidiStreamingClient[polaris.Packet, polaris.Packet] {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := polaris.NewAlmanacClient(system.channel).Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: inventory}}); err != nil {
		t.Fatal(err)
	}
	packet, err := stream.Recv()
	if err != nil || packet.GetHello() == nil {
		t.Fatal("missing signed Polaris Hello", err)
	}
	return stream
}

// TestStreamSnapshotSuffix advances/trims durable history during initial paging and checks a continuous suffix rather than repeated full snapshots.
func TestStreamSnapshotSuffix(t *testing.T) {
	t.Parallel()
	limits := storage.Default()
	limits.History = 1
	system := environment(t, limits)
	scope := storage.Scope{Sector: "routes", Spectrum: "main"}
	for version := storage.Version(1); version <= 40; version++ {
		if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: version, Key: fmt.Sprint(version), Value: make([]byte, 16384)}); err != nil {
			t.Fatal(err)
		}
	}
	stream := system.connect(t, &polaris.Inventory{Complete: true})
	var installed uint64
	var snapshot uint64
	count, changed, ready := 0, false, false
	for !ready || installed < 45 {
		packet, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch body := packet.Body.(type) {
		case *polaris.Packet_Plan:
			if !body.Plan.Complete || len(body.Plan.Positions) != 1 || body.Plan.Positions[0].Version != 40 {
				t.Fatal("initial plan drifted")
			}
		case *polaris.Packet_Snapshot:
			page := body.Snapshot
			if page.Version == nil || page.GetVersion() != 40 {
				t.Fatal("snapshot version was not frozen")
			}
			snapshot = page.GetVersion()
			count += len(page.Entries)
			if !changed {
				for version := storage.Version(41); version <= 45; version++ {
					if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: version, Key: "new", Value: []byte{byte(version)}}); err != nil {
						t.Fatal(err)
					}
				}
				changed = true
			}
			if page.Complete {
				if count != 40 {
					t.Fatal("partial snapshot")
				}
				installed = snapshot
			}
		case *polaris.Packet_Updates:
			for _, patch := range body.Updates.Patches {
				if patch.Version != installed+1 {
					t.Fatal("suffix gap", installed, patch.Version)
				}
				installed = patch.Version
			}
		case *polaris.Packet_Ready:
			ready = true
		default:
			t.Fatal("unexpected frame")
		}
		if installed != 0 {
			if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: &comet.Scope{Sector: []byte(scope.Sector), Spectrum: []byte(scope.Spectrum)}, Version: installed}}}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestStreamUnknownEmptyScope requires even version-zero installation to belong to durable authority, not a client-invented Scope.
func TestStreamUnknownEmptyScope(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	stream := system.connect(t, &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: &comet.Scope{Sector: []byte("missing"), Spectrum: []byte("scope")}}}})
	_, err := stream.Recv()
	if status.Code(err) != codes.Aborted {
		t.Fatal("accepted unknown installed empty scope", err)
	}
}

// TestAuthorityRPC checks identity isolation, durable receipts, original-request confirmation, and same-version conflicts without error-text matching.
func TestAuthorityRPC(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	client := polaris.NewAuthorityClient(system.channel)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request := &polaris.CommitRequest{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 1, Change: &comet.AlmanacChange{Key: "k", Action: &comet.AlmanacChange_Value{Value: []byte{1}}}}
	if _, err := client.Commit(ctx, request); status.Code(err) != codes.Unauthenticated {
		t.Fatal("missing identity accepted", err)
	}
	star := metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.star.Admission), "astra-signature-bin", string(system.star.AdmissionSignature))
	if _, err := client.Commit(star, request); status.Code(err) != codes.Unauthenticated {
		t.Fatal("Star could manage authority", err)
	}
	manager := metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature))
	for range 2 {
		reply, err := client.Commit(manager, request)
		if err != nil || reply.Version != 1 {
			t.Fatal("durable original request not confirmed", err)
		}
	}
	request.Change.Action = &comet.AlmanacChange_Value{Value: []byte{2}}
	if _, err := client.Commit(manager, request); status.Code(err) != codes.Aborted {
		t.Fatal("conflicting request accepted", err)
	}
	loaded, err := system.store.Load(ctx, storage.Scope{Sector: "s", Spectrum: "p"})
	if err != nil || loaded.Version != 1 || loaded.Records[0].Value[0] != 1 {
		t.Fatal("failed request changed durable data", err)
	}
}

// TestAuthorityBatch checks complete real-RPC batch confirmation/encoding; page targets must not split one commit into two Patches.
func TestAuthorityBatch(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	client := polaris.NewAuthorityClient(system.channel)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	manager := metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature))
	scope := &comet.Scope{Sector: []byte("batch"), Spectrum: []byte("main")}
	request := &polaris.CommitRequest{Scope: scope, Version: 1}
	for _, key := range []string{"a", "b"} {
		request.Changes = append(request.Changes, &comet.AlmanacChange{Key: key, Action: &comet.AlmanacChange_Value{Value: make([]byte, 300<<10)}})
	}
	for range 2 {
		result, err := client.Commit(manager, request)
		if err != nil || result.Version != 1 {
			t.Fatal("complete batch confirmation failed", err)
		}
	}
	invalid := proto.Clone(request).(*polaris.CommitRequest)
	invalid.Version = 2
	invalid.Changes[1].Key = "a"
	if _, err := client.Commit(manager, invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatal("duplicate batch accepted", err)
	}
	invalid.Changes[1].Key = "b"
	invalid.Change = invalid.Changes[0]
	if _, err := client.Commit(manager, invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatal("mixed single and batch accepted", err)
	}
	loaded, err := system.store.Load(ctx, storage.Scope{Sector: "batch", Spectrum: "main"})
	if err != nil || loaded.Version != 1 || len(loaded.Records) != 2 {
		t.Fatal("invalid batch changed durable state", err)
	}

	stream := system.connect(t, &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: scope, Version: 0}}})
	installed := false
	for {
		packet, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch body := packet.Body.(type) {
		case *polaris.Packet_Plan:
		case *polaris.Packet_Updates:
			if installed || len(body.Updates.Patches) != 1 {
				t.Fatal("batch split into multiple patches")
			}
			patch := body.Updates.Patches[0]
			if patch.Version != 1 || patch.Change != nil || len(patch.Changes) != 2 || !proto.Equal(patch.Changes[0], request.Changes[0]) || !proto.Equal(patch.Changes[1], request.Changes[1]) {
				t.Fatal("partial or changed batch payload")
			}
			installed = true
			if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: scope, Version: 1}}}); err != nil {
				t.Fatal(err)
			}
		case *polaris.Packet_Ready:
			if !installed {
				t.Fatal("ready before complete batch")
			}
			return
		default:
			t.Fatal("unexpected batch frame")
		}
	}
}

// TestWindow releases only acknowledged scope prefixes and refuses cancelled admission even when the window is empty.
func TestWindow(t *testing.T) {
	t.Parallel()
	a, b := storage.Scope{Sector: "s", Spectrum: "a"}, storage.Scope{Sector: "s", Spectrum: "b"}
	ctx, cancel := context.WithCancel(t.Context())
	transfer := &transfer{ctx: ctx, wake: make(chan struct{}, 1), sent: make(map[storage.Scope]storage.Version), input: make(chan incoming, 1)}
	transfer.charge(a, 0, 100)
	transfer.charge(a, 1, 200)
	transfer.charge(b, 2, 300)
	transfer.release(a, 0)
	if transfer.bytes != 500 || len(transfer.credits) != 2 {
		t.Fatal("zero boundary released wrong suffix")
	}
	transfer.release(a, 1)
	if transfer.bytes != 300 || len(transfer.credits) != 1 {
		t.Fatal("scope boundary released other scope")
	}
	transfer.charge(a, 2, 8<<20)
	cancel()
	if err := transfer.budget(1); err != context.Canceled {
		t.Fatal("cancelled window wait did not stop", err)
	}
	transfer.release(a, 2)
	transfer.release(b, 2)
	if transfer.bytes != 0 || len(transfer.credits) != 0 {
		t.Fatal("window retained released credits")
	}
	if err := transfer.budget(1); err != context.Canceled {
		t.Fatal("empty window admitted a cancelled operation", err)
	}
	if transfer.deadline.Load() != nil {
		t.Fatal("cancelled window retained its wait deadline")
	}
}

// TestAuthorityBatchStream commits an above-frame batch only after complete EOF and synchronizes through paged snapshot fallback.
func TestAuthorityBatchStream(t *testing.T) {
	limits := storage.Default()
	limits.Backlog = 16 << 20 // Retain the large history entry to exercise above-frame Patch fallback rather than a history gap.
	limits.Timeout = 30 * time.Second
	system := environment(t, limits)
	client := polaris.NewAuthorityClient(system.channel)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	manager := metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature))
	scope := &comet.Scope{Sector: []byte("large"), Spectrum: []byte("stream")}
	target := storage.Scope{Sector: "large", Spectrum: "stream"}
	changes := make([]*comet.AlmanacChange, 257)
	for index := range changes {
		changes[index] = &comet.AlmanacChange{Key: fmt.Sprint(index), Action: &comet.AlmanacChange_Value{Value: bytes.Repeat([]byte{byte(index)}, 40<<10)}}
	}
	for attempt := range 2 {
		stream, err := client.Batch(manager)
		if err != nil {
			t.Fatal(err)
		}
		for begin := 0; begin < len(changes); begin += 16 {
			end := min(begin+16, len(changes))
			if err := stream.Send(&polaris.BatchRequest{Scope: scope, Version: 1, Changes: changes[begin:end], Complete: end == len(changes)}); err != nil {
				t.Fatal(err)
			}
		}
		// Final page reached transport without EOF; no reader may observe the initial commit yet.
		if attempt == 0 {
			if version, err := system.store.Version(ctx, target); err != nil || version != 0 {
				t.Fatalf("batch committed before EOF: %v %v", version, err)
			}
		}
		result, err := stream.CloseAndRecv()
		if err != nil || result.Version != 1 {
			t.Fatalf("large batch confirmation: %v", err)
		}
	}
	replay, err := system.store.Since(ctx, target, 0)
	if err != nil || len(replay.Changes) != 1 || len(replay.Changes[0].Value) <= 8<<20 {
		t.Fatalf("large history missing: %v", err)
	}
	stream := system.connect(t, &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: scope}}})
	received := make(map[string][]byte)
	pages, installed := 0, false
	for {
		packet, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch body := packet.Body.(type) {
		case *polaris.Packet_Plan:
		case *polaris.Packet_Snapshot:
			page := body.Snapshot
			if installed || page.Version == nil || page.GetVersion() != 1 {
				t.Fatal("invalid snapshot boundary")
			}
			pages++
			for _, entry := range page.Entries {
				if _, duplicate := received[entry.Key]; duplicate {
					t.Fatal("duplicate snapshot key")
				}
				received[entry.Key] = entry.GetValue()
			}
			if page.Complete {
				if pages < 2 || len(received) != len(changes) {
					t.Fatal("partial large batch")
				}
				for _, entry := range changes {
					if !bytes.Equal(received[entry.Key], entry.GetValue()) {
						t.Fatal("large batch value changed")
					}
				}
				installed = true
				if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: scope, Version: 1}}}); err != nil {
					t.Fatal(err)
				}
			}
		case *polaris.Packet_Ready:
			if !installed {
				t.Fatal("ready before complete large batch")
			}
			return
		default:
			t.Fatal("oversized batch was not sent as complete snapshot")
		}
	}
}

// TestAuthorityBatchIncomplete rejects cancellation, missing tail, position drift, duplicates, and post-complete data without writing a prefix.
func TestAuthorityBatchIncomplete(t *testing.T) {
	system := environment(t, storage.Default())
	client := polaris.NewAuthorityClient(system.channel)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	manager := metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature))
	scope := &comet.Scope{Sector: []byte("incomplete"), Spectrum: []byte("stream")}
	entry := &comet.AlmanacChange{Key: "a", Action: &comet.AlmanacChange_Value{Value: []byte("new")}}
	for _, scenario := range []string{"missing", "cancel", "version", "scope", "duplicate", "after"} {
		t.Run(scenario, func(t *testing.T) {
			current, cancel := context.WithCancel(manager)
			defer cancel()
			stream, err := client.Batch(current)
			if err != nil {
				t.Fatal(err)
			}
			first := &polaris.BatchRequest{Scope: scope, Version: 1, Changes: []*comet.AlmanacChange{entry}, Complete: scenario == "after"}
			if err := stream.Send(first); err != nil {
				t.Fatal(err)
			}
			if scenario == "cancel" {
				cancel()
			}
			if scenario != "missing" && scenario != "cancel" {
				final := &polaris.BatchRequest{Scope: scope, Version: 1, Changes: []*comet.AlmanacChange{entry}, Complete: true}
				if scenario == "version" {
					final.Version = 2
				}
				if scenario == "scope" {
					final.Scope = &comet.Scope{Sector: scope.Sector, Spectrum: []byte("other")}
				}
				// Server may reject an earlier frame; CloseAndRecv obtains final status after Send EOF.
				if err := stream.Send(final); err != nil && !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
			}
			_, err = stream.CloseAndRecv()
			wanted := codes.InvalidArgument
			if scenario == "cancel" {
				wanted = codes.Canceled
			}
			if status.Code(err) != wanted {
				t.Fatalf("invalid batch returned %v", err)
			}
			if version, err := system.store.Version(ctx, storage.Scope{Sector: "incomplete", Spectrum: "stream"}); err != nil || version != 0 {
				t.Fatalf("partial commit: %v %v", version, err)
			}
		})
	}
}
