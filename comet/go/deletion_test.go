// Observe authoritative absence and callback failure through retained public views.
package comet

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestReaderKeyAuthoritativeErase distinguishes a present empty value from later authority.
func TestReaderKeyAuthoritativeErase(t *testing.T) {
	erase := make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{almanac: func(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.AlmanacWatchReply]) error {
		if string(request.Target) != "only" {
			t.Error("ReaderKey changed the exact wire target")
		}
		if cause := stream.Send(&protocol.AlmanacWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(7),
			Changes: []*protocol.AlmanacChange{{Key: "only", Action: &protocol.AlmanacChange_Value{Value: nil}}},
		}); cause != nil {
			return cause
		}
		select {
		case <-erase:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if cause := stream.Send(&protocol.AlmanacWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8),
			Changes: []*protocol.AlmanacChange{{Key: "only", Action: &protocol.AlmanacChange_Erase{Erase: &protocol.Empty{}}}},
		}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	reader, cause := client.ReaderKey(testScope(), "only")
	if cause != nil {
		t.Fatal(cause)
	}
	presence := make(chan bool, 2)
	if cause := reader.WatchKey(func(key string, value Value, present bool) {
		if key != "only" || value.Len() != 0 {
			t.Error("authority callback changed the exact key or empty value")
		}
		recordTest(t, presence, present)
	}); cause != nil {
		t.Fatal(cause)
	}
	if !receiveTest(t, presence) {
		t.Fatal("Reader classified a present empty value as absence")
	}
	retained := reader.State()
	if !retained.HasVersion || retained.Version != 7 || retained.Data.Len() != 1 {
		t.Fatal("Reader did not publish the complete authority baseline")
	}
	close(erase)
	if receiveTest(t, presence) {
		t.Fatal("Reader failed to publish explicit authoritative absence")
	}
	state := reader.State()
	_, present := retained.Data.Get("only")
	if !state.HasVersion || state.Version != 8 || state.Data.Len() != 0 || !present {
		t.Fatal("authority erase lost its version floor or mutated a retained snapshot")
	}
	reader.Stop()
	if cause := reader.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}

// TestBeaconChangedPanicAndRecovery preserves identity and supports a fresh callback registration.
func TestBeaconChangedPanicAndRecovery(t *testing.T) {
	fixture := newFixture(t, fixtureHandlers{})
	client := fixtureClient(t, fixture)
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, nil, 10*time.Second, 5*time.Second)
	if cause != nil {
		t.Fatal(cause)
	}
	identity := beacon.State().Identity
	if cause := beacon.Changed(func(BeaconState) { panic("private callback material") }); cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool {
		state := beacon.State()
		return client.Panics() == 1 && state.Error != nil && state.Error.Code == CodeCallback
	})
	state := beacon.State()
	if state.Identity != identity || !state.HasIdentity || strings.Contains(state.Error.Error(), "private") {
		t.Fatal("callback panic changed identity or exposed its private material")
	}
	state.Error.Code = CodeInternal
	if beacon.State().Error.Code != CodeCallback {
		t.Fatal("returned state error aliases the retained diagnostic")
	}
	states := make(chan BeaconState, 4)
	if cause := beacon.Changed(func(state BeaconState) { recordTest(t, states, state) }); cause != nil {
		t.Fatal(cause)
	}
	replacement := receiveTest(t, states)
	if replacement.Identity != identity || replacement.Error == nil || replacement.Error.Code != CodeCallback {
		t.Fatal("late replacement lost the current identity or diagnostic")
	}
	if _, cause := beacon.Update(testContext(t), []byte("fresh")); cause != nil {
		t.Fatal(cause)
	}
	recovered := receiveTest(t, states)
	if recovered.Phase != Ready || recovered.Error != nil || recovered.Identity != identity || client.Panics() != 1 {
		t.Fatal("successful caller update did not recover after callback panic")
	}
	beacon.Destroy()
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
