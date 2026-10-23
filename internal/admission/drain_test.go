// Exercise cancellation and channel closure against real in-flight TLS admission requests.
package admission

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestNodeDrain joins both actual client operations and server handlers before releasing their shared fixtures.
func TestNodeDrain(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-DRAIN")
	identity := identity(t)
	for _, role := range []orbit.Role{orbit.Role_ROLE_POLARIS, orbit.Role_ROLE_ASTROLABE} {
		for _, refresh := range []bool{false, true} {
			for _, closing := range []bool{false, true} {
				func() {
					label := fmt.Sprintf("role=%s refresh=%t closing=%t", role, refresh, closing)
					local := &orbit.Member{Galaxy: "alpha", Id: []byte("drain"), Principal: identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: role, Group: "default"}
					service := &authority{reply: response(t, local)}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					entered, exited := make(chan struct{}), make(chan struct{})
					var active, calls atomic.Int32
					method := "/proto.orbit.v1.Admission/Register"
					if refresh {
						method = "/proto.orbit.v1.Admission/List"
					}
					server := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())), grpc.UnaryInterceptor(func(ctx context.Context, request any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
						if info.FullMethod != method {
							// Only refresh scenarios register first. Preserve the actual requested role in this fixture.
							if registration, ok := request.(*orbit.RegistrationRequest); ok && registration.Role == role {
								return proto.Clone(service.reply), nil
							}
							return next(ctx, request)
						}
						if calls.Add(1) != 1 {
							return nil, status.Error(codes.Internal, "Unexpected repeated blocked RPC")
						}
						active.Add(1)
						defer func() { active.Add(-1); close(exited) }()
						close(entered)
						<-ctx.Done()
						return nil, status.FromContextError(ctx.Err()).Err()
					}))
					orbit.RegisterAdmissionServer(server, service)
					serving := make(chan error, 1)
					go func() { serving <- server.Serve(listener) }()
					defer func() {
						server.Stop()
						select {
						case err := <-serving:
							if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
								t.Error(err)
							}
						case <-time.After(10 * time.Second):
							t.Error("owned TLS server did not exit: " + label)
						}
					}()
					value, err := Open(identity, listener.Addr().String(), "alpha", "127.0.0.1:7443", "default", role)
					if err != nil {
						t.Fatal(err)
					}
					closed := false
					defer func() {
						if !closed {
							check(value.Close() == nil, "owned client channel did not close: "+label)
						}
					}()
					budget, finish := context.WithTimeout(t.Context(), 10*time.Second)
					defer finish()
					ctx, cancel := context.WithCancel(budget)
					defer cancel()
					if refresh {
						check(value.Register(budget) == nil, "initial TLS registration failed: "+label)
					}
					before, hello := value.Member(), value.Hello()
					members := value.directory.Members()
					request := proto.Clone(value.request)
					result, finished := make(chan error, 1), make(chan struct{})
					defer func() {
						cancel()
						select {
						case <-finished:
						case <-time.After(10 * time.Second):
							t.Error("owned client operation did not drain: " + label)
						}
					}()
					go func() {
						defer close(finished)
						if refresh {
							result <- value.Refresh(ctx)
						} else {
							result <- value.Register(ctx)
						}
					}()
					select {
					case <-entered:
					case <-budget.Done():
						t.Fatal("RPC did not reach the actual TLS server: " + label)
					}
					check(calls.Load() == 1 && active.Load() == 1 && len(value.gate) == 1, "missing native in-flight ownership: "+label)
					check(proto.Equal(value.Member(), before) && proto.Equal(value.Hello(), hello), "in-flight RPC published partial identity: "+label)
					if closing {
						check(value.Close() == nil, "closing in-flight channel failed: "+label)
						closed = true
					} else {
						cancel()
					}
					select {
					case err := <-result:
						check(status.Code(err) == codes.Canceled, "interrupted native RPC returned a false success or unexpected failure: "+label)
					case <-budget.Done():
						t.Fatal("interrupted native RPC did not return: " + label)
					}
					for _, done := range []<-chan struct{}{finished, exited} {
						select {
						case <-done:
							check(true, "owned operation completed: "+label)
						case <-budget.Done():
							t.Fatal("interrupted operation retained work: " + label)
						}
					}
					check(active.Load() == 0 && calls.Load() == 1 && len(value.gate) == 0, "late work or admission ownership survived: "+label)
					check(proto.Equal(value.Member(), before) && proto.Equal(value.Hello(), hello) && proto.Equal(value.request, request), "cancellation changed published identity or retry token: "+label)
					after := value.directory.Members()
					check(len(after) == len(members), "cancellation changed directory size: "+label)
					for index := range members {
						check(proto.Equal(after[index], members[index]), "cancellation changed directory content: "+label)
					}
					t.Logf("node-drain %s calls=%d active=%d permits=%d", label, calls.Load(), active.Load(), len(value.gate))
				}()
			}
		}
	}
}
