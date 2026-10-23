// Verify initial Session admission against actual HTTP/2 transport limits before any request headers are sent.
package comet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc/connectivity"
)

// TestInitialSessionTransportAdmission preserves the initial budget and conservative transport error at stream creation.
func TestInitialSessionTransportAdmission(t *testing.T) {
	for _, testcase := range []struct {
		name    string
		setting http2.Setting
		code    Code
		effect  Effect
	}{
		{"stream-quota-timeout", http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 0}, CodeTimeout, Unapplied},
		{"header-limit", http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 0}, CodeTransport, Unknown},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			listener, cause := net.Listen("tcp", "127.0.0.1:0")
			if cause != nil {
				t.Fatal(cause)
			}
			var workers sync.WaitGroup
			var mutex sync.Mutex
			var connections []net.Conn
			var prefaces, headers atomic.Int32
			failures := make(chan error, 8)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer listener.Close()
				// Login owns exactly two transports: one for streams and one for unary calls.
				for range 2 {
					connection, failure := listener.Accept()
					if failure != nil {
						if !errors.Is(failure, net.ErrClosed) {
							failures <- failure
						}
						return
					}
					mutex.Lock()
					connections = append(connections, connection)
					mutex.Unlock()
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer connection.Close()
						if failure := connection.SetDeadline(time.Now().Add(5 * time.Second)); failure != nil {
							failures <- failure
							return
						}
						preface := make([]byte, len(http2.ClientPreface))
						if _, failure := io.ReadFull(connection, preface); failure != nil {
							failures <- failure
							return
						}
						if string(preface) != http2.ClientPreface {
							failures <- fmt.Errorf("unexpected HTTP/2 client preface")
							return
						}
						prefaces.Add(1)
						framer := http2.NewFramer(connection, connection)
						if failure := framer.WriteSettings(testcase.setting); failure != nil {
							failures <- failure
							return
						}
						for {
							frame, failure := framer.ReadFrame()
							if failure != nil {
								if !errors.Is(failure, io.EOF) && !errors.Is(failure, net.ErrClosed) {
									failures <- failure
								}
								return
							}
							switch frame := frame.(type) {
							case *http2.SettingsFrame:
								if !frame.IsAck() {
									if failure := framer.WriteSettingsAck(); failure != nil {
										failures <- failure
										return
									}
								}
							case *http2.PingFrame:
								if !frame.IsAck() {
									if failure := framer.WritePing(true, frame.Data); failure != nil {
										failures <- failure
										return
									}
								}
							case *http2.HeadersFrame:
								headers.Add(1)
							}
						}
					}()
				}
			}()
			t.Cleanup(func() {
				listener.Close()
				mutex.Lock()
				for _, connection := range connections {
					connection.Close()
				}
				mutex.Unlock()
				drained := make(chan struct{})
				go func() { workers.Wait(); close(drained) }()
				select {
				case <-drained:
				case <-time.After(5 * time.Second):
					t.Fatal("HTTP/2 fixture did not drain")
				}
				close(failures)
				for failure := range failures {
					t.Error(failure)
				}
			})
			settings, trust, failure := normalizeOptions(Options{
				Endpoints: []string{listener.Addr().String()}, Plaintext: true, Key: "key", Secret: []byte("secret"), Timeout: time.Second,
			})
			if failure != nil {
				t.Fatal(failure)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Isolate one login attempt with production-normalized inputs; no supervisor retry changes the transcript.
			client := &Client{options: settings, trust: trust, ctx: ctx}
			selected, session, failure := client.login(settings.Endpoints[0], settings.Secret)
			if selected != nil {
				t.Cleanup(func() { selected.cancel(); selected.streams.Close(); selected.unary.Close() })
			}
			requireCode(t, failure, testcase.code, testcase.effect)
			if selected == nil || session != nil || selected.instance() != "" || selected.session != "" {
				t.Fatal("failed stream creation established Session identity")
			}
			if selected.streams.GetState() != connectivity.Ready || selected.unary.GetState() != connectivity.Ready || prefaces.Load() != 2 || headers.Load() != 0 {
				t.Fatal("transport fault did not occur after both connections became ready and before request headers")
			}
			if errors.Is(failure, context.DeadlineExceeded) != (testcase.code == CodeTimeout) || strings.Contains(failure.Error(), "secret") {
				t.Fatal("initial admission lost deadline identity or exposed credentials")
			}
		})
	}
}
