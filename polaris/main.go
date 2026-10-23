// Polaris is the sole durable Almanac authority and serves internal TLS/gRPC only, without public Comet writes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/command"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/server"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// options holds parsed deployment configuration without plaintext passwords; identity/login.json retains account material.
type options struct {
	listen, advertise, super, galaxy, group, identity, state string // Listen, advertise, admission, Galaxy/group, identity directory, and database path.
	initialize                                               bool   // Explicit initialization of a new database; existing files are rejected.
	snapshots                                                int64  // Shared snapshot-preparation budget in bytes.
}

// parse validates arguments excluding executable name without reading credentials or creating storage; returns deployment options or error.
func parse(arguments []string) (options, error) {
	var config options
	flags := flag.NewFlagSet("polaris", flag.ContinueOnError)
	// Register all deployment flags with public help and their actual defaults.
	flags.StringVar(&config.listen, "listen", "", "Internal numeric IP:PORT listener")
	flags.StringVar(&config.advertise, "advertise", "", "Canonical advertised IP:PORT; defaults to listen")
	flags.StringVar(&config.super, "super", "", "Pulsar admission IP:PORT")
	flags.StringVar(&config.galaxy, "galaxy", "", "Galaxy name")
	flags.StringVar(&config.group, "group", "default", "Logical locality group")
	flags.StringVar(&config.identity, "identity", "identity", "TLS, admission.pub and login.json directory")
	flags.StringVar(&config.state, "state", "state/polaris.db", "Existing exclusive authority SQLite database")
	flags.BoolVar(&config.initialize, "init", false, "Explicitly create a new authority database; refuses an existing file")
	flags.Int64Var(&config.snapshots, "snapshot-bytes", 256<<20, "Shared preparation and active snapshot budget")
	if err := command.Parse(flags, arguments); err != nil {
		return options{}, err
	}
	// Absent advertise defaults to listen.
	if config.advertise == "" {
		config.advertise = config.listen
	}
	// Require canonical numeric listen/advertise/admission endpoints, 80 MiB..1 GiB snapshot budget, valid names/paths, and no positional extras.
	for _, endpoint := range []string{config.listen, config.advertise, config.super} {
		if _, err := admission.Endpoint(endpoint); err != nil {
			return options{}, errors.New("listen, advertise and super require canonical concrete IP:PORT")
		}
	}
	if flags.NArg() != 0 || !admission.Name(config.galaxy) || !admission.Name(config.group) || config.state == "" || config.identity == "" || config.snapshots < 80<<20 || config.snapshots > 1<<30 {
		return options{}, errors.New("invalid Polaris configuration")
	}
	return config, nil
}

// run owns shutdown order: RPC, actual stream workers, directory refresh, Channel, database.
// ctx is process context and config is validated; normal closure returns nil.
func run(ctx context.Context, config options) error {
	// Runtime requires Linux and CGO for flock exclusivity.
	if runtime.GOOS != "linux" {
		return errors.New("Polaris currently requires Linux with the project CGO toolchain")
	}
	// Prepare identity, authority store, login baseline, and admission node in order; any failure returns.
	identity, err := admission.Load(config.identity, config.advertise)
	if err != nil {
		return err
	}
	store, err := storage.Open(ctx, config.state, storage.Binding{Galaxy: config.galaxy, Username: identity.Username(), Advertise: config.advertise}, storage.Default(), config.initialize)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := server.Validate(ctx, store); err != nil {
		return err
	}
	node, err := admission.Open(identity, config.super, config.galaxy, config.advertise, config.group, orbit.Role_ROLE_POLARIS)
	if err != nil {
		return err
	}
	defer node.Close()
	// Reserve the certificate-authorized listener before admission; gRPC Serve begins only after full initialization.
	listener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return errors.New("cannot bind Polaris internal listener")
	}
	defer listener.Close()
	// Complete admission before constructing management and push services.
	if err := node.Join(ctx); err != nil {
		return err
	}
	management, err := server.NewAuthority(store, node.Directory(), config.snapshots)
	if err != nil {
		return err
	}
	streams := server.NewStreams(node, management)
	// Internal TLS, 8 MiB messages, 32 concurrent streams, and 30/10-second keepalive settings.
	rpc := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())), grpc.MaxRecvMsgSize(8<<20), grpc.MaxSendMsgSize(8<<20), grpc.MaxConcurrentStreams(32), grpc.MaxHeaderListSize(8192), grpc.ConnectionTimeout(3*time.Second), grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}), grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}))
	polaris.RegisterAuthorityServer(rpc, management)
	polaris.RegisterAlmanacServer(rpc, streams)
	// Health is SERVING during operation and changes to nonserving before draining shutdown.
	healthy := health.NewServer()
	grpc_health_v1.RegisterHealthServer(rpc, healthy)
	healthy.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	slog.Info("Polaris ready", "endpoint", config.advertise, "galaxy", config.galaxy, "instance", string(node.Member().Id))
	return serve(ctx, listener, rpc, healthy, func(ctx context.Context) error {
		return node.Run(ctx, func(err error) {
			if err != nil {
				slog.Warn("Pulsar directory refresh unavailable; retaining observed membership")
			}
		})
	}, streams.Wait)
}

// serve drains all owned workers before its caller closes admission and storage dependencies.
// Refresh returns when cancelled or permanently refused; wait joins the stream workers after RPC shutdown.
func serve(ctx context.Context, listener net.Listener, rpc *grpc.Server, healthy *health.Server, refresh func(context.Context) error, wait func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	refreshed := make(chan error, 1)
	go func() { refreshed <- refresh(ctx) }()
	serving := make(chan error, 1)
	go func() { serving <- rpc.Serve(listener) }()
	var result error
	joined, served := false, false
	select {
	case <-ctx.Done():
	case result = <-refreshed:
		joined = true
	case result = <-serving:
		served = true
	}
	// Refuse new health admission before cancelling refresh and draining accepted RPCs.
	healthy.Shutdown()
	cancel()
	stopped := make(chan struct{})
	go func() {
		rpc.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		rpc.Stop()
		<-stopped
	}
	wait()
	if !joined {
		<-refreshed
	}
	if !served {
		<-serving
	}
	if errors.Is(result, context.Canceled) || errors.Is(result, grpc.ErrServerStopped) {
		return nil
	}
	return result
}

// start returns the process status only after startup resources and signal notification are released.
func start(arguments []string) int {
	config, err := parse(arguments)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("Polaris stopped", "error", err)
		return 1
	}
	return 0
}

// main owns process logging and exits after the complete application scope has drained.
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	os.Exit(start(os.Args[1:]))
}
