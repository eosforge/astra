// Astrolabe provides management login and Almanac authority forwarding without owning a database or modifying Star authority state directly.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eosforge/astra/astrolabe/internal/bridge"
	"github.com/eosforge/astra/astrolabe/internal/web"
	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/command"
	"github.com/eosforge/astra/internal/generated/orbit"
)

// options uses trusted deployment origins, never arbitrary proxy headers; the account file holds only a password digest.
type options struct {
	listen, advertise, super, galaxy, group, identity, account, public, origins, metrics string
	plain, crosssite                                                                     bool
	sessions                                                                             int // Session capacity, 1..4096.
}

// parse validates nonsecret deployment options; --http permits loopback proxies only, while Pulsar/Polaris transport always uses TLS.
func parse(arguments []string) (options, error) {
	var config options
	flags := flag.NewFlagSet("astrolabe", flag.ContinueOnError)

	flags.StringVar(&config.listen, "listen", "", "Numeric management IP:PORT listener")
	flags.StringVar(&config.advertise, "advertise", "", "Backend IP:PORT registered at Pulsar; defaults to listen")
	flags.StringVar(&config.super, "super", "", "Pulsar admission IP:PORT")
	flags.StringVar(&config.galaxy, "galaxy", "", "Galaxy name")
	flags.StringVar(&config.group, "group", "default", "Logical locality group")
	flags.StringVar(&config.identity, "identity", "identity", "Internal TLS, admission.pub and login.json directory")
	flags.StringVar(&config.account, "account", "", "Existing username/salt/hash JSON for one management account")
	flags.StringVar(&config.public, "public", "", "Exact externally visible API origin, such as https://admin.example")
	flags.StringVar(&config.origins, "origins", "", "Additional comma-separated allowed browser origins")
	flags.StringVar(&config.metrics, "metrics", "", "Optional JSON map of Star endpoints to protected metrics URLs")
	flags.BoolVar(&config.plain, "http", false, "HTTP on loopback only, for a separately configured reverse proxy")
	flags.BoolVar(&config.crosssite, "crosssite", false, "Explicit SameSite=None; requires HTTPS public origin")
	flags.IntVar(&config.sessions, "sessions", 4096, "Maximum in-memory eight-hour management sessions")
	if err := command.Parse(flags, arguments); err != nil {
		return options{}, err
	}
	if config.advertise == "" {
		// Default the advertised address to the listen address when omitted.
		config.advertise = config.listen
	}
	// Require canonical numeric IP:PORT endpoints, without hostnames or paths.
	for _, endpoint := range []string{config.listen, config.advertise, config.super} {
		if _, err := admission.Endpoint(endpoint); err != nil {
			return options{}, errors.New("listen, advertise and super require concrete canonical IP:PORT")
		}
	}

	listen, _ := admission.Endpoint(config.listen)
	public, err := web.Origin(config.public)
	if err != nil || flags.NArg() != 0 || !admission.Name(config.galaxy) || !admission.Name(config.group) || config.identity == "" || config.account == "" || config.sessions < 1 || config.sessions > 4096 || config.plain && !listen.Addr().IsLoopback() || config.crosssite && !strings.HasPrefix(public, "https://") || !config.plain && !strings.HasPrefix(public, "https://") {
		return options{}, errors.New("invalid Astrolabe configuration")
	}
	config.public = public
	// Normalize and deduplicate extra browser origins; allow at most 32 including the public origin.
	origins := map[string]bool{public: true}
	if config.origins != "" {
		for _, raw := range strings.Split(config.origins, ",") {
			origin, err := web.Origin(raw)
			if err != nil || origins[origin] || len(origins) >= 32 {
				return options{}, errors.New("invalid or duplicate browser origin")
			}
			origins[origin] = true
		}
	}
	return config, nil
}

// run opens local management login before asynchronous admission, so Pulsar outages are not reported as invalid browser credentials.
// The parent context owns shutdown; config has already passed deployment validation.
func run(parent context.Context, config options) error {

	targets, err := bridge.Targets(config.metrics)
	if err != nil {
		return err
	}
	identity, err := admission.Load(config.identity, config.advertise)
	if err != nil {
		return err
	}
	account, err := web.LoadAccount(config.account)
	if err != nil {
		return err
	}
	node, err := admission.Open(identity, config.super, config.galaxy, config.advertise, config.group, orbit.Role_ROLE_ASTROLABE)
	if err != nil {
		return err
	}
	defer node.Close()
	backend := bridge.New(node, identity)
	defer backend.Close()

	origins := []string{config.public}
	if config.origins != "" {
		origins = append(origins, strings.Split(config.origins, ",")...)
	}
	handler, err := web.New(account, backend, web.Options{Origins: origins, Secure: strings.HasPrefix(config.public, "https://"), Crosssite: config.crosssite, Sessions: config.sessions})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return errors.New("cannot bind Astrolabe management listener")
	}
	defer listener.Close()
	if !config.plain {
		listener = tls.NewListener(listener, identity.Server())
	}
	// Own and join the metrics monitor for the duration of this run.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	monitored := make(chan struct{})
	go func() { defer close(monitored); backend.Monitor(ctx, targets, identity.Client()) }()
	defer func() { cancel(); <-monitored }()
	// HTTP bounds: 3-second header reads, 10-second reads, 35-second writes and 8 KiB headers.
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	// The directory worker joins, publishes its first Update and then runs continuously; report failures through the buffered channel.
	refresh := make(chan error, 1)
	go func() {
		if err := node.Join(ctx); err != nil {
			refresh <- err
			return
		}
		backend.Update(nil)
		refresh <- node.Run(ctx, backend.Update)
	}()

	serving := make(chan error, 1)
	go func() { serving <- server.Serve(listener) }()
	slog.Info("Astrolabe management listener ready", "endpoint", config.advertise, "galaxy", config.galaxy)

	var result error
	refreshed := false
	select {
	case <-parent.Done():
	case result = <-refresh:
		refreshed = true
	case result = <-serving:
	}
	// Cancel every owned HTTP-to-RPC chain before bounded service and directory drainage; leave no request goroutines behind.
	cancel()
	deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if server.Shutdown(deadline) != nil {
		_ = server.Close()
	}
	if !refreshed {
		<-refresh
	}
	if errors.Is(result, context.Canceled) || errors.Is(result, http.ErrServerClosed) {
		return nil
	}
	return result
}

// main logs fixed diagnostics without passwords, cookies, SQL or raw backend messages; signals stop only owned resources.
func main() {

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	config, err := parse(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {

		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("Astrolabe stopped", "error", err)
		os.Exit(1)
	}
}
