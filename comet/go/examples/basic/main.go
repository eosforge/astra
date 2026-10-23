// Demonstrate all six public roles against an explicitly configured existing Star.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/eosforge/astra/comet/go"
)

// main owns process cancellation; this example never starts or installs a service.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if cause := run(ctx); cause != nil {
		fmt.Fprintln(os.Stderr, cause)
		os.Exit(1)
	}
}

// run configures secure defaults and gives the Client a separate bounded cleanup Context.
func run(ctx context.Context) error {
	endpoint := os.Getenv("COMET_ENDPOINT")
	if endpoint == "" {
		return errors.New("set COMET_ENDPOINT to an existing Star host:port")
	}
	anonymous, cause := environmentFlag("COMET_ANONYMOUS")
	if cause != nil {
		return cause
	}
	plaintext, cause := environmentFlag("COMET_PLAINTEXT")
	if cause != nil {
		return cause
	}
	client, cause := comet.New(comet.Options{Endpoints: []string{endpoint}, Key: os.Getenv("COMET_KEY"), Secret: []byte(os.Getenv("COMET_SECRET")),
		Anonymous: anonymous, Plaintext: plaintext})
	if cause != nil {
		return cause
	}
	defer func() {
		client.Close()
		drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cause := client.Wait(drain); cause != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", cause)
		}
	}()
	scope := comet.Scope{Sector: "example", Spectrum: "workers"}
	subscriber, cause := client.Subscriber(scope)
	if cause != nil {
		return cause
	}
	defer subscriber.Stop()
	if cause := subscriber.Watch(func(snapshot comet.Map) { fmt.Println("Catalog records:", snapshot.Len()) }); cause != nil {
		return cause
	}
	reader, cause := client.Reader(scope)
	if cause != nil {
		return cause
	}
	defer reader.Stop()
	if cause := reader.Changed(func(view comet.View) { fmt.Println("Almanac ready:", view.HasVersion, "version:", view.Version) }); cause != nil {
		return cause
	}
	observer, cause := client.Observer(scope)
	if cause != nil {
		return cause
	}
	defer observer.Stop()
	publisher, cause := client.Publisher(scope)
	if cause != nil {
		return cause
	}
	defer publisher.Close()
	if _, cause := publisher.Update(ctx, []comet.Entry{{Key: "example-worker", Data: []byte("ready")}}, 10*time.Second); cause != nil {
		return cause
	}
	beacon, cause := client.Beacon(ctx, scope, []byte("example-worker"), []byte("available"), 10*time.Second, 2*time.Second)
	if cause != nil {
		return cause
	}
	defer beacon.Destroy()
	if cause := beacon.Tick(time.Second, func() ([]byte, error) { return []byte("available"), nil }); cause != nil {
		return cause
	}
	// First-match selection demonstrates ownership only; applications define real policy.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			item, cause := observer.One(func(pool comet.Pool) *comet.Item {
				var selected *comet.Item
				pool.Range(func(candidate *comet.Item) bool { selected = candidate; return false })
				return selected
			})
			if cause == nil && item != nil {
				// This estimate is local to Observer; it does not update Beacon or Star.
				if cause := item.Update([]byte("selected locally")); cause != nil {
					fmt.Fprintln(os.Stderr, "local estimate:", cause)
				}
			}
		}
	}
}

// environmentFlag accepts explicit Boolean opt-outs and otherwise keeps secure defaults.
func environmentFlag(name string) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return false, nil
	}
	flag, cause := strconv.ParseBool(value)
	if cause != nil {
		return false, fmt.Errorf("%s must be a Boolean", name)
	}
	return flag, nil
}
