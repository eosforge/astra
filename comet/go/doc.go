// Package comet provides native, synchronous Comet writes and continuously
// synchronized, immutable read views. It owns authentication, versions, recovery
// and bounded background work; applications own payload encoding and explicit
// shutdown. A successful RPC receipt is not a replication or durability promise.
//
// New validates local options and starts connecting asynchronously. Beacon waits
// for its first registration acknowledgment; other factories return after local
// admission. Request contexts do not become role lifetimes. Call Stop, Destroy
// or Close explicitly, then Wait with a bounded context when draining is needed.
// Do not wait for a role or Client from its own notification or sampling callback.
package comet
