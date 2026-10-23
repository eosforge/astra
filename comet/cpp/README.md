# Comet C++ SDK

Comet is Astra's native C++23 application SDK. Public headers expose Client, Reader, Subscriber, Publisher, Observer and Beacon through
`comet::Result<T>` (`std::expected<T, comet::Error>`), without public gRPC types.

[Architecture](../../docs/architecture.md) · [Deploy a Star](../../docs/deployment.md) · [Provision
credentials](../../astrolabe/README.md#publish-data-and-credentials)

The republished 0.1.0 SDK uses PascalCase enum items: for example, `Reader::State::Ready` replaces the earlier `Reader::State::ready`, and
`Error::Code::Input` replaces `Error::Code::input`. This source-breaking change covers all items of `Beacon::Phase`, `Reader::State`,
`Observer::State`, `Subscriber::State`, `Error::Code` and `Error::Effect`. Old names have no compatibility aliases; enum values and wire formats
are unchanged. Earlier 0.1.0 downloads used the original names; rebuild source consumers with matching headers and libraries from this publication.

## Build and link

The Linux release includes `include/comet/`, `lib/libcomet.a` and installed CMake exports. Use GCC 16.2.0 and matching Protobuf 36.1.0/gRPC 1.84.0
development packages from the lock. Those external development packages are not all bundled in the release archive. The installed SDK checks its
producing platform and exact compiler version.

After [dependency preparation](../../docs/build.md), build just the SDK from a full source checkout:

```bash
cmake -S comet/cpp -B build/comet -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -DCMAKE_CXX_COMPILER="$PWD/build/tools/gcc-16.2.0/bin/g++" \
  -DCMAKE_PREFIX_PATH="$PWD/build/deps/astra/linux-gcc16/install"
cmake --build build/comet --parallel 2 --target comet
cmake --install build/comet --prefix "$PWD/build/comet-install"
```

The SDK consumes generated sources under `common/`; copying only `comet/cpp` is insufficient. A standalone Windows/MSVC 19.51+ source entry also
exists, with matching Windows dependencies. No Windows binary is included in this release.

An application's `CMakeLists.txt` can use:

```cmake
cmake_minimum_required(VERSION 3.28)
project(comet_example LANGUAGES CXX)
find_package(Comet CONFIG REQUIRED)
add_executable(comet_example main.cpp)
target_link_libraries(comet_example PRIVATE comet::comet)
```

Configure that application with `CMAKE_PREFIX_PATH` containing both the installed SDK and matching dependency prefix, separated by `;`. The imported
target propagates C++23 and link requirements.

## Minimal Catalog publisher

Save the following deployment-dependent example as `main.cpp`. Set `COMET_KEY`, `COMET_SECRET_FILE` and `COMET_CA_FILE`; pass an existing Star
application endpoint as its only argument. The secret file contains exact raw bytes without an unintended trailing newline. The CA file is a PEM
bundle covering the Star certificate.

```cpp
#include <comet/client.hpp>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <utility>

// Publish once to an existing Star, then drain the owned client.
int main(int count, char** arguments) {

    const auto key = std::getenv("COMET_KEY");
    const auto secret = std::getenv("COMET_SECRET_FILE");
    const auto ca = std::getenv("COMET_CA_FILE");
    if (count != 2 || !key || !secret || !ca) {
        std::cerr << "Provide endpoint, COMET_KEY, COMET_SECRET_FILE and COMET_CA_FILE\n";
        return 1;
    }
    std::ifstream input(secret, std::ios::binary);
    if (!input) {
        return 1;
    }
    comet::Client::Options options;
    options.endpoints = {arguments[1]};
    options.key = key;
    options.ca = ca;
    options.secret.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    if (input.bad()) {
        return 1;
    }

    auto client = comet::Client::open(std::move(options));
    if (!client) {
        std::cerr << "Client configuration rejected\n";
        return 1;
    }
    int result = 1;
    auto publisher = client->publisher({"example", "workers"});
    if (publisher) {
        const auto receipt = publisher->update("worker-a", {'r', 'e', 'a', 'd', 'y'}, std::chrono::seconds(30));
        if (receipt) {
            std::cout << "Committed at " << receipt->instance << " version " << receipt->version << '\n';
            result = 0;
        } else {
            std::cerr << "Write failed; inspect Error::effect before considering a retry\n";
        }
        publisher->close();
    }

    client->close();
    return client->wait(std::chrono::seconds(5)) ? result : 1;
}
```

`Client::open` performs local validation and asynchronous admission; it does not prove server readiness. Update confirms only the attached Star's
commit. The record expires unless explicitly updated again. Closing the Publisher does not delete the record. Release packaging does not execute this
example.

## Roles and data

| Factory | Use |
| --- | --- |
| `client.reader(scope)` | Almanac `watch`, `state`, `changed`, `stop` |
| `client.subscriber(scope)` | Catalog `watch`, `state`, `changed`, `stop` |
| `client.publisher(scope)` | Synchronous atomic `update`; explicit TTL per call |
| `client.observer(scope)` | Local Ephemeris selection with `one`, then `stop` |
| `client.beacon(scope, attr, data, ttl, beat)` | Synchronous initial registration; `update`, optional `tick`, beat renewal and `destroy` |

`comet::Value` is shared immutable byte storage. A null pointer is not an empty value. Reader/Subscriber publish complete views, not partial pages or
batches. Exact-key absence is distinct from unready/stale state. Observer local estimates do not write remote data.

Beacon requires `0 < beat < ttl`; Attr, TTL and beat remain fixed. Update changes full Data. Recovery preserves the existing handle's logical ID and
last confirmed data, not failed updates or arbitrary external UUID ownership.

## Errors and lifetime

TLS and API authentication default to enabled. `Options::ca` is an explicit runtime PEM file and takes precedence over an optional build-time
`COMET_CA_FILE`; otherwise the runtime's default trust roots apply. TLS and authentication failures never trigger automatic downgrade.

Publisher TTL is 1 second through 10 minutes. Update timeout defaults to three seconds and accepts `(0, 1 minute]`. One deadline covers connection,
version preparation and bounded conflict repair. Overlapping calls on one Publisher return `busy`.

Inspect `Error::code` and `Error::effect` separately. `unknown` may mean the operation committed without a delivered receipt. Failed payloads are not
replayed in the background. `Client::secret` updates the same API key's secret for later authentication, not server-side credential storage.

Client copies share ownership. Business handles have their own lifetimes; destroying one does not close other roles. `close`, `stop` and `destroy`
prevent new work immediately, while actual network/callback cleanup completes later. Call `Client::wait` outside callbacks after closing and give it a
finite budget.

Callbacks run outside internal state locks; different roles can notify concurrently. Keep callbacks fast, avoid synchronous SDK writes and never wait
for cleanup from an SDK callback. Application context must outlive already-started callbacks. Beacon unregister is bounded best effort; remote expiry
can outlast local destruction.

The versioned [public headers](include/comet) define overloads, ownership and error values.
See [protocol contracts](../../proto/README.md) for the underlying boundaries.
