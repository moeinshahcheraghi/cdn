# Validation results

## Initial validation (2026-11-06)

Base: v4 merge `7c5b50a`, with the feature changes described below.

* `go test -race -json -count=1 -timeout 10m ./...`: exit 0;
  86 passing test/subtest events, 2 skipped events, no failing package.
  The skips were the opt-in raw injection test and external REALITY test.
* The raw injection test then passed separately, including `-race -count=1`,
  in an isolated user/network namespace with only loopback enabled. Real
  packet injection did not corrupt or prefix the application's TCP payload.
* `make vet`, native Linux amd64 build, Linux arm64 cross-build, shell syntax
  check and `git diff --check`: passed. ARM64 binaries were compiled, not run.
* Compiled amd64 client/server: local HTTP and SOCKS5 forwarding passed with
  TLS certificate verification enabled.
* Five browser profiles were checked over actual local TLS connections for
  both HTTP/2 and WebSocket request headers.
* DPI lab tests covered fake SNI versus sequence-aware observation,
  fragmentation reassembly, the emitted ECH outer ClientHello, and encrypted
  transfers on direct TLS, local WebSocket/CDN and HTTP/2/CDN paths.

The full suite includes congestion, route failure, stream resumption, auto-IP
switching, HTTP carrier and WebSocket scenarios. Passed observer tests establish
the visibility limits described in DPI-REVIEW.md, not undetectability.

Remaining validation: live external REALITY, actual Cloudflare behavior,
OpenVPN deployment traffic, Iranian networks, and a multi-hour field soak.
No four-hour reliability or universal whitelist-bypass claim is supported.

Normal environment execution cannot create raw sockets (`CAP_NET_RAW` absent).
The isolated namespace test succeeds without altering host routes or sending
packets to an external destination; see README.md for its exact invocation.

## Pre-publication recheck (2026-11-07)

* `go test -race -count=1 -timeout 10m ./...`: **failed** in
  `TestRotationKeepsStreamsAlive` (`internal/tunnel/rotate_test.go:71`):
  `user stream corrupted: n=0 err=<nil>`. Other packages passed. This run
  does not support an all-tests-passing claim; the rotation failure remains
  unresolved. A targeted follow-up with `go test -race -count=10 -timeout 3m
  -run '^TestRotationKeepsStreamsAlive$' ./internal/tunnel` passed all ten
  repetitions; this does not erase the full-suite failure.
* `make vet all linux-arm64`: passed. ARM64 was compiled, not executed.
* `bash -n scripts/cf-scan.sh`, `git diff --cached --check`, formatting checks,
  local README links, and the external-forwarder JSON example: passed.
* Native fake-SNI loopback integration with `-race -count=1`: passed again
  inside an isolated user/network namespace. No external injection was run.
* Persian build, configuration, fake-SNI, echo-transfer and Cloudflare-scanning
  instructions were added to the main README.
