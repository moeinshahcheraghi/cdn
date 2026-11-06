module github.com/moeinshah0/tunnel

go 1.25.0

require (
	github.com/refraction-networking/utls v1.8.2
	github.com/xtaci/smux v1.5.57
	github.com/xtls/reality v0.0.0-20260908042918-393f8de3ee2d
	golang.org/x/crypto v0.48.0
	golang.org/x/net v0.49.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)

replace github.com/xtaci/smux => ./third_party/smux
