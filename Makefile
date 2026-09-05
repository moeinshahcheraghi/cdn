BINDIR := bin
LDFLAGS := -s -w

.PHONY: all server client test vet clean linux-amd64 linux-arm64

all: server client

server:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tunnel-server ./cmd/server

client:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tunnel-client ./cmd/client

test:
	go test ./...

vet:
	go vet ./...

# Cross builds for common server/client targets.
linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tunnel-server-linux-amd64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tunnel-client-linux-amd64 ./cmd/client

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tunnel-server-linux-arm64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tunnel-client-linux-arm64 ./cmd/client

clean:
	rm -rf $(BINDIR)
