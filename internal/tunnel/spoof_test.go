package tunnel

import (
	"github.com/moeinshah0/tunnel/internal/config"
	"testing"
)

func TestFakeSNIRouteIsolation(t *testing.T) {
	cfg := &config.ClientConfig{
		Server: "192.0.2.1:443", SNI: "cdn.example", FakeSNI: "chatgpt.com",
		WS: config.WSClientConfig{Path: "/test-path", Host: "cdn.example"},
		Backups: []config.Backup{
			{Server: "192.0.2.2:443", SNI: "backup.example"},
			{Server: "192.0.2.3:443", SNI: "third.example", FakeSNI: "example.org"},
		},
	}
	eps := Endpoints(cfg)
	if len(eps) != 3 || eps[0].FakeSNI != "chatgpt.com" || eps[1].FakeSNI != "" || eps[2].FakeSNI != "example.org" {
		t.Fatalf("fake SNI not isolated by route: %+v", eps)
	}
	if eps[0].SNI != "cdn.example" || eps[0].WS.Host != "cdn.example" || eps[0].AllowInsecure {
		t.Fatal("fake SNI changed actual TLS/HTTP identity or verification")
	}
}
