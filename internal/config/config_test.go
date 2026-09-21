package config

import (
	"os"
	"testing"
)

func TestCleanHost(t *testing.T) {
	cases := map[string]string{
		"[www.microsoft.com:443](https://www.microsoft.com:443)": "www.microsoft.com:443",
		"[www.microsoft.com](https://www.microsoft.com)":         "www.microsoft.com",
		" 91.107.153.68:443 ":                                    "91.107.153.68:443",
		"example.com":                                            "example.com",
	}
	for in, want := range cases {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// write puts s in a temp file and returns its path.
func write(t *testing.T, s string) string {
	t.Helper()
	p := t.TempDir() + "/cfg.json"
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A mistake in a config must be named on startup, not discovered in the
// field as "it just doesn't connect".
func TestServerConfigRejectsUnworkableCombinations(t *testing.T) {
	cases := map[string]string{
		"reality with a websocket but no separate port": `{"passwords":["x"],
			"reality":{"dest":"a.com:443","server_names":["a.com"],"private_key":"k"},
			"ws":{"path":"/a-secret-path"}}`,
		"websocket port without a path": `{"passwords":["x"],"ws":{"listen":":8443"}}`,
		"guessable websocket path":      `{"passwords":["x"],"ws":{"path":"/ws"}}`,
		"no password":                   `{"listen":":443"}`,
	}
	for name, body := range cases {
		if _, err := LoadServer(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The same file with its own websocket port is fine.
	ok := `{"passwords":["x"],"reality":{"dest":"a.com:443","server_names":["a.com"],"private_key":"k"},
		"ws":{"path":"/a-secret-path","listen":":8443"}}`
	if _, err := LoadServer(write(t, ok)); err != nil {
		t.Errorf("reality + ws on its own port: %v", err)
	}
}

func TestClientConfigBackups(t *testing.T) {
	c, err := LoadClient(write(t, `{
		"server":"1.2.3.4:443","password":"p","sni":"www.microsoft.com",
		"reality":{"public_key":"K","short_id":"ab"},
		"backups":[{"server":"cdn.example.com:443","sni":"cdn.example.com",
		            "ws":{"path":"/a-secret-path"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Backups) != 1 || c.Backups[0].WS.Path != "/a-secret-path" {
		t.Fatalf("backup not loaded: %+v", c.Backups)
	}
	// A backup with no fingerprint inherits the primary's.
	if c.Backups[0].Fingerprint != c.Fingerprint {
		t.Errorf("backup fingerprint %q, want the primary's %q", c.Backups[0].Fingerprint, c.Fingerprint)
	}
	// REALITY and a websocket cannot share one route.
	if _, err := LoadClient(write(t, `{"server":"1.2.3.4:443","password":"p",
		"reality":{"public_key":"K"},"ws":{"path":"/a-secret-path"}}`)); err == nil {
		t.Error("reality+ws on one route was accepted")
	}
}
