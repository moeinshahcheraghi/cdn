package config

import "testing"

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
