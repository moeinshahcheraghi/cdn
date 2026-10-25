package transport

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

// ECH (Encrypted Client Hello) hides the real server name. The censor sees
// only the CDN's shared public name (cloudflare-ech.com on Cloudflare); the
// domain itself travels encrypted to the CDN, which routes on it as usual.
//
// Why: a censor that lets only names it knows through can stall every
// connection to a new domain right after the handshake, whatever the IP or
// the protocol inside. With ECH no new domain is ever visible.
//
// The keys come from the domain's DNS HTTPS record and are rotated by the
// CDN. A stale key is not a problem: the CDN refuses it, hands back its
// current keys over a handshake checked against the public name, and the
// next attempt uses them.
type ECH struct {
	mu   sync.Mutex
	list []byte // serialized ECHConfigList
}

// NewECH starts from list, a serialized ECHConfigList (see ParseECHList).
func NewECH(list []byte) *ECH { return &ECH{list: list} }

// ParseECHList accepts an ECHConfigList in base64, or a whole HTTPS record
// as printed by `dig +short HTTPS domain`, from which the ech= value is taken.
func ParseECHList(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "ech="); i >= 0 {
		s = s[i+len("ech="):]
		if j := strings.IndexAny(s, " \t\""); j >= 0 {
			s = s[:j]
		}
	}
	b, err := base64.StdEncoding.DecodeString(strings.Trim(s, "\""))
	if err != nil || len(b) < 4 {
		return nil, fmt.Errorf("not an ECHConfigList (run: dig +short HTTPS your.domain, and copy the ech= value)")
	}
	return b, nil
}

func (e *ECH) get() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.list
}

// deferRejection is uTLS's hook for checking the certificate of a handshake
// in which the CDN refused our keys. uTLS calls it before it has recorded
// the certificates, so it lets the handshake finish; checkRejection then
// verifies them before any returned keys are believed.
func deferRejection(utls.ConnectionState) error { return nil }

// checkRejection verifies, after the CDN refused our keys, that the
// certificate it presented is valid for the public name the refused
// handshake ran under. Only then are the keys it sent back trusted.
func (e *ECH) checkRejection(certs []*x509.Certificate) error {
	name := publicName(e.get())
	if name == "" || len(certs) == 0 {
		return errors.New("ech: refused, and nothing to verify the new keys with")
	}
	opts := x509.VerifyOptions{DNSName: name, Intermediates: x509.NewCertPool()}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("ech: refused by a server not valid for %s: %w", name, err)
	}
	return nil
}

// publicName returns the public name of the first config in an
// ECHConfigList, or "" if it cannot be read.
func publicName(list []byte) string {
	s := cryptobyte.String(list)
	var configs, body cryptobyte.String
	var version uint16
	if !s.ReadUint16LengthPrefixed(&configs) || !configs.ReadUint16(&version) ||
		!configs.ReadUint16LengthPrefixed(&body) {
		return ""
	}
	var id uint8
	var kem uint16
	var key, suites, name cryptobyte.String
	var maxLen uint8
	if !body.ReadUint8(&id) || !body.ReadUint16(&kem) ||
		!body.ReadUint16LengthPrefixed(&key) || !body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8(&maxLen) || !body.ReadUint8LengthPrefixed(&name) {
		return ""
	}
	return string(name)
}

// update adopts the keys the CDN sent back with a rejection, and reports
// whether there were any.
func (e *ECH) update(err error) bool {
	var rej *utls.ECHRejectionError
	if !errors.As(err, &rej) || len(rej.RetryConfigList) == 0 {
		return false
	}
	e.mu.Lock()
	e.list = rej.RetryConfigList
	e.mu.Unlock()
	return true
}
