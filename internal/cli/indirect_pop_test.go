package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/capture"
	"github.com/misiektoja/certrally/internal/keys"
)

// requireCertifiesKey checks that cert certifies the key in keyFile, for any key type including
// ML-KEM, whose public keys have no Equal method.
func requireCertifiesKey(t *testing.T, cert *x509.Certificate, keyFile string) {
	t.Helper()
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want, err := keys.MarshalPublicKey(keys.Public(key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, want) {
		t.Errorf("the certificate does not certify the key in %s", keyFile)
	}
}

// startIndirectMock starts certrally mock with both indirect proofs of possession accepted.
func startIndirectMock(t *testing.T, args ...string) *mockRun {
	t.Helper()
	return startMock(t, append([]string{"--listen", "127.0.0.1:0", "--ref", testRef,
		"--accept", "encrypted-cert-pop", "--accept", "challenge-pop"}, args...)...)
}

// TestEnrollMLKEM enrolls generated ML-KEM keys with both indirect proofs of possession and every
// request type that carries a CRMF request.
func TestEnrollMLKEM(t *testing.T) {
	useSecret(t, testSecret)
	m := startIndirectMock(t)
	tests := []struct {
		keyType, pop, reqType string
		wantPOP, wantLadder   string
	}{
		{"ml-kem-768", "", typeIR, "encrypted certificate", "ip  accepted"},
		{"ml-kem-1024", popEncryptedCert, typeCR, "encrypted certificate", "cp  accepted"},
		{"ml-kem-768", popChallenge, typeIR, "encrypted challenge", "popdecc"},
	}
	for _, tt := range tests {
		t.Run(tt.keyType+"/"+tt.pop+"/"+tt.reqType, func(t *testing.T) {
			dir := t.TempDir()
			certOut, keyOut := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
			args := []string{"enroll", "--server", m.url, "--ref", testRef, "--type", tt.reqType,
				"--subject", "CN=kem-device", "--key-type", tt.keyType, "--cert-out", certOut, "--key-out", keyOut}
			if tt.pop != "" {
				args = append(args, "--pop", tt.pop)
			}
			code, out, errOut := run(t, args...)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s%s", code, out, errOut)
			}
			cert := readCert(t, certOut)
			requireCertifiesKey(t, cert, keyOut)
			if cert.KeyUsage != x509.KeyUsageKeyEncipherment {
				t.Errorf("key usage = %v, want keyEncipherment", cert.KeyUsage)
			}
			for _, want := range []string{"Proof of possession", tt.wantPOP, strings.ToUpper(tt.keyType)} {
				if !strings.Contains(out, want) {
					t.Errorf("report lacks %q:\n%s", want, out)
				}
			}
			if !errorContains(errOut, tt.wantLadder) {
				t.Errorf("ladder lacks %q:\n%s", tt.wantLadder, errOut)
			}
		})
	}
}

// TestEnrollMLKEMNewKey certifies an ML-KEM key from keygen with --new-key, reports the method in
// --json and renews an ECDSA certificate with a kur for a new ML-KEM key.
func TestEnrollMLKEMNewKey(t *testing.T) {
	useSecret(t, testSecret)
	m := startIndirectMock(t)
	dir := t.TempDir()
	kemKey := filepath.Join(dir, "kem.key")
	if code, _, errOut := run(t, "keygen", "--key-type", "ml-kem-768", "--out", kemKey); code != exitOK {
		t.Fatalf("keygen exited with %d:\n%s", code, errOut)
	}
	kemCert := filepath.Join(dir, "kem.pem")
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=kem",
		"--new-key", kemKey, "--pop", popChallenge, "--cert-out", kemCert, "--json")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s%s", code, out, errOut)
	}
	requireCertifiesKey(t, readCert(t, kemCert), kemKey)
	var doc struct {
		Result enrollJSON `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Result.ProofOfPossession != popChallenge {
		t.Errorf("proofOfPossession = %q, want %q", doc.Result.ProofOfPossession, popChallenge)
	}

	oldCert, oldKey := enrollIR(t, &testCA{url: m.url}, "--subject", "CN=renewed")
	newCert, newKey := filepath.Join(dir, "new.pem"), filepath.Join(dir, "new.key")
	code, out, errOut = run(t, "enroll", "--server", m.url, "--type", typeKUR, "--cert", oldCert, "--key", oldKey,
		"--key-type", "ml-kem-1024", "--cert-out", newCert, "--key-out", newKey)
	if code != exitOK {
		t.Fatalf("kur exited with %d:\n%s%s", code, out, errOut)
	}
	cert := readCert(t, newCert)
	requireCertifiesKey(t, cert, newKey)
	if cert.Subject.String() != "CN=renewed" {
		t.Errorf("subject = %q", cert.Subject)
	}
	if !errorContains(errOut, "kup  accepted") {
		t.Errorf("ladder:\n%s", errOut)
	}

	// The ML-KEM key cannot sign the protection of another request.
	code, _, errOut = run(t, "enroll", "--server", m.url, "--type", typeCR, "--cert", newCert, "--key", newKey,
		"--cert-out", filepath.Join(dir, "x.pem"), "--key-out", filepath.Join(dir, "x.key"))
	if code != exitLocal || !errorContains(errOut, "an ML-KEM-1024 key cannot sign") {
		t.Errorf("exited with %d, want 1 and the key refused:\n%s", code, errOut)
	}
}

// TestEnrollMLKEMUsage checks the command lines that combine --pop or an ML-KEM key with what
// cannot use them. None of them reaches the CA.
func TestEnrollMLKEMUsage(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	out, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	kemKey, ecKey, csr := filepath.Join(dir, "kem.key"), filepath.Join(dir, "ec.key"), filepath.Join(dir, "ec.csr")
	if code, _, errOut := run(t, "keygen", "--key-type", "ml-kem-768", "--out", kemKey); code != exitOK {
		t.Fatalf("keygen exited with %d:\n%s", code, errOut)
	}
	if code, _, errOut := run(t, "keygen", "--out", ecKey, "--csr-out", csr, "--subject", "CN=a"); code != exitOK {
		t.Fatalf("keygen exited with %d:\n%s", code, errOut)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"pop with a generated signing key", []string{"--pop", popChallenge, "--key-out", key},
			"ecdsa-p256 keys sign their proof of possession"},
		{"pop with a signing new key", []string{"--pop", popEncryptedCert, "--new-key", ecKey},
			"ECDSA P-256 keys sign their proof of possession"},
		{"invalid pop", []string{"--key-type", "ml-kem-768", "--pop", "decrypt", "--key-out", key}, "invalid --pop"},
		{"pop with csr", []string{"--type", typeP10CR, "--csr", csr, "--pop", popChallenge}, "--csr is signed"},
		{"generated key for p10cr", []string{"--type", typeP10CR, "--key-type", "ml-kem-1024", "--key-out", key},
			"ml-kem-1024 keys cannot sign"},
		{"new key for p10cr", []string{"--type", typeP10CR, "--new-key", kemKey}, "ML-KEM-768 keys cannot sign"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"enroll", "--server", ca.url, "--ref", testRef, "--cert-out", out}, tt.args...)
			code, _, errOut := run(t, args...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want 1 and %q in:\n%s", code, tt.want, errOut)
			}
		})
	}
	if n := ca.requests.Load(); n != 0 {
		t.Errorf("the CA received %d requests", n)
	}
}

// TestEnrollMLKEMRefused checks the report when the CA does not accept an indirect proof of possession.
func TestEnrollMLKEMRefused(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	dir := t.TempDir()
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=kem",
		"--key-type", "ml-kem-768", "--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"))
	if code != exitRejected || !errorContains(out+errOut, pkicmp.FailBadPOP.String()) {
		t.Errorf("exited with %d, want %d with badPOP:\n%s%s", code, exitRejected, out, errOut)
	}
}

// TestPollMLKEM checks that poll decrypts the waiting certificate of an ML-KEM key with the key that
// enroll saved, and with --new-key once that file has moved.
func TestPollMLKEM(t *testing.T) {
	useSecret(t, testSecret)
	m := startIndirectMock(t, "--waiting", "1", "--check-after", "0s")
	dir := t.TempDir()
	t.Chdir(dir)
	later := func(name string) string {
		t.Helper()
		code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN="+name,
			"--key-type", "ml-kem-768", "--cert-out", name+".pem", "--key-out", name+".key",
			"--poll-later", "--capture", name+".jsonl")
		if code != exitOK || !strings.Contains(out, "Request waiting for the CA") {
			t.Fatalf("enroll exited with %d:\n%s%s", code, out, errOut)
		}
		return transactionIDIn(t, out)
	}

	id := later("saved")
	code, out, errOut := run(t, "poll", "--transaction-id", id, "--capture", "saved.jsonl")
	if code != exitOK || !strings.Contains(out, "encrypted certificate") {
		t.Fatalf("poll exited with %d:\n%s%s", code, out, errOut)
	}
	requireCertifiesKey(t, readCert(t, "saved.pem"), "saved.key")

	id = later("moved")
	if err := os.Rename("moved.key", "elsewhere.key"); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", "moved.jsonl")
	if code != exitLocal || !errorContains(errOut, "name that key with --new-key") {
		t.Errorf("poll without the key exited with %d:\n%s", code, errOut)
	}
	if got := lastTransactionState(t, "moved.jsonl", id); got != capture.TransactionWaiting {
		t.Errorf("the transaction is recorded as %q, want waiting", got)
	}
	code, out, errOut = run(t, "poll", "--transaction-id", id, "--capture", "moved.jsonl", "--new-key", "elsewhere.key")
	if code != exitOK {
		t.Fatalf("poll --new-key exited with %d:\n%s%s", code, out, errOut)
	}
	requireCertifiesKey(t, readCert(t, "moved.pem"), "elsewhere.key")
}

// TestPollNewKeyUnused checks that poll refuses --new-key for a request whose key signs.
func TestPollNewKeyUnused(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	t.Chdir(t.TempDir())
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=ec",
		"--cert-out", "ec.pem", "--key-out", "ec.key", "--poll-later", "--capture", "ec.jsonl")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s%s", code, out, errOut)
	}
	code, _, errOut = run(t, "poll", "--transaction-id", transactionIDIn(t, out), "--capture", "ec.jsonl",
		"--new-key", "ec.key")
	if code != exitLocal || !errorContains(errOut, "--new-key is only used") {
		t.Errorf("exited with %d:\n%s", code, errOut)
	}
}

// TestKeygenMLKEM checks the key and public key files of ML-KEM keys and that they get no request.
func TestKeygenMLKEM(t *testing.T) {
	isolateColorEnv(t)
	dir := t.TempDir()
	for _, keyType := range []string{"ml-kem-768", "ml-kem-1024"} {
		keyOut, pubOut := filepath.Join(dir, keyType+".key"), filepath.Join(dir, keyType+".pub")
		code, out, errOut := run(t, "keygen", "--key-type", keyType, "--out", keyOut, "--pub-out", pubOut)
		if code != exitOK || !strings.Contains(out, strings.ToUpper(keyType)) {
			t.Fatalf("%s: exited with %d:\n%s%s", keyType, code, out, errOut)
		}
		pub, err := pkicmp.ParsePublicKey(readPEM(t, pubOut, "PUBLIC KEY"))
		if err != nil {
			t.Fatal(err)
		}
		if got := keys.Describe(pub); got != strings.ToUpper(keyType) {
			t.Errorf("public key file holds %s", got)
		}
		requireCertifiesKey(t, &x509.Certificate{RawSubjectPublicKeyInfo: readPEM(t, pubOut, "PUBLIC KEY")}, keyOut)
	}
	csrOut := filepath.Join(dir, "r.csr")
	code, _, errOut := run(t, "keygen", "--key-type", "ml-kem-768", "--out", filepath.Join(dir, "x.key"),
		"--csr-out", csrOut, "--subject", "CN=a")
	if code != exitLocal || !errorContains(errOut, "cannot write a request") {
		t.Errorf("exited with %d:\n%s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.key")); !os.IsNotExist(err) {
		t.Errorf("a key was written for a refused command line: %v", err)
	}
}

// TestWizardMLKEM checks that the wizard refuses an ML-KEM key as the signing --key and offers
// ML-KEM key types with a hint.
func TestWizardMLKEM(t *testing.T) {
	isolateColorEnv(t)
	kemKey := filepath.Join(t.TempDir(), "kem.key")
	if code, _, errOut := run(t, "keygen", "--key-type", "ml-kem-768", "--out", kemKey); code != exitOK {
		t.Fatalf("keygen exited with %d:\n%s", code, errOut)
	}
	if err := checkKey(kemKey); err == nil || !strings.Contains(err.Error(), "cannot sign") {
		t.Errorf("checkKey error = %v", err)
	}
	if keyTypeHint("ml-kem-1024") == "" {
		t.Error("ml-kem-1024 has no hint")
	}
}
