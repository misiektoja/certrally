package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misiektoja/certrally/internal/secret"
)

// An ECDSA P-256 key as openssl pkcs8 -topk8 writes it, PBES2 with AES-256-CBC and PBKDF2 with
// hmacWithSHA256, encrypted with encryptedKeyPassword, and the SubjectPublicKeyInfo of that key.
const (
	encryptedKeyPassword = "correct-horse"
	encryptedPKCS8DER    = "3081f4305f06092a864886f70d01050d3052303106092a864886f70d01050c30240410c887802b878abb4ddf64" +
		"578365a0e5df02020800300c06082a864886f70d02090500301d060960864801650304012a041067d4ef2ad6f8633d9e5b3ca02b" +
		"9364b4048190fb5855891abf211f73a346bdf6b5d9cfd1873d7f122b84d8d9804bb3a38dea490bd01cd65700c6c2f538178254" +
		"e74a3352979917377263753e677f38eb1f35ceb5c4a9421418958ba3b7fdb3397b1f9243ecac7ab46dc7df777c8723937f05c5" +
		"8f8418a5e4f855387b5dd0a85ca31e065a830d6a9629cbc9ae79a82d97db382871a3c5deb9da088988d7e918f5fd07c1"
	encryptedPKCS8Public = "3059301306072a8648ce3d020106082a8648ce3d03010703420004071cfd327039d9d3b35614cfc74132d37e57" +
		"765aa1f78c64e11ed0ca00e424bcc3b01d01710048bdb8974415983737a5b7f7f0f890824a6c4a58c0e783a5637d"
)

// encryptedKeyFiles writes the encrypted key and a file with its password and returns their paths.
func encryptedKeyFiles(t *testing.T) (keyFile, passwordFile string) {
	t.Helper()
	dir := t.TempDir()
	der, err := hex.DecodeString(encryptedPKCS8DER)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, passwordFile = filepath.Join(dir, "device.p8"), filepath.Join(dir, "password.txt")
	writeFile(t, keyFile, der)
	writeFile(t, passwordFile, []byte(encryptedKeyPassword+"\n"))
	return keyFile, passwordFile
}

// useKeyPassword makes the key password available through the environment, or removes it when empty.
func useKeyPassword(t *testing.T, value string) {
	t.Helper()
	t.Setenv(secret.KeyPasswordEnvVar, value)
	if value == "" {
		if err := os.Unsetenv(secret.KeyPasswordEnvVar); err != nil {
			t.Fatal(err)
		}
	}
}

// checkEncryptedKeyCert checks that the certificate in path was issued for the encrypted key.
func checkEncryptedKeyCert(t *testing.T, path string) {
	t.Helper()
	der, err := hex.DecodeString(encryptedPKCS8Public)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := readCert(t, path)
	if !cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
		t.Errorf("%s is not for the encrypted key", path)
	}
}

// TestEncryptedKeyCMP checks that enroll takes an encrypted key as --new-key with the password from
// --key-password-file and as --key with the password from CERTRALLY_KEY_PASSWORD, and the errors
// for a wrong or missing password.
func TestEncryptedKeyCMP(t *testing.T) {
	useSecret(t, testSecret)
	useKeyPassword(t, "")
	ca := startCA(t, nil)
	keyFile, passwordFile := encryptedKeyFiles(t)
	dir := t.TempDir()
	certOut := filepath.Join(dir, "cert.pem")
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--new-key", keyFile,
		"--key-password-file", passwordFile, "--cert-out", certOut)
	if code != exitOK {
		t.Fatalf("enroll --new-key exited with %d:\n%s", code, errOut)
	}
	checkEncryptedKeyCert(t, certOut)

	t.Run("kur from environment", func(t *testing.T) {
		useKeyPassword(t, encryptedKeyPassword)
		newCert := filepath.Join(t.TempDir(), "cert.pem")
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--type", "kur", "--cert", certOut, "--key", keyFile,
			"--cert-out", newCert, "--key-out", filepath.Join(t.TempDir(), "key.pem"))
		if code != exitOK {
			t.Fatalf("enroll --type kur exited with %d:\n%s", code, errOut)
		}
		if readCert(t, newCert).Subject.String() != readCert(t, certOut).Subject.String() {
			t.Error("the kur certificate has another subject")
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		wrong := filepath.Join(t.TempDir(), "wrong.txt")
		writeFile(t, wrong, []byte("wrong-horse"))
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--new-key", keyFile,
			"--key-password-file", wrong, "--cert-out", filepath.Join(t.TempDir(), "cert.pem"))
		if code != exitLocal || !errorContains(errOut, "wrong password") {
			t.Errorf("exited with %d, want 1 and wrong password in:\n%s", code, errOut)
		}
	})
	t.Run("missing password", func(t *testing.T) {
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--new-key", keyFile,
			"--cert-out", filepath.Join(t.TempDir(), "cert.pem"))
		if code != exitLocal || !errorContains(errOut, "is encrypted") || !errorContains(errOut, secret.KeyPasswordEnvVar) ||
			!errorContains(errOut, "--key-password-file") {
			t.Errorf("exited with %d, want 1 and the password sources in:\n%s", code, errOut)
		}
	})
	t.Run("standard input twice", func(t *testing.T) {
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--secret-file", "-",
			"--new-key", keyFile, "--key-password-file", "-", "--cert-out", filepath.Join(t.TempDir(), "cert.pem"))
		if code != exitLocal || !errorContains(errOut, "cannot both read standard input") {
			t.Errorf("exited with %d, want 1 and a usage error in:\n%s", code, errOut)
		}
	})
	t.Run("wizard accepts", func(t *testing.T) {
		if err := checkKey(keyFile); err != nil {
			t.Errorf("checkKey(%s) = %v", keyFile, err)
		}
	})
}

// TestEncryptedKeyEST checks that est enroll and est reenroll take an encrypted key.
func TestEncryptedKeyEST(t *testing.T) {
	usePassword(t, estTestPassword)
	useKeyPassword(t, "")
	srv := startESTServer(t, nil, nil, nil)
	keyFile, passwordFile := encryptedKeyFiles(t)
	certOut := filepath.Join(t.TempDir(), "cert.pem")
	code, _, errOut := run(t, srv.args("enroll", "--user", estTestUser, "--subject", "CN=dev-1", "--new-key", keyFile,
		"--key-password-file", passwordFile, "--cert-out", certOut)...)
	if code != exitOK {
		t.Fatalf("est enroll exited with %d:\n%s", code, errOut)
	}
	checkEncryptedKeyCert(t, certOut)
	useKeyPassword(t, encryptedKeyPassword)
	newCert := filepath.Join(t.TempDir(), "cert.pem")
	code, _, errOut = run(t, srv.args("reenroll", "--cert", certOut, "--key", keyFile, "--cert-out", newCert,
		"--key-out", filepath.Join(t.TempDir(), "key.pem"))...)
	if code != exitOK {
		t.Fatalf("est reenroll exited with %d:\n%s", code, errOut)
	}
	if readCert(t, newCert).Subject.CommonName != "dev-1" {
		t.Error("the renewed certificate has another subject")
	}
}

// TestEncryptedKeyPoll checks that poll decrypts the signing key of the enroll run with
// --key-password-file.
func TestEncryptedKeyPoll(t *testing.T) {
	useSecret(t, testSecret)
	useKeyPassword(t, encryptedKeyPassword)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	keyFile, passwordFile := encryptedKeyFiles(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "device.pem")
	code, _, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=device-42",
		"--new-key", keyFile, "--cert-out", certFile)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	useSecret(t, "")
	captureFile, certOut := filepath.Join(dir, "run.jsonl"), filepath.Join(dir, "second.pem")
	code, out, errOut := run(t, "enroll", "--server", m.url, "--cert", certFile, "--key", keyFile, "--type", "cr",
		"--subject", "CN=second", "--cert-out", certOut, "--key-out", filepath.Join(dir, "second.key"),
		"--poll-later", "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("enroll --poll-later exited with %d:\n%s", code, errOut)
	}
	useKeyPassword(t, "")
	id := transactionIDIn(t, out)
	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitLocal || !errorContains(errOut, "is encrypted") {
		t.Fatalf("poll without the password exited with %d, want 1 and is encrypted in:\n%s", code, errOut)
	}
	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile, "--key-password-file", passwordFile)
	if code != exitOK {
		t.Fatalf("poll exited with %d:\n%s", code, errOut)
	}
	if got := readCert(t, certOut).Subject.String(); got != "CN=second" {
		t.Errorf("subject = %q, want CN=second", got)
	}
}

// TestKeyPasswordStdin checks that --key-password-file - reads the password from standard input.
func TestKeyPasswordStdin(t *testing.T) {
	useKeyPassword(t, "")
	keyFile, _ := encryptedKeyFiles(t)
	k := &keyPassword{file: stdoutPath}
	if _, err := k.load(keyFile, strings.NewReader(encryptedKeyPassword+"\n"), io.Discard); err != nil {
		t.Errorf("load = %v", err)
	}
	if _, err := k.load(keyFile, strings.NewReader("wrong-horse\n"), io.Discard); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("load with a wrong password = %v", err)
	}
}
