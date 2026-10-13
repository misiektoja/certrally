// Package pemfile reads certificates, requests and keys from files and writes results safely.
package pemfile

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// ReadCertificates reads every certificate in a PEM file, or the single certificate in a DER file.
func ReadCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the user names the file to read.
	if err != nil {
		return nil, err
	}
	ders, err := decodeAll(data, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	certs := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: certificate %d: %w", path, i+1, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ReadCSR reads a PKCS#10 certificate request in PEM or DER form and returns its DER encoding.
// crypto/x509 parses composite ML-DSA requests without their key, which is enough here.
func ReadCSR(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the user names the file to read.
	if err != nil {
		return nil, err
	}
	ders, err := decodeAll(data, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(ders) != 1 {
		return nil, fmt.Errorf("%s: holds %d certificate requests, want 1", path, len(ders))
	}
	if _, err := x509.ParseCertificateRequest(ders[0]); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ders[0], nil
}

// decodeAll returns the DER content of every PEM block of the wanted types. Data without any PEM
// block is treated as a single DER value. Blocks of other types are an error, so that a key passed
// where a certificate is expected is reported rather than ignored.
func decodeAll(data []byte, types ...string) ([][]byte, error) {
	var ders [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if !slices.Contains(types, block.Type) {
			return nil, fmt.Errorf("unexpected PEM block %q, want %s", block.Type, types[0])
		}
		ders = append(ders, block.Bytes)
	}
	if ders != nil {
		return ders, nil
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return nil, errors.New("malformed PEM data")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("file is empty")
	}
	return [][]byte{data}, nil
}

// EncodeCertificates returns certs as concatenated PEM blocks.
func EncodeCertificates(certs []*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

// CheckWritable reports an error if a later Write to path would fail because the file exists and
// overwrite is false, or because the directory does not exist. Checking before a request is sent
// avoids getting a certificate issued that cannot be saved.
func CheckWritable(path string, overwrite bool) error {
	info, err := os.Stat(path)
	switch {
	case err == nil && info.IsDir():
		return fmt.Errorf("%s is a directory", path)
	case err == nil && !overwrite:
		return fmt.Errorf("%s already exists, use --force to replace it", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// Write stores data at path with the given permissions. The data is written to a temporary file in
// the same directory first, so a reader never sees a partial file. Without overwrite, an existing
// file is left alone and an error is returned.
func Write(path string, data []byte, perm fs.FileMode, overwrite bool) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if overwrite {
		return os.Rename(tmpName, path)
	}
	// A hard link fails if path exists, which makes the no-clobber check and the write one step.
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists, use --force to replace it", path)
		}
		return err
	}
	return os.Remove(tmpName)
}
