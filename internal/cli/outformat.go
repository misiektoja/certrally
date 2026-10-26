package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/spf13/cobra"
	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
)

// flagOutFormat names the flag that chooses the encoding of the files a command writes.
const flagOutFormat = "out-format"

// The values of --out-format.
const (
	formatPEM = "pem"
	formatDER = "der"
)

// Help texts of --out-format.
const (
	outFormatHelp      = "format of the output files: pem or der"
	outFormatChainHelp = "format of the output files: pem or der, which writes the chain as PKCS#7"
	outFormatCertsHelp = "format of the --out file: pem or der, which writes the certificates as PKCS#7"
	outFormatOutHelp   = "format of the --out file: pem or der"
)

// outFormat holds --out-format, the encoding of the certificates, keys and requests a command
// saves. The zero value and formatPEM write PEM.
type outFormat struct {
	name string
}

// addFlags registers --out-format with the default def, which is empty where the format comes
// from elsewhere when the flag is left out.
func (f *outFormat) addFlags(cmd *cobra.Command, def, help string) {
	cmd.Flags().StringVar(&f.name, flagOutFormat, def, help)
	_ = cmd.RegisterFlagCompletionFunc(flagOutFormat, fixedCompletion([]string{formatPEM, formatDER}))
}

// validate checks the value of --out-format.
func (f *outFormat) validate() error {
	switch f.name {
	case "", formatPEM, formatDER:
		return nil
	}
	return fmt.Errorf("invalid --out-format %q, want pem or der", f.name)
}

// der reports whether the files are written as DER.
func (f *outFormat) der() bool { return f.name == formatDER }

// block returns der as a PEM block of type typ, or unchanged for DER output.
func (f *outFormat) block(typ string, der []byte) []byte {
	if f.der() {
		return der
	}
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// certificate encodes one certificate.
func (f *outFormat) certificate(cert *x509.Certificate) []byte {
	return f.block("CERTIFICATE", cert.Raw)
}

// certificates encodes certs as concatenated PEM blocks or, for DER output, as one PKCS#7
// SignedData that carries only the certificates, the form that openssl crl2pkcs7 -nocrl writes.
func (f *outFormat) certificates(certs []*x509.Certificate) ([]byte, error) {
	if !f.der() {
		return pemfile.EncodeCertificates(certs), nil
	}
	size := 0
	for _, cert := range certs {
		size += len(cert.Raw)
	}
	raw := make([]byte, 0, size)
	for _, cert := range certs {
		raw = append(raw, cert.Raw...)
	}
	data, err := pkcs7.DegenerateCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("encode PKCS#7: %w", err)
	}
	return data, nil
}

// key encodes a private key as unencrypted PKCS#8.
func (f *outFormat) key(key crypto.Signer) ([]byte, error) {
	if f.der() {
		return keys.Marshal(key)
	}
	return keys.MarshalPEM(key)
}
