package cli

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/ui"
)

// keygenOptions holds the keygen command line.
type keygenOptions struct {
	outputOptions
	keyType string
	out     string
	pubOut  string
	csrOut  string
	subject string
	sans    []string
	force   bool
	list    bool
}

// newKeygenCommand returns the keygen command.
func newKeygenCommand() *cobra.Command {
	o := &keygenOptions{}
	cmd := &cobra.Command{
		Use:   "keygen --out FILE [flags]",
		Short: "Generate a private key and optionally a certificate request",
		Long: "Generate a private key, including ML-DSA and composite ML-DSA keys. It is saved as unencrypted " +
			"PKCS#8 PEM with mode 0600. --csr-out also writes a PKCS#10 request for the key, for " +
			"enroll --type p10cr --csr or for another CA. --list prints every key type.",
		Example: "  certrally keygen --key-type ml-dsa-65 --out device.key\n" +
			"  certrally keygen --out device.key --csr-out device.csr --subject CN=device-42",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(_ *cobra.Command, _ []string, p *printer) error {
			return runKeygen(o, p)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&o.keyType, "key-type", keys.DefaultType,
		"type of the key, such as ecdsa-p384, rsa-3072, ml-dsa-65 or mldsa65-ecdsa-p256-sha512")
	f.StringVar(&o.out, "out", "", "write the private key to this file, or - for standard output")
	f.StringVar(&o.pubOut, "pub-out", "", "write the public key to this file")
	f.StringVar(&o.csrOut, "csr-out", "", "write a certificate request for the key to this file")
	f.StringVar(&o.subject, "subject", "", "subject name of the request, such as CN=device-42,O=Example")
	f.StringArrayVar(&o.sans, "san", nil, "subject alternative name of the request (repeatable)")
	f.BoolVar(&o.force, "force", false, "replace existing output files")
	f.BoolVar(&o.list, "list", false, "list the key types and exit")
	o.outputOptions.addFlags(cmd)
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(keys.TypeNames()))
	for _, name := range []string{"subject", "san"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// runKeygen performs the keygen command.
func runKeygen(o *keygenOptions, p *printer) error {
	if o.list {
		if p.text() {
			_, err := fmt.Fprintln(p.stdout, strings.Join(keys.TypeNames(), "\n"))
			return err
		}
		p.result("", nil, &keyTypesJSON{KeyTypes: keys.TypeNames()})
		return nil
	}
	if err := o.validate(); err != nil {
		return err
	}
	p.dataOnStdout = slices.Contains([]string{o.out, o.pubOut, o.csrOut}, stdoutPath)
	var subject pkix.Name
	if o.subject != "" {
		var err error
		if subject, err = dn.ParseName(o.subject); err != nil {
			return fmt.Errorf("--subject: %w", err)
		}
	}
	extensions, err := sanExtensions(o.sans, o.subject != "")
	if err != nil {
		return err
	}
	key, err := keys.Generate(o.keyType)
	if err != nil {
		return err
	}
	keyPEM, err := keys.MarshalPEM(key)
	if err != nil {
		return err
	}
	pubDER, err := compositex509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	result := &keygenJSON{KeyType: o.keyType, Key: keys.Describe(key.Public()), PublicKey: pemString("PUBLIC KEY", pubDER)}
	if o.csrOut != "" {
		der, err := createCSR(subject, extensions, key)
		if err != nil {
			return err
		}
		result.CSR = pemString("CERTIFICATE REQUEST", der)
	}

	// The private key is written first, so that no request or public key exists without it.
	outputs := []struct {
		path string
		data []byte
		perm fs.FileMode
	}{{o.out, keyPEM, 0o600}, {o.pubOut, []byte(result.PublicKey), 0o644}, {o.csrOut, []byte(result.CSR), 0o644}}
	for _, out := range outputs {
		if out.path == "" {
			continue
		}
		if err := writeData(out.path, out.data, out.perm, o.force, p.stdout); err != nil {
			return err
		}
	}
	result.Saved = savedPaths(o.out, o.pubOut, o.csrOut)
	p.result("Key generated", []ui.Field{
		{Name: fieldKey, Value: result.Key},
		{Name: fieldSaved, Value: strings.Join(result.Saved, ", ")},
	}, result)
	return nil
}

// validate checks flag combinations and the outputs before a key is generated.
func (o *keygenOptions) validate() error {
	switch {
	case o.out == "":
		return errors.New("--out is required")
	case (o.subject != "" || len(o.sans) > 0) && o.csrOut == "":
		return errors.New("--subject and --san describe the request, so they need --csr-out")
	case o.csrOut != "" && o.subject == "" && len(o.sans) == 0:
		return errors.New("--csr-out needs --subject or --san")
	}
	stdoutUses := 0
	for _, p := range []string{o.out, o.pubOut, o.csrOut} {
		if p == stdoutPath {
			stdoutUses++
		}
	}
	if stdoutUses > 1 {
		return errors.New("only one output can go to standard output")
	}
	if err := o.checkStdout(o.out, o.pubOut, o.csrOut); err != nil {
		return err
	}
	return checkOutputs(o.force, o.out, o.pubOut, o.csrOut)
}
