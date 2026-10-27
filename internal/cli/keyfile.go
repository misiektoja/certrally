package cli

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/secret"
)

// Flags that supply the password of an encrypted private key.
const (
	flagKeyPassword     = "key-password"
	flagKeyPasswordFile = "key-password-file"
)

// keyPassword holds the flags that supply the password of an encrypted private key file.
type keyPassword struct {
	value secret.Value
	file  string
}

// addFlags registers --key-password and --key-password-file.
func (k *keyPassword) addFlags(cmd *cobra.Command) {
	cmd.Flags().Var(&k.value, flagKeyPassword,
		"password of an encrypted private key, which other users of this machine can see in the process list")
	cmd.Flags().StringVar(&k.file, flagKeyPasswordFile, "",
		"read the password of an encrypted private key from a file, or - for standard input")
	cmd.MarkFlagsMutuallyExclusive(flagKeyPassword, flagKeyPasswordFile)
	_ = cmd.RegisterFlagCompletionFunc(flagKeyPassword, cobra.NoFileCompletions)
}

// checkStdin rejects --key-password-file - together with another flag that reads standard input.
func (k *keyPassword) checkStdin(other, otherFile string) error {
	if k.file == stdoutPath && otherFile == stdoutPath {
		return fmt.Errorf("%s and --%s cannot both read standard input", other, flagKeyPasswordFile)
	}
	return nil
}

// load reads the private key in path. An encrypted PKCS#8 key is decrypted with the password from
// --key-password, --key-password-file, the CERTRALLY_KEY_PASSWORD environment variable or a prompt
// on stdin. The key is a crypto.Signer, or a crypto.Decapsulator for ML-KEM.
func (k *keyPassword) load(path string, stdin io.Reader, prompt io.Writer) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the user names the file to read.
	if err != nil {
		return nil, err
	}
	key, err := keys.Parse(data)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, keys.ErrEncrypted) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	password, err := secret.Source{
		Kind:      secret.KeyPassword,
		Value:     k.value.Bytes(),
		File:      k.file,
		LookupEnv: os.LookupEnv,
		Stdin:     stdin,
		Prompt:    prompt,
	}.Read()
	if err != nil {
		return nil, fmt.Errorf("%s is encrypted: %w", path, err)
	}
	key, err = keys.ParseEncrypted(data, password)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// loadSigner reads the private key in path as load does and refuses a key that cannot sign.
func (k *keyPassword) loadSigner(path string, stdin io.Reader, prompt io.Writer) (crypto.Signer, error) {
	key, err := k.load(path, stdin, prompt)
	if err != nil {
		return nil, err
	}
	signer, err := keys.Signer(key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return signer, nil
}
