package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// confirmOutputs checks the output files in paths as checkOutputs does. When some of them exist,
// --force is not given and the command reports text on a terminal, it asks once whether to replace
// them and sets *force when the answer is yes. Scripts and JSON output keep the error, so nothing
// is replaced without --force where nobody can answer. It runs before any request is sent.
func (p *printer) confirmOutputs(force *bool, paths ...string) error {
	// Problems that replacing cannot fix, such as one file named for two outputs, come first.
	if err := checkOutputs(true, paths...); err != nil || *force {
		return err
	}
	existing := existingFiles(paths)
	if len(existing) == 0 || !p.text() || !wizardTerminal(p.stdin, p.terminal) {
		return checkOutputs(false, paths...)
	}
	title := existing[0] + " exists. Replace it?"
	if len(existing) > 1 {
		title = joinList(existing) + " exist. Replace them?"
	}
	replace, err := newAsker(p.ctx, p.stdin, p.terminal).confirm(title, false)
	switch {
	case err != nil && !errors.Is(err, errEnrollCancelled):
		return err
	case err != nil || !replace:
		return fmt.Errorf("kept %s. Choose other files or use --force to replace them", joinList(existing))
	}
	*force = true
	return nil
}

// existingFiles returns the paths that name an existing file. Empty paths and - are skipped.
func existingFiles(paths []string) []string {
	var existing []string
	for _, path := range paths {
		if path == "" || path == stdoutPath {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	return existing
}

// joinList joins items as "a", "a and b" or "a, b and c".
func joinList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
