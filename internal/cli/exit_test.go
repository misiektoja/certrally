package cli

import (
	"fmt"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// TestVerificationHint checks that a signer outside --ca-cert and a signature that does not verify get
// different hints, also when the error is wrapped.
func TestVerificationHint(t *testing.T) {
	hint := func(reason pkicmp.InvalidReason) string {
		return verificationHint(fmt.Errorf("verify response: %w", &pkicmp.VerificationError{Reason: reason}))
	}
	untrusted, badSignature := hint(pkicmp.ReasonUntrustedSigner), hint(pkicmp.ReasonSignatureFailed)
	if untrusted == "" || untrusted != hint(pkicmp.ReasonMissingTrustAnchors) {
		t.Errorf("untrusted signer hint = %q, want the missing trust anchors hint %q", untrusted, hint(pkicmp.ReasonMissingTrustAnchors))
	}
	if badSignature == "" || badSignature == untrusted {
		t.Errorf("signature failure hint = %q, want one of its own", badSignature)
	}
}
