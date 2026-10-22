package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// TestVerificationHint checks that a signer outside --ca-cert, a signature that does not verify and a
// senderKID that names no certificate get different hints, also when the error is wrapped.
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
	// Only the strict profile refuses a senderKID that names no candidate, so the hint names the other one.
	kid := hint(pkicmp.ReasonSenderKIDMismatch)
	if kid == hint(pkicmp.ReasonNoCandidateSigner) || !strings.Contains(kid, "--ca-cert") || !strings.Contains(kid, "--profile compatible") {
		t.Errorf("senderKID mismatch hint = %q, want one of its own that names --ca-cert and --profile compatible", kid)
	}
}
