package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// Exit statuses. Scripts rely on them, so they must not change meaning.
const (
	exitOK          = 0
	exitLocal       = 1 // usage error or local failure
	exitTransport   = 2 // server unreachable or not answering with CMP
	exitRejected    = 3 // the CA answered with a rejection
	exitProtocol    = 4 // the exchange broke the protocol or failed verification
	exitUnconfirmed = 5 // the certificate was issued but the confirmation failed
)

// exitError is an error that has already been reported to the user and carries the exit status.
type exitError struct {
	code int
	err  error
}

// Error returns the underlying error text.
func (e *exitError) Error() string { return e.err.Error() }

// Unwrap returns the underlying error.
func (e *exitError) Unwrap() error { return e.err }

// exitCode classifies a failed exchange. The order matters: a confirmation failure can wrap a CA
// rejection, and a rejection can arrive with an HTTP error status.
func exitCode(err error, r *trace.Recorder) int {
	_, unconfirmed := errors.AsType[*client.ConfirmationError](err)
	_, rejected := errors.AsType[*pkicmp.PKIStatusError](err)
	_, unverified := errors.AsType[*client.UnverifiedStatusError](err)
	switch {
	case unconfirmed:
		return exitUnconfirmed
	case rejected, unverified:
		return exitRejected
	case errors.Is(err, context.Canceled):
		return exitLocal
	case r.TransportError() != nil, errors.Is(err, context.DeadlineExceeded):
		return exitTransport
	case len(r.Events()) == 0:
		return exitLocal
	}
	return exitProtocol
}

// errorField shows an error, which can quote the peer, safely.
func errorField(err error) ui.Field {
	return ui.Field{Name: "Error", Value: ui.Sanitize(err.Error())}
}

// hintField suggests what to change.
func hintField(hint string) ui.Field {
	return ui.Field{Name: "Hint", Value: hint}
}

// reportFailure explains a failed exchange on w and returns the error that sets the exit status.
// When the CA issued a certificate but the confirmation failed, the certificate and key are saved,
// because retrying could issue a second certificate.
func (o *enrollOptions) reportFailure(w io.Writer, err error, r *trace.Recorder, e *enrollment) error {
	code := exitCode(err, r)
	var title string
	var fields []ui.Field
	switch code {
	case exitUnconfirmed:
		confErr, _ := errors.AsType[*client.ConfirmationError](err)
		saved, saveErr := o.save(confErr.Certificate, e.newKey, nil)
		title = "The certificate was issued but the confirmation failed"
		fields = []ui.Field{
			errorField(confErr.Err),
			{Name: "Saved", Value: strings.Join(saved, ", ")},
			{Name: "Note", Value: "The CA may keep or revoke this certificate. " +
				"Check with the CA before retrying, because a retry can issue a second certificate."},
		}
		if saveErr != nil {
			fields = append(fields, ui.Field{Name: "Save error", Value: saveErr.Error()})
		}
	case exitRejected:
		title, fields = "The CA rejected the request", rejectionFields(err, e.anchored)
	case exitTransport:
		title, fields = "No CMP answer from the server", o.transportFields(err, r)
	case exitLocal:
		title, fields = "The request was not completed", []ui.Field{errorField(err)}
	default:
		title, fields = "The exchange failed", []ui.Field{errorField(err), hintField(verificationHint(err))}
	}
	ui.Report(w, false, title, fields)
	return &exitError{code: code, err: err}
}

// rejectionFields describes a rejection. A status the client could not verify is marked as such,
// because any peer on the path could have sent it.
func rejectionFields(err error, anchored bool) []ui.Field {
	var status pkicmp.PKIStatus
	var failInfo pkicmp.PKIFailureInfo
	var text, note string
	if statusErr, ok := errors.AsType[*pkicmp.PKIStatusError](err); ok {
		status, failInfo, text = statusErr.Status, statusErr.FailInfo, statusErr.StatusString
	} else if unverified, ok := errors.AsType[*client.UnverifiedStatusError](err); ok {
		status, failInfo, text = unverified.Status, unverified.FailInfo, unverified.StatusString
		note = "This answer is not authenticated, so treat it as a hint."
		if !anchored {
			note += " Pass the CA certificate with --trusted to verify error messages."
		}
	}
	fields := []ui.Field{
		{Name: "Status", Value: status.String()},
		{Name: "Fail info", Value: failInfo.String()},
	}
	if text != "" {
		fields = append(fields, ui.Field{Name: "CA says", Value: fmt.Sprintf("%q", ui.Sanitize(text))})
	}
	return append(fields, hintField(failureHint(failInfo)), ui.Field{Name: "Note", Value: note})
}

// failureHints suggests what to change for the common failure bits, most specific first.
var failureHints = []struct {
	bit  pkicmp.PKIFailureInfo
	hint string
}{
	{pkicmp.FailBadMessageCheck, "The CA could not verify the request protection. " +
		"Check the shared secret and --ref, or --cert and --key."},
	{pkicmp.FailSignerNotTrusted, "The CA does not trust the certificate in --cert."},
	{pkicmp.FailCertRevoked, "The certificate in --cert is revoked."},
	{pkicmp.FailWrongAuthority, "The request reached the wrong CA. Check --server and --recipient."},
	{pkicmp.FailBadCertTemplate, "The CA did not accept the requested name or key. " +
		"Check --subject, --san and --key-type against the certificate profile."},
	{pkicmp.FailBadAlg, "The CA does not accept the key or protection algorithm. Try another --key-type or --mac."},
	{pkicmp.FailBadTime, "The CA rejected the message time. Check the system clock."},
	{pkicmp.FailNotAuthorized, "The credentials are not authorized for this request."},
	{pkicmp.FailUnacceptedPolicy, "The CA did not accept the requested policy or profile. Check --cert-profile."},
	{pkicmp.FailDuplicateCertReq, "The CA refuses to issue a duplicate certificate."},
	{pkicmp.FailSystemUnavail, "The CA is temporarily unavailable. Try again later."},
	{pkicmp.FailTransactionIdInUse, "The CA still holds a transaction with this ID. Try again."},
}

// failureHint returns a suggestion for the failure bits, or "" when none applies.
func failureHint(info pkicmp.PKIFailureInfo) string {
	for _, h := range failureHints {
		if info&h.bit != 0 {
			return h.hint
		}
	}
	return ""
}

// transportFields describes a failure to get a CMP answer.
func (o *enrollOptions) transportFields(err error, r *trace.Recorder) []ui.Field {
	problem := r.TransportError()
	if problem == nil {
		problem = err
	}
	_, unknownAuthority := errors.AsType[x509.UnknownAuthorityError](problem)
	_, dnsFailure := errors.AsType[*net.DNSError](problem)
	_, netFailure := errors.AsType[*net.OpError](problem)
	hint := ""
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		hint = fmt.Sprintf("No answer within --timeout %s.", o.timeout)
	case unknownAuthority:
		hint = "The HTTPS certificate of the server is not trusted. Pass its CA with --tls-trusted."
	case dnsFailure:
		hint = "Check the host name in --server."
	case netFailure:
		hint = "Check the host and port in --server."
	case strings.HasPrefix(problem.Error(), "HTTP 404"):
		hint = "Check the path in --server."
	}
	server := o.server
	if u, err := url.Parse(o.server); err == nil {
		server = u.Redacted()
	}
	return []ui.Field{{Name: "Server", Value: server}, errorField(problem), hintField(hint)}
}

// verificationHint names the flag that would let a failed response verify, or returns "".
func verificationHint(err error) string {
	verifyErr, ok := errors.AsType[*pkicmp.VerificationError](err)
	if !ok {
		return ""
	}
	switch verifyErr.Reason {
	case pkicmp.ReasonMissingTrustAnchors:
		return "The response is signed. Pass the CA certificate with --trusted."
	case pkicmp.ReasonNoCandidateSigner:
		return "The response does not carry the certificate it was signed with. Pass it with --server-cert."
	case pkicmp.ReasonBadMAC:
		return "The response MAC does not verify. Check the shared secret."
	case pkicmp.ReasonSignatureFailed:
		return "The response signature does not verify against --trusted."
	case pkicmp.ReasonUnexpectedProtection:
		return "The response uses a different protection than the request."
	default:
		return ""
	}
}
