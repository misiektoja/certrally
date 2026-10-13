package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
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
// rejection. A rejection can also arrive with an HTTP error status.
func exitCode(err error, r *trace.Recorder) int {
	_, unconfirmed := errors.AsType[*client.ConfirmationError](err)
	_, rejected := errors.AsType[*pkicmp.PKIStatusError](err)
	_, unverified := errors.AsType[*client.UnverifiedStatusError](err)
	switch {
	case unconfirmed:
		return exitUnconfirmed
	case rejected, unverified, errors.Is(err, client.ErrInfoTypeNotSupported):
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

// fail explains a failed exchange and returns the error that carries the exit status.
func (s *session) fail(err error) error {
	code := exitCode(err, s.recorder)
	var title string
	var fields []ui.Field
	switch code {
	case exitRejected:
		title, fields = "The CA rejected the request", s.rejectionFields(err)
	case exitTransport:
		title, fields = "No CMP answer from the server", s.transportFields(err)
	case exitLocal:
		title, fields = "The request was not completed", []ui.Field{errorField(err)}
	default:
		title, fields = "The exchange failed", []ui.Field{errorField(err), hintField(verificationHint(err))}
	}
	ui.Report(s.errOut, false, title, fields)
	return &exitError{code: code, err: err}
}

// rejectionFields describes a rejection. A status the client could not verify is marked as such,
// because any peer on the path could have sent it.
func (s *session) rejectionFields(err error) []ui.Field {
	if errors.Is(err, client.ErrInfoTypeNotSupported) {
		return []ui.Field{hintField("The CA does not offer this information.")}
	}
	var status pkicmp.PKIStatus
	var failInfo pkicmp.PKIFailureInfo
	var text, note string
	if statusErr, ok := errors.AsType[*pkicmp.PKIStatusError](err); ok {
		status, failInfo, text = statusErr.Status, statusErr.FailInfo, statusErr.StatusString
	} else if unverified, ok := errors.AsType[*client.UnverifiedStatusError](err); ok {
		status, failInfo, text = unverified.Status, unverified.FailInfo, unverified.StatusString
		note = "This answer is not authenticated, so treat it as a hint."
		if !s.pinned {
			note += " Pass the CA certificate with --ca-cert to verify it."
		}
	}
	fields := []ui.Field{
		{Name: "Status", Value: status.String()},
		{Name: "Fail info", Value: failInfo.String()},
	}
	if text != "" {
		fields = append(fields, ui.Field{Name: "CA says", Value: fmt.Sprintf("%q", ui.Sanitize(text))})
	}
	return append(fields, hintField(failureHint(failInfo)), ui.Field{Name: fieldNote, Value: note})
}

// failureHints suggests what to change for the common failure bits, most specific first.
var failureHints = []struct {
	bit  pkicmp.PKIFailureInfo
	hint string
}{
	{pkicmp.FailBadMessageCheck, "The CA could not verify the request protection. " +
		"Check the shared secret and --ref, or --cert and --key."},
	{pkicmp.FailSignerNotTrusted, "The CA does not trust the certificate in --cert."},
	{pkicmp.FailCertRevoked, "The certificate is already revoked."},
	{pkicmp.FailBadCertId, "The CA does not know this certificate."},
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
	{pkicmp.FailBadRequest, "The CA does not accept this request."},
}

// failureHint returns a suggestion for the failure bits. It returns "" when none applies.
func failureHint(info pkicmp.PKIFailureInfo) string {
	for _, h := range failureHints {
		if info&h.bit != 0 {
			return h.hint
		}
	}
	return ""
}

// transportFields describes a failure to get a CMP answer.
func (s *session) transportFields(err error) []ui.Field {
	problem := s.recorder.TransportError()
	if problem == nil {
		problem = err
	}
	return []ui.Field{
		{Name: "Server", Value: s.conn.redactedServer()},
		errorField(problem),
		hintField(s.conn.transportHint(err, problem)),
	}
}

// transportHint suggests a fix for a failure to reach the server. It returns "" when it has none.
func (c *connection) transportHint(err, problem error) string {
	_, unknownAuthority := errors.AsType[x509.UnknownAuthorityError](problem)
	_, dnsFailure := errors.AsType[*net.DNSError](problem)
	_, netFailure := errors.AsType[*net.OpError](problem)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("No answer within --timeout %s.", c.timeout)
	case unknownAuthority:
		return "The HTTPS certificate of the server is not trusted. Pass its CA with --tls-ca-cert."
	case dnsFailure:
		return "Check the host name in --server."
	case netFailure:
		return "Check the host and port in --server."
	case strings.HasPrefix(problem.Error(), "HTTP 404"):
		return "Check the path in --server."
	}
	return ""
}

// verificationHint names the flag that would let a failed response verify, or returns "".
func verificationHint(err error) string {
	verifyErr, ok := errors.AsType[*pkicmp.VerificationError](err)
	if !ok {
		return ""
	}
	switch verifyErr.Reason {
	case pkicmp.ReasonMissingTrustAnchors, pkicmp.ReasonSignatureFailed:
		return "The response is not signed by the CA in --ca-cert."
	case pkicmp.ReasonNoCandidateSigner:
		return "The response does not carry the certificate it was signed with. Pass it with --ca-cert."
	case pkicmp.ReasonBadMAC:
		return "The response MAC does not verify. Check the shared secret."
	case pkicmp.ReasonUnexpectedProtection:
		return "The response uses a different protection than the request."
	default:
		return ""
	}
}
