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

// errorField shows an error message, which can quote the peer, safely.
func errorField(message string) ui.Field {
	return ui.Field{Name: "Error", Value: ui.Sanitize(message)}
}

// hintField suggests what to change.
func hintField(hint string) ui.Field {
	return ui.Field{Name: "Hint", Value: hint}
}

// failure describes why a command failed. It is the error member of the JSON document.
type failure struct {
	code    int
	Title   string `json:"title"`
	Message string `json:"message"`
	// Status, FailInfo and StatusText repeat the PKIStatusInfo of a CA rejection.
	Status     string   `json:"status,omitempty"`
	FailInfo   []string `json:"failInfo,omitempty"`
	StatusText []string `json:"statusText,omitempty"`
	// Unauthenticated marks a CA status that the client could not verify.
	Unauthenticated bool   `json:"unauthenticated,omitempty"`
	Hint            string `json:"hint,omitempty"`
	Note            string `json:"note,omitempty"`
}

// fields returns the text form of f. s is the session of the command. It is nil when there is none.
func (f *failure) fields(s *session) []ui.Field {
	var fields []ui.Field
	switch {
	case f.Status != "":
		fields = append(fields,
			ui.Field{Name: "Status", Value: f.Status},
			ui.Field{Name: "Fail info", Value: strings.Join(f.FailInfo, ", ")},
			ui.Field{Name: "CA says", Value: quoteText(f.StatusText)},
		)
	case f.code == exitTransport && s != nil:
		fields = append(fields, ui.Field{Name: "Server", Value: s.conn.redactedServer()}, errorField(f.Message))
	default:
		fields = append(fields, errorField(f.Message))
	}
	return append(fields, hintField(f.Hint), ui.Field{Name: fieldNote, Value: f.Note})
}

// quoteText joins and quotes peer-supplied text for display. It returns "" when there is none.
func quoteText(text []string) string {
	if len(text) == 0 {
		return ""
	}
	return fmt.Sprintf("%q", ui.Sanitize(strings.Join(text, " ")))
}

// fail explains a failed exchange and returns the error that carries the exit status.
func (s *session) fail(err error) error {
	return s.p.fail(s.failure(err), err)
}

// failure describes a failed exchange.
func (s *session) failure(err error) *failure {
	code := exitCode(err, s.recorder)
	switch code {
	case exitRejected:
		return s.rejection(err)
	case exitTransport:
		return s.transportFailure(err)
	case exitLocal:
		return &failure{code: code, Title: "The request was not completed", Message: err.Error()}
	default:
		return &failure{code: code, Title: "The exchange failed", Message: err.Error(), Hint: verificationHint(err)}
	}
}

// rejection describes a rejection. A status the client could not verify is marked as such, because
// any peer on the path could have sent it.
func (s *session) rejection(err error) *failure {
	f := &failure{code: exitRejected, Title: "The CA rejected the request", Message: err.Error()}
	if errors.Is(err, client.ErrInfoTypeNotSupported) {
		f.Hint = "The CA does not offer this information."
		return f
	}
	var status pkicmp.PKIStatus
	var failInfo pkicmp.PKIFailureInfo
	var text string
	if statusErr, ok := errors.AsType[*pkicmp.PKIStatusError](err); ok {
		status, failInfo, text = statusErr.Status, statusErr.FailInfo, statusErr.StatusString
	} else if unverified, ok := errors.AsType[*client.UnverifiedStatusError](err); ok {
		status, failInfo, text = unverified.Status, unverified.FailInfo, unverified.StatusString
		f.Unauthenticated = true
		f.Note = "This answer is not authenticated, so treat it as a hint."
		if !s.pinned {
			f.Note += " Pass the CA certificate with --ca-cert to verify it."
		}
	}
	f.Status, f.FailInfo, f.Hint = status.String(), trace.FailureNames(failInfo), failureHint(failInfo)
	if text != "" {
		f.StatusText = []string{text}
	}
	return f
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

// transportFailure describes a failure to get a CMP answer.
func (s *session) transportFailure(err error) *failure {
	problem := s.recorder.TransportError()
	if problem == nil {
		problem = err
	}
	return &failure{
		code:    exitTransport,
		Title:   "No CMP answer from the server",
		Message: problem.Error(),
		Hint:    s.conn.transportHint(err, problem),
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

// verificationHint names the flag that would let a failed response verify. It returns "" when it has none.
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
