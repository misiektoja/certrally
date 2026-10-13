package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/profile"
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
	exitProfile     = 6 // a response broke a rule of the strict profile
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
// rejection or a profile violation. A rejection can also arrive with an HTTP error status.
func exitCode(err error, r *trace.Recorder) int {
	_, unconfirmed := errors.AsType[*client.ConfirmationError](err)
	_, violation := errors.AsType[*profileError](err)
	_, rejected := errors.AsType[*pkicmp.PKIStatusError](err)
	_, unverified := errors.AsType[*client.UnverifiedStatusError](err)
	switch {
	case unconfirmed:
		return exitUnconfirmed
	case violation:
		return exitProfile
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
	// Joined errors put each cause on its own line, which would break the field layout.
	return ui.Field{Name: "Error", Value: ui.Sanitize(strings.ReplaceAll(message, "\n", ": "))}
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
		fields = append(fields, ui.Field{Name: fieldServer, Value: s.conn.redactedServer()}, errorField(f.Message))
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

// profileError reports a response that breaks rules of the strict profile.
type profileError struct {
	findings []profile.Finding
}

// Error lists the deviations as sentences.
func (e *profileError) Error() string {
	texts := make([]string, 0, len(e.findings))
	for _, f := range e.findings {
		texts = append(texts, f.String())
	}
	return strings.Join(texts, " ")
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
	case exitProfile:
		violation, _ := errors.AsType[*profileError](err)
		return &failure{
			code:    code,
			Title:   "The response breaks the strict profile",
			Message: violation.Error(),
			Hint:    "Use --profile compatible to accept these deviations with a warning.",
		}
	default:
		hint := issuedTrustHint(err, s.pinned)
		if hint == "" {
			hint = verificationHint(err)
		}
		return &failure{code: code, Title: "The exchange failed", Message: err.Error(), Hint: hint}
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
	req := s.lastRequest()
	if req != nil && req.Body == "genm" && failInfo == pkicmp.FailBadRequest {
		// EJBCA Community Edition, for one, rejects every general message this way.
		f.Hint += " It may not support general messages."
	}
	if req != nil && req.Protection == "PBMAC1" && pbmacUnsupported(failInfo, text) {
		f.Hint = strings.TrimSpace(f.Hint + " Some CAs accept only PasswordBasedMac. Try --mac pbm.")
	}
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
	{pkicmp.FailWrongIntegrity, "The CA expects the other kind of protection: " +
		"a shared secret instead of --cert and --key, or the reverse."},
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

// pbmacUnsupported reports whether a rejection of a PBMAC1-protected request suggests that the CA does
// not know PBMAC1. Such a CA cannot check the MAC or takes the request for a signed one. badRequest
// alone says nothing about the protection, so it counts only when the text asks for a signer
// certificate, as the OpenSSL CMP server does with "no suitable sender cert".
func pbmacUnsupported(failInfo pkicmp.PKIFailureInfo, text string) bool {
	const protection = pkicmp.FailBadMessageCheck | pkicmp.FailWrongIntegrity | pkicmp.FailSignerNotTrusted
	if failInfo&protection != 0 {
		return true
	}
	return failInfo&pkicmp.FailBadRequest != 0 && strings.Contains(strings.ToLower(text), "sender cert")
}

// lastRequest returns the summary of the last request sent, or nil when none was.
func (s *session) lastRequest() *trace.Summary {
	events := s.recorder.Events()
	for _, ev := range slices.Backward(events) {
		if ev.Kind == trace.Request && ev.Message != nil {
			return ev.Message
		}
	}
	return nil
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
	_, wrongHost := errors.AsType[x509.HostnameError](problem)
	_, dnsFailure := errors.AsType[*net.DNSError](problem)
	_, netFailure := errors.AsType[*net.OpError](problem)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("No answer within --timeout %s.", c.timeout)
	case unknownAuthority:
		return "The HTTPS certificate of the server is not trusted. Pass its CA with --tls-ca-cert."
	case wrongHost:
		return "The HTTPS certificate of the server is issued for another host name. " +
			"Use a name from the certificate in --server."
	case dnsFailure:
		return "Check the host name in --server."
	case netFailure:
		return "Check the host and port in --server."
	case strings.HasPrefix(problem.Error(), "HTTP 404"):
		return "Check the path in --server."
	}
	return ""
}

// issuedTrustHint explains a new certificate that does not chain to the trusted CA certificates. It
// returns "" for other errors.
func issuedTrustHint(err error, pinned bool) string {
	// The go-pki-cmp client names this check "verify certificate trust".
	if clientErr, ok := errors.AsType[*client.Error](err); !ok || clientErr.Op != "verify certificate trust" {
		return ""
	}
	if pinned {
		return "The new certificate does not chain to the certificates in --ca-cert. " +
			"Add the CA certificate that issued it."
	}
	return "The response does not carry the CA certificate that issued the new certificate. " +
		"Pass it with --ca-cert."
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
