package cli

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/cmpfile"
	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// inspectOptions holds the inspect command line.
type inspectOptions struct {
	outputOptions
	caCerts    []string
	secretFile string
}

// fileArgsHelp describes the FILE arguments of inspect and lint.
const fileArgsHelp = "Each FILE is a capture file written with --capture, a message as DER, base64 or hex, or " +
	"messages as PEM blocks. A FILE of - reads standard input."

// newInspectCommand returns the inspect command.
func newInspectCommand() *cobra.Command {
	o := &inspectOptions{}
	cmd := &cobra.Command{
		Use:   "inspect FILE... [flags]",
		Short: "Decode CMP messages from capture or message files",
		Long: "Decode CMP messages and show their header, protection, body and extra certificates.\n\n" +
			fileArgsHelp + "\n\n" +
			"certrally checks a signature with the certificates the message carries and those in --ca-cert. " +
			"With --ca-cert it also checks that the signer chains to those certificates. It checks a MAC with " +
			"the shared secret from --secret-file or the " + secret.EnvVar + " environment variable. " +
			"inspect does not judge the messages. lint checks them against RFC 9483.\n\n" +
			"Exit status: 0 success, 1 a file cannot be read or holds no CMP message.",
		Example: "  certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \\\n" +
			"    --cert-out device.pem --key-out device.key --capture enroll.jsonl\n" +
			"  certrally inspect enroll.jsonl",
		Args: cobra.MinimumNArgs(1),
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, args []string, p *printer) error {
			return runInspect(o, p, args, cmd.InOrStdin())
		}),
	}
	f := cmd.Flags()
	f.StringArrayVar(&o.caCerts, "ca-cert", nil, "check signatures with the CA certificates in this file (repeatable)")
	f.StringVar(&o.secretFile, "secret-file", "",
		"check MACs with the shared secret in this file, or - for standard input")
	f.BoolVar(&o.json, "json", false, "print the messages as one JSON document on standard output")
	return cmd
}

// runInspect performs the inspect command.
func runInspect(o *inspectOptions, p *printer, paths []string, stdin io.Reader) error {
	if o.secretFile == stdoutPath && slices.Contains(paths, stdoutPath) {
		return errors.New("standard input can be read only once, so --secret-file and FILE cannot both be -")
	}
	caCerts, err := readCACerts(o.caCerts)
	if err != nil {
		return err
	}
	a := &anchors{caCerts: caCerts}
	if err := a.readSecret(o.secretFile, stdin); err != nil {
		return err
	}
	msgs, err := readMessages(paths, stdin)
	if err != nil {
		return err
	}
	result := &inspectJSON{Messages: make([]messageJSON, 0, len(msgs))}
	w := p.reportWriter()
	for i, m := range msgs {
		r := describeMessage(m, a)
		result.Messages = append(result.Messages, r.json)
		if !p.text() {
			continue
		}
		if i > 0 {
			_, _ = fmt.Fprintln(w)
		}
		title, details := r.title()
		ui.Heading(w, title, details)
		for _, s := range r.sections {
			ui.Section(w, s.heading, s.fields)
		}
		for _, problem := range r.json.Problems {
			ui.Warning(w, ui.Sanitize(problem))
		}
	}
	p.doc.Result = result
	return nil
}

// readMessages reads the messages in every file of paths. A path of "-" reads stdin, which can
// be read only once.
func readMessages(paths []string, stdin io.Reader) ([]cmpfile.Message, error) {
	for i, path := range paths {
		if path == stdoutPath && slices.Contains(paths[:i], stdoutPath) {
			return nil, errors.New("standard input can be read only once, so - can appear only once")
		}
	}
	var msgs []cmpfile.Message
	for _, path := range paths {
		m, err := cmpfile.Read(path, stdin)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, m...)
	}
	return msgs, nil
}

// readCACerts reads the certificates in the --ca-cert files.
func readCACerts(paths []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, path := range paths {
		c, err := pemfile.ReadCertificates(path)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c...)
	}
	return certs, nil
}

// anchors holds what inspect checks protection with.
type anchors struct {
	// caCerts are the --ca-cert certificates.
	caCerts []*x509.Certificate
	// secret is the shared secret for MACs. It is nil when none was given.
	secret []byte
	// secretSource names where the secret came from, for the report.
	secretSource string
}

// readSecret reads the shared secret from file or, when file is empty, from the environment. A file
// of - reads stdin. Without a secret MACs are not checked. inspect never prompts because it often
// runs on files that need no secret.
func (a *anchors) readSecret(file string, stdin io.Reader) error {
	src := secret.Source{File: file, LookupEnv: os.LookupEnv}
	if file == stdoutPath {
		src.Stdin = stdin
	}
	value, err := src.Read()
	switch {
	case errors.Is(err, secret.ErrMissing):
		return nil
	case err != nil:
		return err
	}
	a.secret, a.secretSource = value, secret.EnvVar
	if file != "" {
		a.secretSource = "--secret-file"
	}
	return nil
}

// Outcomes of a protection check, as in the JSON result.
const (
	checkValid     = "valid"
	checkInvalid   = "invalid"
	checkUnchecked = "unchecked"
)

// Values of the JSON result: an absent protection or proof-of-possession, and a signature proof.
const (
	valueNone     = "none"
	popoSignature = "signature"
)

// messageReport describes one message as JSON and as sections of the text report.
type messageReport struct {
	json     messageJSON
	sections []reportSection
}

// reportSection is a heading and its fields in the text report.
type reportSection struct {
	heading string
	fields  []ui.Field
}

// section adds a section to the text report.
func (r *messageReport) section(heading string, fields ...ui.Field) {
	r.sections = append(r.sections, reportSection{heading: heading, fields: fields})
}

// problem records a part of the message that could not be decoded.
func (r *messageReport) problem(format string, args ...any) {
	r.json.Problems = append(r.json.Problems, fmt.Sprintf(format, args...))
}

// describeMessage describes m and checks its protection with a.
func describeMessage(m cmpfile.Message, a *anchors) *messageReport {
	msg := m.Msg
	r := &messageReport{json: messageJSON{
		Source:    m.Source,
		Direction: "response",
		Server:    m.Server,
		Size:      len(m.DER),
		Body:      msg.Body.Type.String(),
	}}
	if m.Request {
		r.json.Direction = "request"
	}
	if !m.Time.IsZero() {
		t := m.Time.UTC()
		r.json.Time = &t
	}
	extra := r.parseExtraCerts(msg)
	r.header(&msg.Header)
	signer := r.protection(msg, extra, a)
	r.body(msg.Body)
	for i, cert := range extra {
		if cert == nil {
			continue
		}
		r.json.ExtraCerts = append(r.json.ExtraCerts, certificateResult(cert))
		heading := fmt.Sprintf("Extra certificate %d", i+1)
		if cert == signer {
			heading += " (signer)"
		}
		r.section(heading, describeCertificate(cert)...)
	}
	return r
}

// title returns the heading line of the message in the text report.
func (r *messageReport) title() (title, details string) {
	j := &r.json
	arrow := "←"
	if j.Direction == "request" {
		arrow = "→"
	}
	parts := []string{ui.Sanitize(j.Source), j.Protection.Algorithm, count(j.Size, "byte", "bytes")}
	if j.Time != nil {
		parts = append(parts, j.Time.Format(messageTimeLayout))
	}
	return arrow + " " + j.Body, strings.Join(parts, "  ")
}

// messageTimeLayout formats message times, which need seconds unlike certificate validity.
const messageTimeLayout = "2006-01-02 15:04:05 UTC"

// parseExtraCerts parses the extraCerts of msg. A certificate that does not parse is left nil and
// recorded as a problem, so that the others keep their position.
func (r *messageReport) parseExtraCerts(msg *pkicmp.PKIMessage) []*x509.Certificate {
	certs := make([]*x509.Certificate, len(msg.ExtraCerts))
	for i := range msg.ExtraCerts {
		cert, err := msg.ExtraCerts[i].Parse()
		if err != nil {
			r.problem("Extra certificate %d does not parse: %v", i+1, err)
			continue
		}
		certs[i] = cert
	}
	return certs
}

// header describes the message header.
func (r *messageReport) header(h *pkicmp.PKIHeader) {
	j := headerJSON{
		PVNO:          h.PVNO,
		Sender:        generalName(h.Sender),
		Recipient:     generalName(h.Recipient),
		TransactionID: hex.EncodeToString(h.TransactionID),
		SenderNonce:   hex.EncodeToString(h.SenderNonce),
		RecipNonce:    hex.EncodeToString(h.RecipNonce),
		SenderKID:     hex.EncodeToString(h.SenderKID),
		RecipKID:      hex.EncodeToString(h.RecipKID),
		FreeText:      h.FreeText,
		CertProfile:   h.CertProfile(),
	}
	messageTime := ""
	if h.HasMessageTime() {
		t := h.MessageTime.UTC()
		j.MessageTime = &t
		messageTime = t.Format(messageTimeLayout)
	}
	for _, item := range h.GeneralInfo {
		j.GeneralInfo = append(j.GeneralInfo, infoTypeName(item.InfoType))
	}
	r.json.Header = j
	r.section("Header",
		ui.Field{Name: "Version", Value: strconv.Itoa(h.PVNO)},
		ui.Field{Name: "Sender", Value: nameText(j.Sender)},
		ui.Field{Name: "Recipient", Value: nameText(j.Recipient)},
		ui.Field{Name: "Message time", Value: messageTime},
		ui.Field{Name: "Transaction ID", Value: hexBytes(h.TransactionID)},
		ui.Field{Name: "Sender nonce", Value: hexBytes(h.SenderNonce)},
		ui.Field{Name: "Recipient nonce", Value: hexBytes(h.RecipNonce)},
		ui.Field{Name: "Sender KID", Value: keyID(h.SenderKID)},
		ui.Field{Name: "Recipient KID", Value: keyID(h.RecipKID)},
		ui.Field{Name: "Free text", Value: quoteText(h.FreeText)},
		ui.Field{Name: "General info", Value: strings.Join(j.GeneralInfo, ", ")},
		ui.Field{Name: "Profile", Value: ui.Sanitize(j.CertProfile)},
	)
}

// generalName returns a GeneralName for display. A directory name is an RFC 4514 string and
// the empty directory name, the NULL-DN of RFC 9483, is "". Forms other than directoryName and
// rfc822Name are named by their tag.
func generalName(g pkicmp.GeneralName) string {
	switch {
	case len(g.DirectoryName) > 0:
		return dn.String(g.DirectoryName)
	case g.RFC822Name != "":
		return g.RFC822Name
	case len(g.Raw) > 0 && g.Raw[0] != 0xa4:
		return fmt.Sprintf("GeneralName [%d]", g.Raw[0]&0x1f)
	}
	return ""
}

// nameText shows a name from generalName in the text report.
func nameText(name string) string {
	if name == "" {
		return "empty name"
	}
	return ui.Sanitize(name)
}

// keyID shows a key identifier as hex, followed by its text when it is printable. A MAC-protected
// message often carries a reference such as a user name in senderKID.
func keyID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return hexBytes(b)
		}
	}
	return fmt.Sprintf("%s %q", hexBytes(b), string(b))
}

// protection describes the protection of msg and checks it. extra are the parsed extraCerts. It
// returns the certificate whose signature verifies, if any.
func (r *messageReport) protection(msg *pkicmp.PKIMessage, extra []*x509.Certificate, a *anchors) *x509.Certificate {
	alg := msg.Header.ProtectionAlg
	if alg == nil {
		r.json.Protection = protectionJSON{Algorithm: valueNone}
		r.section("Protection", ui.Field{Name: "Algorithm", Value: valueNone})
		return nil
	}
	j := protectionJSON{Algorithm: trace.AlgorithmName(alg.Algorithm), Check: checkUnchecked}
	var signer *x509.Certificate
	kind := "Signature"
	if alg.Algorithm.Equal(oidPBM) || alg.Algorithm.Equal(oidPBMAC1) {
		kind = "MAC"
		j.Check, j.Problem = checkMAC(msg, a)
	} else {
		signer, j.Check, j.Problem = checkSignature(msg, slices.Concat(extra, a.caCerts))
	}
	trust := ""
	if signer != nil {
		j.Signer = dn.Format(signer.RawSubject)
		if len(a.caCerts) > 0 {
			trusted := chainsTo(msg, a.caCerts)
			j.Trusted = &trusted
			trust = "does not chain to --ca-cert"
			if trusted {
				trust = "chains to --ca-cert"
			}
		}
	}
	r.json.Protection = j
	r.section("Protection",
		ui.Field{Name: "Algorithm", Value: j.Algorithm},
		ui.Field{Name: kind, Value: checkText(j.Check, j.Problem)},
		ui.Field{Name: "Signer", Value: ui.Sanitize(j.Signer)},
		ui.Field{Name: "Trust", Value: trust},
	)
	return signer
}

// MAC protection algorithms of RFC 9481.
var (
	oidPBM    = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
)

// checkSignature finds the certificate among candidates whose signature protects msg. Nil
// candidates are skipped. It returns the signer, the outcome and why the outcome is not valid.
//
// Each candidate is tried directly, without building a chain, so that the signature check does not
// depend on trust. go-pki-cmp checks the validity period and the sender name before the signature,
// so a candidate that fails either may still be the signer and the outcome is then unchecked.
func checkSignature(msg *pkicmp.PKIMessage, candidates []*x509.Certificate) (signer *x509.Certificate, outcome, problem string) {
	kid := msg.Header.SenderKID
	var skipped string
	available, tried := 0, 0
	for _, cand := range candidates {
		if cand == nil {
			continue
		}
		available++
		// RFC 9483 section 3.1 sets senderKID to the subject key identifier of the signer.
		if len(kid) > 0 && len(cand.SubjectKeyId) > 0 && !bytes.Equal(kid, cand.SubjectKeyId) {
			continue
		}
		tried++
		_, err := msg.Verify(pkicmp.VerifyOptions{RequiredProtection: pkicmp.ProtectionSignature, TrustedCert: cand})
		if err == nil {
			return cand, checkValid, ""
		}
		verifyErr, ok := errors.AsType[*pkicmp.VerificationError](err)
		switch {
		case !ok || verifyErr.Reason == pkicmp.ReasonUnsupportedAlgorithm:
			return nil, checkUnchecked, err.Error()
		case skipped != "":
		case verifyErr.Reason == pkicmp.ReasonCertificateExpired:
			skipped = "the certificate " + dn.Format(cand.RawSubject) + " is outside its validity period"
		case verifyErr.Reason == pkicmp.ReasonSenderMismatch:
			skipped = "the certificate " + dn.Format(cand.RawSubject) + " does not name the sender"
		}
	}
	switch {
	case available == 0:
		return nil, checkUnchecked, "the message carries no certificate and --ca-cert names none"
	case tried == 0:
		return nil, checkUnchecked, "no certificate in extraCerts or --ca-cert matches senderKID"
	case skipped != "":
		return nil, checkUnchecked, skipped
	}
	return nil, checkInvalid, "no certificate in extraCerts or --ca-cert verifies it"
}

// checkMAC checks the MAC of msg with the shared secret of a. It returns the outcome and why the
// outcome is not valid. A wrong secret and a changed message fail the same way.
func checkMAC(msg *pkicmp.PKIMessage, a *anchors) (outcome, problem string) {
	if a.secret == nil {
		return checkUnchecked, "it needs the shared secret from --secret-file or " + secret.EnvVar
	}
	_, err := msg.Verify(pkicmp.VerifyOptions{RequiredProtection: pkicmp.ProtectionMAC, SharedSecret: a.secret})
	if err == nil {
		return checkValid, ""
	}
	if verifyErr, ok := errors.AsType[*pkicmp.VerificationError](err); ok && verifyErr.Reason == pkicmp.ReasonBadMAC {
		return checkInvalid, "it does not match the shared secret from " + a.secretSource
	}
	// go-pki-cmp refuses unsupported algorithms and parameters outside its limits, such as an
	// iteration count that would take too long, before it computes the MAC.
	return checkUnchecked, err.Error()
}

// chainsTo reports whether msg is signed with a certificate that chains to caCerts.
func chainsTo(msg *pkicmp.PKIMessage, caCerts []*x509.Certificate) bool {
	pool := x509.NewCertPool()
	candidates := slices.Clone(msg.ExtraCerts)
	for _, cert := range caCerts {
		pool.AddCert(cert)
		candidates = append(candidates, pkicmp.CMPCertificate{Raw: cert.Raw})
	}
	_, err := msg.Verify(pkicmp.VerifyOptions{
		RequiredProtection: pkicmp.ProtectionSignature,
		TrustPool:          pool,
		ExtraCerts:         candidates,
		SenderKID:          msg.Header.SenderKID,
	})
	return err == nil
}

// checkText shows the outcome of a protection check and its reason.
func checkText(outcome, problem string) string {
	text := outcome
	if outcome == checkUnchecked {
		text = "not checked"
	}
	if problem != "" {
		text += ", " + ui.Sanitize(problem)
	}
	return text
}

// body describes the content of the message body.
func (r *messageReport) body(b *pkicmp.PKIBody) {
	var err error
	switch b.Type {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR:
		var reqs *pkicmp.CertReqMessages
		if reqs, err = b.CertReqMessages(); err == nil {
			for i := range *reqs {
				r.certRequest(&(*reqs)[i])
			}
		}
	case pkicmp.BodyTypeP10CR:
		var csr *x509.CertificateRequest
		if csr, err = b.P10CR(); err == nil {
			r.csr(csr)
		}
	case pkicmp.BodyTypeIP, pkicmp.BodyTypeCP, pkicmp.BodyTypeKUP:
		var rep *pkicmp.CertRepMessage
		if rep, err = certRepContent(b); err == nil {
			r.certRep(rep)
		}
	case pkicmp.BodyTypeRR:
		var rr *pkicmp.RevReqContent
		if rr, err = b.RR(); err == nil {
			r.revRequests(*rr)
		}
	case pkicmp.BodyTypeRP:
		var rp *pkicmp.RevRepContent
		if rp, err = b.RP(); err == nil {
			r.revResponses(rp)
		}
	case pkicmp.BodyTypeCertConf:
		var conf *pkicmp.CertConfirmContent
		if conf, err = b.CertConf(); err == nil {
			r.confirmations(*conf)
		}
	case pkicmp.BodyTypePollReq:
		var ids *pkicmp.PollReqContent
		if ids, err = b.PollReq(); err == nil {
			for _, id := range *ids {
				r.json.Polls = append(r.json.Polls, pollJSON{CertReqID: id})
				r.section(fmt.Sprintf("Poll for request %d", id))
			}
		}
	case pkicmp.BodyTypePollRep:
		var items *pkicmp.PollRepContent
		if items, err = b.PollRep(); err == nil {
			r.pollResponses(*items)
		}
	case pkicmp.BodyTypeError:
		var content *pkicmp.ErrorMsgContent
		if content, err = b.Error(); err == nil {
			r.errorContent(content)
		}
	case pkicmp.BodyTypeGenM:
		var items *pkicmp.GenMsgContent
		if items, err = b.GenM(); err == nil {
			r.infoItems(*items)
		}
	case pkicmp.BodyTypeGenP:
		var items *pkicmp.GenRepContent
		if items, err = b.GenP(); err == nil {
			r.infoItems(*items)
		}
	case pkicmp.BodyTypePKIConf:
		// A pkiconf body holds only NULL.
	case pkicmp.BodyTypeNested:
		var nested []*pkicmp.PKIMessage
		if nested, err = b.Nested(); err == nil {
			for _, m := range nested {
				r.json.Nested = append(r.json.Nested, m.Body.Type.String())
			}
			r.section("Nested messages", ui.Field{Name: "Bodies", Value: strings.Join(r.json.Nested, ", ")})
		}
	}
	if err != nil {
		r.problem("The %s body does not decode: %v", b.Type, err)
	}
}

// certRepContent returns the content of an ip, cp or kup body.
func certRepContent(b *pkicmp.PKIBody) (*pkicmp.CertRepMessage, error) {
	switch b.Type {
	case pkicmp.BodyTypeIP:
		return b.IP()
	case pkicmp.BodyTypeCP:
		return b.CP()
	default:
		return b.KUP()
	}
}

// certRequest describes a request of an ir, cr or kur body.
func (r *messageReport) certRequest(m *pkicmp.CertReqMsg) {
	id := m.CertReq.CertReqID
	j := certRequestJSON{CertReqID: &id, Subject: generalName(m.CertReq.CertTemplate.Subject)}
	if pub, err := m.PublicKey(); err != nil {
		r.problem("The key of certificate request %d does not decode: %v", id, err)
	} else if pub != nil {
		j.Key = keys.Describe(pub)
	}
	if exts, err := m.Extensions(); err != nil {
		r.problem("The extensions of certificate request %d do not decode: %v", id, err)
	} else {
		j.Extensions = extensionsResult(exts)
	}
	j.POP, j.POPSignature, j.POPProblem = describePOP(m)
	oldCert := ""
	if old, err := m.CertReq.OldCertID(); err != nil {
		r.problem("The oldCertID control of certificate request %d does not decode: %v", id, err)
	} else if old != nil {
		j.OldCert = &certIDJSON{Issuer: generalName(old.Issuer), Serial: serialHex(old.SerialNumber)}
		oldCert = ui.Sanitize(j.OldCert.Issuer) + ", serial " + serialText(old.SerialNumber)
	}
	r.json.Requests = append(r.json.Requests, j)
	r.section(fmt.Sprintf("Certificate request %d", id), requestFields(&j, oldCert)...)
}

// csr describes the request of a p10cr body.
func (r *messageReport) csr(csr *x509.CertificateRequest) {
	j := certRequestJSON{
		Subject:      dn.Format(csr.RawSubject),
		Extensions:   extensionsResult(csr.Extensions),
		POP:          popoSignature,
		POPSignature: checkValid,
	}
	if pub, err := compositex509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo); err != nil {
		r.problem("The key of the certificate request does not decode: %v", err)
	} else {
		j.Key = keys.Describe(pub)
	}
	if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
		j.POPSignature, j.POPProblem = checkInvalid, err.Error()
	}
	r.json.Requests = append(r.json.Requests, j)
	r.section("Certificate request", requestFields(&j, "")...)
}

// requestFields returns the text form of a certificate request.
func requestFields(j *certRequestJSON, oldCert string) []ui.Field {
	exts := make([]string, 0, len(j.Extensions))
	for _, e := range j.Extensions {
		name := e.Name
		if name == "" {
			name = e.OID
		}
		if e.Critical {
			name += " (critical)"
		}
		exts = append(exts, name)
	}
	proof := j.POP
	if j.POPSignature != "" {
		proof += ", " + checkText(j.POPSignature, j.POPProblem)
	}
	return []ui.Field{
		{Name: fieldSubject, Value: ui.Sanitize(j.Subject)},
		{Name: fieldKey, Value: j.Key},
		{Name: "Extensions", Value: strings.Join(exts, ", ")},
		{Name: "Proof", Value: proof},
		{Name: "Replaces", Value: oldCert},
	}
}

// extensionsResult returns the JSON form of certificate extensions.
func extensionsResult(exts []pkix.Extension) []extensionJSON {
	out := make([]extensionJSON, 0, len(exts))
	for _, e := range exts {
		out = append(out, extensionJSON{OID: e.Id.String(), Name: extensionNames[e.Id.String()], Critical: e.Critical})
	}
	return out
}

// describePOP returns the kind of proof-of-possession of a request and, for a signature, the
// outcome of checking it and why it is not valid.
func describePOP(m *pkicmp.CertReqMsg) (kind, outcome, problem string) {
	popo := m.Popo
	switch {
	case popo == nil:
		return valueNone, "", ""
	case popo.Signature != nil:
		if in := popo.Signature.PoposkInput; in != nil && in.PublicKeyMAC != nil {
			return popoSignature, checkUnchecked, "its publicKeyMAC needs the shared secret"
		}
		if err := pkicmp.VerifyPOP(m); err != nil {
			return popoSignature, checkInvalid, err.Error()
		}
		return popoSignature, checkValid, ""
	case popo.RAVerified:
		return "raVerified", "", ""
	case popo.KeyEncipherment != nil:
		return "keyEncipherment", "", ""
	case popo.KeyAgreement != nil:
		return "keyAgreement", "", ""
	}
	return valueNone, "", ""
}

// certRep describes the responses and caPubs of an ip, cp or kup body.
func (r *messageReport) certRep(rep *pkicmp.CertRepMessage) {
	for _, resp := range rep.Response {
		j := certResponseJSON{CertReqID: resp.CertReqID, statusJSON: statusResult(resp.Status)}
		fields := statusFields(resp.Status)
		if kp := resp.CertifiedKeyPair; kp != nil {
			switch {
			case kp.CertOrEncCert.Certificate != nil:
				cert, err := kp.CertOrEncCert.Certificate.Parse()
				if err != nil {
					r.problem("The certificate of response %d does not parse: %v", resp.CertReqID, err)
					break
				}
				j.Certificate = certificateResult(cert)
				fields = append(fields, describeCertificate(cert)...)
			case kp.CertOrEncCert.EncryptedCert != nil:
				j.Encrypted = true
				fields = append(fields, ui.Field{Name: "Certificate", Value: "encrypted"})
			}
		}
		r.json.Responses = append(r.json.Responses, j)
		r.section(fmt.Sprintf("Certificate response %d", resp.CertReqID), fields...)
	}
	for i := range rep.CAPubs {
		cert, err := rep.CAPubs[i].Parse()
		if err != nil {
			r.problem("CA certificate %d in caPubs does not parse: %v", i+1, err)
			continue
		}
		r.json.CAPubs = append(r.json.CAPubs, certificateResult(cert))
		r.section(fmt.Sprintf("CA certificate %d", i+1), describeCertificate(cert)...)
	}
}

// revRequests describes the entries of an rr body.
func (r *messageReport) revRequests(rr pkicmp.RevReqContent) {
	for i := range rr {
		d := &rr[i]
		j := revocationJSON{Issuer: dn.Format(d.CertDetails.Issuer), Serial: serialHex(d.CertDetails.SerialNumber)}
		if exts, err := d.CRLEntryExtensions(); err != nil {
			r.problem("The crlEntryDetails of revocation request %d do not decode: %v", i+1, err)
		} else {
			j.Reason = crlReason(exts)
		}
		r.json.Revocations = append(r.json.Revocations, j)
		r.section(fmt.Sprintf("Revocation request %d", i+1),
			ui.Field{Name: fieldIssuer, Value: ui.Sanitize(j.Issuer)},
			ui.Field{Name: fieldSerial, Value: serialText(d.CertDetails.SerialNumber)},
			ui.Field{Name: fieldReason, Value: j.Reason},
		)
	}
}

// revResponses describes the entries of an rp body.
func (r *messageReport) revResponses(rp *pkicmp.RevRepContent) {
	for i, st := range rp.Status {
		status := statusResult(st)
		j := revocationJSON{statusJSON: &status}
		fields := statusFields(st)
		if i < len(rp.RevCerts) {
			id := rp.RevCerts[i]
			j.Issuer, j.Serial = generalName(id.Issuer), serialHex(id.SerialNumber)
			fields = append(fields,
				ui.Field{Name: fieldIssuer, Value: ui.Sanitize(j.Issuer)},
				ui.Field{Name: fieldSerial, Value: serialText(id.SerialNumber)},
			)
		}
		r.json.Revocations = append(r.json.Revocations, j)
		r.section(fmt.Sprintf("Revocation response %d", i+1), fields...)
	}
}

// confirmations describes the entries of a certConf body.
func (r *messageReport) confirmations(conf pkicmp.CertConfirmContent) {
	for _, cs := range conf {
		j := confirmationJSON{CertReqID: cs.CertReqID, CertHash: hex.EncodeToString(cs.CertHash)}
		if cs.HashAlg != nil {
			j.HashAlg = trace.AlgorithmName(cs.HashAlg.Algorithm)
		}
		fields := []ui.Field{
			{Name: "Certificate hash", Value: hexBytes(cs.CertHash)},
			{Name: "Hash algorithm", Value: j.HashAlg},
		}
		if cs.StatusInfo != nil {
			status := statusResult(*cs.StatusInfo)
			j.statusJSON = &status
			fields = append(fields, statusFields(*cs.StatusInfo)...)
		} else {
			fields = append(fields, ui.Field{Name: fieldStatus, Value: "accepted, no status given"})
		}
		r.json.Confirmations = append(r.json.Confirmations, j)
		r.section(fmt.Sprintf("Confirmation of response %d", cs.CertReqID), fields...)
	}
}

// pollResponses describes the entries of a pollRep body.
func (r *messageReport) pollResponses(items pkicmp.PollRepContent) {
	for _, item := range items {
		checkAfter := item.CheckAfter
		r.json.Polls = append(r.json.Polls, pollJSON{CertReqID: item.CertReqID, CheckAfter: &checkAfter, Reason: item.Reason})
		r.section(fmt.Sprintf("Poll response for request %d", item.CertReqID),
			ui.Field{Name: "Check after", Value: count(int(checkAfter), "second", "seconds")},
			ui.Field{Name: fieldReason, Value: quoteText(item.Reason)},
		)
	}
}

// errorContent describes an error body.
func (r *messageReport) errorContent(content *pkicmp.ErrorMsgContent) {
	r.json.Error = &errorContentJSON{
		statusJSON:   statusResult(content.PKIStatusInfo),
		ErrorCode:    content.ErrorCode,
		ErrorDetails: content.ErrorDetails,
	}
	code := ""
	if content.ErrorCode != 0 {
		code = strconv.Itoa(content.ErrorCode)
	}
	r.section("Error", append(statusFields(content.PKIStatusInfo),
		ui.Field{Name: "Error code", Value: code},
		ui.Field{Name: "Details", Value: quoteText(content.ErrorDetails)},
	)...)
}

// infoItems describes the items of a genm or genp body.
func (r *messageReport) infoItems(items []pkicmp.InfoTypeAndValue) {
	for _, item := range items {
		r.json.Items = append(r.json.Items, infoItemJSON{
			InfoType: infoTypeName(item.InfoType),
			OID:      item.InfoType.String(),
			Value:    item.InfoValue,
		})
		r.section(infoTypeName(item.InfoType),
			ui.Field{Name: "OID", Value: item.InfoType.String()},
			ui.Field{Name: "Value", Value: describeValue(item.InfoValue)},
		)
	}
}

// statusResult returns the JSON form of a PKIStatusInfo.
func statusResult(info pkicmp.PKIStatusInfo) statusJSON {
	return statusJSON{
		Status:     info.Status.String(),
		FailInfo:   trace.FailureNames(info.FailInfo),
		StatusText: info.StatusString,
	}
}

// statusFields returns the text form of a PKIStatusInfo.
func statusFields(info pkicmp.PKIStatusInfo) []ui.Field {
	return []ui.Field{
		{Name: fieldStatus, Value: info.Status.String()},
		{Name: "Fail info", Value: strings.Join(trace.FailureNames(info.FailInfo), ", ")},
		{Name: "Status text", Value: quoteText(info.StatusString)},
	}
}

// serialHex returns a serial number as upper-case hex, as in certificate results.
func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(n.Bytes()))
}

// serialText returns a serial number as colon-separated hex for the text report.
func serialText(n *big.Int) string {
	if n == nil {
		return ""
	}
	return hexBytes(n.Bytes())
}

// oidCRLReason is the reasonCode CRL entry extension of RFC 5280 section 5.3.1.
var oidCRLReason = asn1.ObjectIdentifier{2, 5, 29, 21}

// crlReason returns the reason code in CRL entry extensions. It returns "" when there is none.
func crlReason(exts []pkix.Extension) string {
	for _, e := range exts {
		if !e.Id.Equal(oidCRLReason) {
			continue
		}
		var reason asn1.Enumerated
		if rest, err := asn1.Unmarshal(e.Value, &reason); err != nil || len(rest) > 0 {
			return "unreadable"
		}
		return pkicmp.CRLReason(reason).String()
	}
	return ""
}
