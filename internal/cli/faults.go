package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/ui"
)

// Flags that send deliberately wrong messages to test how a CA copes.
const (
	flagFault        = "fault"
	flagConfirmDelay = "confirm-delay"
)

// --fault values. docs/faults.md names the RFC 9483 rule each one breaks.
const (
	faultRejectCertificate  = "reject-certificate"
	faultWrongCertHash      = "wrong-cert-hash"
	faultWrongCertReqID     = "wrong-cert-req-id"
	faultReuseSenderNonce   = "reuse-sender-nonce"
	faultStaleRecipNonce    = "stale-recip-nonce"
	faultWrongTransactionID = "wrong-transaction-id"
	faultNoProtection       = "no-protection"
	faultLateCertConf       = "late-certconf"
)

// faultNames lists the --fault values in the order of the help text.
var faultNames = []string{
	faultRejectCertificate, faultWrongCertHash, faultWrongCertReqID, faultReuseSenderNonce,
	faultStaleRecipNonce, faultWrongTransactionID, faultNoProtection, faultLateCertConf,
}

// rejectionText is the statusString of the certConf that --fault reject-certificate sends.
const rejectionText = "rejected by certrally --fault " + faultRejectCertificate

// lateCertConfMargin is how long --fault late-certconf waits past confirmWaitTime. GeneralizedTime
// drops the fraction of a second, so the deadline a CA keeps can be up to a second later than the
// one it sends.
const lateCertConfMargin = 2 * time.Second

// faultHelp explains the --fault values for enroll --help.
const faultHelp = "--fault sends a deliberately wrong message to test how the CA copes, the mirror of the fault " +
	"flags of certrally mock. It is repeatable. A refusal by the CA is the expected outcome, so the exit " +
	"status follows the usual rules and the report names the faults sent. The values are " +
	faultRejectCertificate + " (certConf rejects the certificate, which is still saved), " +
	faultWrongCertHash + " (certConf with a certHash of another certificate), " +
	faultWrongCertReqID + " (certConf with a certReqId the response did not use), " +
	faultReuseSenderNonce + " (every later message repeats the senderNonce of the first request), " +
	faultStaleRecipNonce + " (later messages carry a recipNonce that answers no response), " +
	faultWrongTransactionID + " (later messages carry another transactionID), " +
	faultNoProtection + " (certConf without protection) and " +
	faultLateCertConf + " (certConf after the confirmWaitTime of the response or after --confirm-delay " +
	"when the response sets none)."

// faultOptions holds the --fault and --confirm-delay flags.
type faultOptions struct {
	faults []string
	// confirmDelay is how long late-certconf waits when the response carries no confirmWaitTime.
	confirmDelay time.Duration
}

// addFlags registers --fault and --confirm-delay.
func (o *faultOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArrayVar(&o.faults, flagFault, nil,
		"send a deliberately wrong message to test the CA (repeatable): "+strings.Join(faultNames, ", "))
	f.DurationVar(&o.confirmDelay, flagConfirmDelay, 0,
		"time --fault late-certconf waits before certConf when the response carries no confirmWaitTime")
	_ = cmd.RegisterFlagCompletionFunc(flagFault, fixedCompletion(faultNames))
	_ = cmd.RegisterFlagCompletionFunc(flagConfirmDelay, cobra.NoFileCompletions)
}

// validate checks the fault names and the flags that go with them. pollLater is set when the run
// stops at a waiting answer, which leaves the later messages to poll.
func (o *faultOptions) validate(pollLater bool) error {
	for _, name := range o.faults {
		if !slices.Contains(faultNames, name) {
			return fmt.Errorf("invalid --%s %q, want one of %s", flagFault, name, strings.Join(faultNames, ", "))
		}
	}
	switch {
	case len(o.faults) > 0 && pollLater:
		return fmt.Errorf("--%s changes the later messages of the transaction, which --poll-later leaves to "+
			"certrally poll", flagFault)
	case o.confirmDelay < 0:
		return fmt.Errorf("--%s must not be negative", flagConfirmDelay)
	case o.confirmDelay > 0 && !slices.Contains(o.faults, faultLateCertConf):
		return fmt.Errorf("--%s sets the wait of --%s %s", flagConfirmDelay, flagFault, faultLateCertConf)
	}
	return nil
}

// injector applies the --fault values to the messages of one enrollment and records which messages
// each fault changed.
type injector struct {
	ctx          context.Context
	faults       []string
	confirmDelay time.Duration
	// firstNonce is the senderNonce of the first request.
	firstNonce []byte
	// sent maps each fault to the body types of the messages it changed, in order.
	sent map[string][]string
}

// newInjector returns the injector of the faults in o, nil when there are none. ctx bounds the wait
// of late-certconf.
func newInjector(ctx context.Context, o *faultOptions) *injector {
	if len(o.faults) == 0 {
		return nil
	}
	var faults []string
	for _, name := range faultNames {
		if slices.Contains(o.faults, name) {
			faults = append(faults, name)
		}
	}
	return &injector{ctx: ctx, faults: faults, confirmDelay: o.confirmDelay, sent: map[string][]string{}}
}

// requestOptions returns the request options that send the faults.
func (in *injector) requestOptions() []client.RequestOption {
	opts := []client.RequestOption{
		client.WithMessageMutator(in.beforeProtection),
		client.WithProtectedMessageMutator(in.afterProtection),
	}
	if in.has(faultRejectCertificate) {
		opts = append(opts, client.WithCertConfStatus(&pkicmp.PKIStatusInfo{
			Status:       pkicmp.StatusRejection,
			StatusString: pkicmp.PKIFreeText{rejectionText},
		}))
	}
	return opts
}

// has reports whether the fault name is to be sent.
func (in *injector) has(name string) bool {
	return slices.Contains(in.faults, name)
}

// record notes that the fault name changed msg.
func (in *injector) record(name string, msg *pkicmp.PKIMessage) {
	in.sent[name] = append(in.sent[name], msg.Body.Type.String())
}

// beforeProtection applies the faults that the protection covers. answered is nil for the first
// request, which every fault leaves unchanged.
func (in *injector) beforeProtection(msg, answered *pkicmp.PKIMessage) error {
	if answered == nil {
		in.firstNonce = bytes.Clone(msg.Header.SenderNonce)
		return nil
	}
	if in.has(faultReuseSenderNonce) {
		msg.Header.SenderNonce = bytes.Clone(in.firstNonce)
		in.record(faultReuseSenderNonce, msg)
	}
	if in.has(faultStaleRecipNonce) {
		nonce, err := randomOtherThan(answered.Header.SenderNonce)
		if err != nil {
			return err
		}
		msg.Header.RecipNonce = nonce
		in.record(faultStaleRecipNonce, msg)
	}
	if in.has(faultWrongTransactionID) {
		id, err := randomOtherThan(msg.Header.TransactionID)
		if err != nil {
			return err
		}
		msg.Header.TransactionID = id
		in.record(faultWrongTransactionID, msg)
	}
	if msg.Body.Type == pkicmp.BodyTypeCertConf {
		return in.changeCertConf(msg, answered)
	}
	return nil
}

// changeCertConf applies the faults of a certConf. answered is the response that carried the
// certificate.
func (in *injector) changeCertConf(msg, answered *pkicmp.PKIMessage) error {
	conf, err := msg.Body.CertConf()
	if err != nil {
		return fmt.Errorf("read certConf: %w", err)
	}
	if len(*conf) == 0 || len((*conf)[0].CertHash) == 0 {
		return fmt.Errorf("the certConf carries no certHash")
	}
	status := &(*conf)[0]
	// The client sends its own rejection of a certificate it refuses, which this fault does not change.
	if in.has(faultRejectCertificate) && status.StatusInfo != nil &&
		slices.Equal(status.StatusInfo.StatusString, pkicmp.PKIFreeText{rejectionText}) {
		in.record(faultRejectCertificate, msg)
	}
	if in.has(faultWrongCertHash) {
		status.CertHash = bytes.Clone(status.CertHash)
		status.CertHash[0] ^= 0xff
		in.record(faultWrongCertHash, msg)
	}
	if in.has(faultWrongCertReqID) {
		// A p10cr is answered with -1 and confirmed with 0 or -1, so the value must be neither.
		status.CertReqID = max(status.CertReqID+1, 1)
		in.record(faultWrongCertReqID, msg)
	}
	msg.Body = pkicmp.NewCertConfBody(conf)
	if in.has(faultLateCertConf) {
		if err := in.waitPastConfirmTime(answered); err != nil {
			return err
		}
		// The message is produced now, after the wait.
		msg.Header.MessageTime = time.Now()
		in.record(faultLateCertConf, msg)
	}
	return nil
}

// waitPastConfirmTime waits until the confirmWaitTime of answered has passed. Without one it waits
// for --confirm-delay.
func (in *injector) waitPastConfirmTime(answered *pkicmp.PKIMessage) error {
	var wake time.Time
	for _, item := range answered.Header.GeneralInfo {
		if deadline, err := pkicmp.ParseConfirmWaitTime(item); err == nil {
			wake = deadline.Add(lateCertConfMargin)
		}
	}
	if wake.IsZero() {
		if in.confirmDelay == 0 {
			return fmt.Errorf("the response carries no confirmWaitTime, so --%s %s needs --%s",
				flagFault, faultLateCertConf, flagConfirmDelay)
		}
		wake = time.Now().Add(in.confirmDelay)
	}
	if deadline, ok := in.ctx.Deadline(); ok && wake.After(deadline) {
		return fmt.Errorf("--%s %s waits until %s, after --timeout ends", flagFault, faultLateCertConf,
			wake.UTC().Format(time.RFC3339))
	}
	timer := time.NewTimer(time.Until(wake))
	defer timer.Stop()
	select {
	case <-in.ctx.Done():
		return in.ctx.Err()
	case <-timer.C:
		return nil
	}
}

// afterProtection applies the faults that change the protection itself.
func (in *injector) afterProtection(msg, answered *pkicmp.PKIMessage) error {
	if answered == nil || msg.Body.Type != pkicmp.BodyTypeCertConf || !in.has(faultNoProtection) {
		return nil
	}
	msg.Header.ProtectionAlg = nil
	msg.Protection = nil
	in.record(faultNoProtection, msg)
	return nil
}

// randomOtherThan returns 16 random bytes that differ from old.
func randomOtherThan(old []byte) ([]byte, error) {
	for {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if !bytes.Equal(b, old) {
			return b, nil
		}
	}
}

// faultJSON is a fault of the JSON document: its --fault name and the body types of the messages it
// changed, empty when no message was sent that it applies to.
type faultJSON struct {
	Name     string   `json:"name"`
	Messages []string `json:"messages"`
}

// results returns the faults with the messages each changed, in the order of the help text.
func (in *injector) results() []faultJSON {
	results := make([]faultJSON, 0, len(in.faults))
	for _, name := range in.faults {
		results = append(results, faultJSON{Name: name, Messages: append([]string{}, in.sent[name]...)})
	}
	return results
}

// field describes the faults for the text report, such as "wrong-cert-hash (certConf)".
func (in *injector) field() ui.Field {
	parts := make([]string, 0, len(in.faults))
	for _, f := range in.results() {
		where := "not sent"
		if len(f.Messages) > 0 {
			where = strings.Join(f.Messages, ", ")
		}
		parts = append(parts, f.Name+" ("+where+")")
	}
	return ui.Field{Name: fieldFaults, Value: strings.Join(parts, ", ")}
}

// report adds the faults to every report of the command: a field in the text report and the faults
// member of the JSON document.
func (in *injector) report(p *printer) {
	if in == nil {
		return
	}
	p.trailer = append(p.trailer, in.field())
	p.doc.Faults = in.results()
}

// rejected reports whether the certConf rejected the certificate on --fault reject-certificate.
func (in *injector) rejected() bool {
	return in != nil && len(in.sent[faultRejectCertificate]) > 0
}
