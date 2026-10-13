package cli

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// pingOptions holds the ping command line.
type pingOptions struct {
	connection
	outputOptions
	count    int
	interval time.Duration
}

// newPingCommand returns the ping command.
func newPingCommand() *cobra.Command {
	o := &pingOptions{}
	cmd := &cobra.Command{
		Use:   "ping --server URL [flags]",
		Short: "Check that a server answers CMP",
		Long: "Send an unprotected general message and report who answers and how fast. Any CMP answer counts, " +
			"including the error a server sends back for an unprotected message, so no credentials are needed.\n\n" +
			"With --ca-cert every answer must also be signed by that CA.\n\n" +
			"Exit status: 0 the server answered with CMP, 1 usage error, 2 no CMP answer, " +
			"4 an answer failed verification against --ca-cert.",
		Example: "  certrally ping --server https://ca.example.com/.well-known/cmp --count 5",
		Args:    cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runPing(cmd.Context(), o, p)
		}),
	}
	o.connection.addFlags(cmd, 10*time.Second, "limit for each request")
	o.outputOptions.addFlags(cmd)
	cmd.Flags().IntVarP(&o.count, "count", "c", 1, "number of requests to send")
	cmd.Flags().DurationVarP(&o.interval, "interval", "i", time.Second, "wait between requests")
	return cmd
}

// pingReply is the outcome of one ping.
type pingReply struct {
	// event is the recorded response. It is the failure when there was no response.
	event trace.Event
	// answered is set when the response is a CMP message.
	answered bool
	// tidEchoed is set when the answer repeats the transaction ID of the request.
	tidEchoed bool
	// verifyErr is why the answer failed verification against --ca-cert, if it was checked.
	verifyErr error
}

// runPing performs the ping command.
func runPing(ctx context.Context, o *pingOptions, p *printer) error {
	if err := o.validate(); err != nil {
		return err
	}
	if o.count < 1 || o.interval < 0 {
		return errors.New("--count must be at least 1 and --interval must not be negative")
	}
	recipient := pkicmp.NewDirectoryName(pkix.Name{})
	if o.recipient != "" {
		name, err := dn.ParseName(o.recipient)
		if err != nil {
			return fmt.Errorf("--recipient: %w", err)
		}
		recipient = pkicmp.NewDirectoryName(name)
	}
	s, err := o.open(p, nil)
	if err != nil {
		return err
	}

	var replies []pingReply
	for i := range o.count {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(o.interval):
			}
		}
		if ctx.Err() != nil {
			break
		}
		r, err := s.ping(ctx, recipient)
		if err != nil {
			return err
		}
		replies = append(replies, r)
		if o.count > 1 {
			p.line(fmt.Sprintf("  %d  %s", i+1, r.line()))
		}
	}
	return report(s, replies)
}

// ping sends one unprotected general message and records the answer.
func (s *session) ping(ctx context.Context, recipient pkicmp.GeneralName) (pingReply, error) {
	msg := pkicmp.NewPKIMessage(pkicmp.NewGenMBody(), pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{}),
		Recipient: recipient,
	})
	der, err := msg.MarshalBinary()
	if err != nil {
		return pingReply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.conn.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.conn.server, bytes.NewReader(der))
	if err != nil {
		return pingReply{}, err
	}
	req.Header.Set("Content-Type", "application/pkixcmp")
	if resp, err := s.http.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	events := s.recorder.Events()
	r := pingReply{event: events[len(events)-1]}
	if r.event.Kind != trace.Response || r.event.Transport != nil || r.event.Message == nil {
		return r, nil
	}
	r.answered = true
	answer, err := pkicmp.ParsePKIMessage(r.event.DER)
	if err != nil {
		return r, nil
	}
	r.tidEchoed = bytes.Equal(answer.Header.TransactionID, msg.Header.TransactionID)
	if s.pinned {
		r.verifyErr = s.verify(answer)
	}
	return r, nil
}

// verify checks that an answer is signed by the CA named with --ca-cert.
func (s *session) verify(msg *pkicmp.PKIMessage) error {
	if msg.Header.ProtectionAlg == nil {
		return errors.New("the answer is not protected")
	}
	candidates := append([]pkicmp.CMPCertificate(nil), msg.ExtraCerts...)
	for _, cert := range s.caCerts {
		candidates = append(candidates, pkicmp.CMPCertificate{Raw: cert.Raw})
	}
	_, err := msg.Verify(pkicmp.VerifyOptions{
		RequiredProtection: pkicmp.ProtectionSignature,
		TrustPool:          s.pool,
		ExtraCerts:         candidates,
		SenderKID:          msg.Header.SenderKID,
	})
	return err
}

// answer describes the body and status of a reply, such as "error rejection badMessageCheck".
func (r pingReply) answer() string {
	m := r.event.Message
	parts := []string{m.Body}
	if m.Status != "" {
		parts = append(parts, m.Status)
	}
	if m.FailInfo != 0 {
		parts = append(parts, m.FailInfo.String())
	}
	return strings.Join(parts, " ")
}

// line describes a reply in one line, for repeated pings.
func (r pingReply) line() string {
	rtt := formatRTT(r.event.Elapsed)
	if !r.answered {
		problem := "no CMP answer"
		if r.event.Transport != nil {
			problem = r.event.Transport.Error()
		}
		return ui.Sanitize(problem) + "  " + rtt
	}
	line := fmt.Sprintf("%s  %s  %d B  %s", r.answer(), r.event.Message.Protection, r.event.Size, rtt)
	if r.verifyErr != nil {
		line += "  not verified"
	}
	return line
}

// report summarizes the replies and returns the error that sets the exit status.
func report(s *session, replies []pingReply) error {
	var answered []pingReply
	var unverified error
	for _, r := range replies {
		if r.answered {
			answered = append(answered, r)
			if r.verifyErr != nil && unverified == nil {
				unverified = r.verifyErr
			}
		}
	}
	result := &pingJSON{Sent: len(replies), Answered: len(answered)}
	if len(answered) == 0 {
		s.p.doc.Result = result
		last := replies[len(replies)-1].event.Transport
		if last == nil {
			last = errors.New("the server sent no CMP message")
		}
		return s.p.fail(s.transportFailure(last), last)
	}

	first := answered[0]
	m := first.event.Message
	lo, avg, hi := roundTrips(answered)
	result.Sender, result.Protection = m.Sender, m.Protection
	result.RTTMS = &rttJSON{Min: milliseconds(lo), Avg: milliseconds(avg), Max: milliseconds(hi)}
	if s.pinned {
		verified := unverified == nil
		result.Verified = &verified
	}
	rtt := formatRTT(lo)
	if len(answered) > 1 {
		rtt = fmt.Sprintf("min %s, avg %s, max %s", formatRTT(lo), formatRTT(avg), formatRTT(hi))
	}
	fields := []ui.Field{
		{Name: "Server", Value: s.conn.redactedServer()},
		{Name: "Answer", Value: first.answer()},
		{Name: "CA says", Value: quoteText(m.StatusText)},
		{Name: "Sender", Value: ui.Sanitize(m.Sender)},
		{Name: "Protection", Value: m.Protection},
		{Name: "Round trip", Value: rtt},
	}
	if len(replies) > 1 {
		fields = append(fields, ui.Field{Name: "Replies", Value: fmt.Sprintf("%d of %d", len(answered), len(replies))})
	}
	var notes []string
	if m.Body == "error" {
		notes = append(notes, "An error is the expected answer, because the request carries no protection.")
	}
	if !first.tidEchoed {
		notes = append(notes, "The answer does not repeat the transaction ID of the request.")
	}
	fields = append(fields, ui.Field{Name: fieldNote, Value: strings.Join(notes, " ")})
	if unverified != nil {
		s.p.doc.Result = result
		fields = append(fields, ui.Field{Name: "Verified", Value: "no, " + ui.Sanitize(unverified.Error())})
		f := &failure{
			code:    exitProtocol,
			Title:   "The server answers CMP, but not as the CA in --ca-cert",
			Message: unverified.Error(),
		}
		return s.p.fail(f, unverified, fields...)
	}
	if s.pinned {
		fields = append(fields, ui.Field{Name: "Verified", Value: "signed by the CA in --ca-cert"})
	}
	s.p.result("The server answers CMP", fields, result)
	return nil
}

// roundTrips returns the shortest, average and longest round-trip times of the answered pings.
func roundTrips(replies []pingReply) (lo, avg, hi time.Duration) {
	lo, hi = replies[0].event.Elapsed, replies[0].event.Elapsed
	var sum time.Duration
	for _, r := range replies {
		lo, hi, sum = min(lo, r.event.Elapsed), max(hi, r.event.Elapsed), sum+r.event.Elapsed
	}
	return lo, sum / time.Duration(len(replies)), hi
}

// milliseconds returns d in milliseconds, to the microsecond.
func milliseconds(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// formatRTT returns a round-trip time in milliseconds with one decimal.
func formatRTT(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", milliseconds(d))
}
