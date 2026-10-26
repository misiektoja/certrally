package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// TestEnrollFaults checks that certrally mock answers every --fault the way RFC 9483 asks and that
// the reports name the fault and the refusal.
func TestEnrollFaults(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--confirm-wait", "1s")
	strict := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--strict")
	for _, tc := range []struct {
		fault string
		mock  *mockRun
		extra []string
		code  int
		// reason is in the error report and the mock log. An empty reason expects success.
		failInfo, reason string
		// note is a line of the mock log below the certConf.
		note string
	}{
		{fault: faultRejectCertificate, mock: m, code: exitOK, note: "certificate rejected"},
		{fault: faultWrongCertHash, mock: m, code: exitUnconfirmed, failInfo: "badCertId", reason: "certHash mismatch"},
		{fault: faultWrongCertReqID, mock: m, code: exitUnconfirmed, failInfo: "badCertId",
			reason: "certReqId does not match the issued certificate"},
		{fault: faultWrongCertReqID, mock: m, extra: []string{"--type", typeP10CR}, code: exitUnconfirmed,
			failInfo: "badCertId", reason: "certReqId does not match the issued certificate"},
		{fault: faultReuseSenderNonce, mock: m, code: exitOK},
		{fault: faultReuseSenderNonce, mock: strict, code: exitUnconfirmed, failInfo: "badSenderNonce",
			reason: "senderNonce reused"},
		{fault: faultStaleRecipNonce, mock: m, code: exitUnconfirmed, failInfo: "badRecipientNonce",
			reason: "recipNonce mismatch"},
		{fault: faultWrongTransactionID, mock: m, code: exitUnconfirmed, failInfo: "badRequest", reason: "unknown transaction"},
		{fault: faultNoProtection, mock: m, code: exitUnconfirmed, failInfo: "badMessageCheck", reason: "message not protected"},
		{fault: faultLateCertConf, mock: m, code: exitUnconfirmed, failInfo: "badRequest",
			reason: "certConf after confirmWaitTime", note: "certificate not confirmed in time"},
	} {
		t.Run(tc.fault+strings.Join(tc.extra, ""), func(t *testing.T) {
			dir := t.TempDir()
			certOut := filepath.Join(dir, "cert.pem")
			before := len(tc.mock.stdout.String())
			args := append([]string{"enroll", "--server", tc.mock.url, "--ref", testRef, "--sender", "CN=" + testRef,
				"--cert-out", certOut, "--key-out", filepath.Join(dir, "key.pem"), "--fault", tc.fault}, tc.extra...)
			code, out, errOut := run(t, args...)
			if code != tc.code {
				t.Fatalf("enroll exited with %d, want %d:\n%s%s", code, tc.code, out, errOut)
			}
			report := out + errOut
			if !errorContains(report, fieldFaults+" "+tc.fault+" (certConf)") {
				t.Errorf("the report does not name the fault:\n%s", report)
			}
			if _, err := os.Stat(certOut); err != nil {
				t.Errorf("the issued certificate was not saved: %v", err)
			}
			log := tc.mock.stdout.String()[before:]
			if tc.reason != "" {
				if !errorContains(errOut, tc.failInfo) || !errorContains(errOut, tc.reason) {
					t.Errorf("the report lacks %s and %q:\n%s", tc.failInfo, tc.reason, errOut)
				}
				if !strings.Contains(log, tc.failInfo+`  "`) || !strings.Contains(log, tc.reason) {
					t.Errorf("the mock log does not say why it refused the certConf:\n%s", log)
				}
			}
			if tc.note != "" && !strings.Contains(log, tc.note) {
				t.Errorf("the mock log lacks %q:\n%s", tc.note, log)
			}
		})
	}
}

// TestEnrollFaultRejectCertificate checks that the certConf of reject-certificate rejects the
// certificate with a statusString and that the report says so.
func TestEnrollFaultRejectCertificate(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	code, errOut, capture := mockEnroll(t, m, "--fault", faultRejectCertificate)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	msgs := readCapture(t, capture)
	conf, err := pkicmp.ParsePKIMessage(msgs[2].DER)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := conf.Body.CertConf()
	if err != nil {
		t.Fatal(err)
	}
	info := (*statuses)[0].StatusInfo
	if info == nil || info.Status != pkicmp.StatusRejection || len(info.StatusString) != 1 || info.StatusString[0] != rejectionText {
		t.Errorf("certConf statusInfo = %+v, want a rejection with %q", info, rejectionText)
	}
	answer, err := pkicmp.ParsePKIMessage(msgs[3].DER)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Body.Type != pkicmp.BodyTypePKIConf {
		t.Errorf("the CA answered the rejection with %s, want pkiconf", answer.Body.Type)
	}
}

// TestEnrollFaultsWhilePolling checks the faults on the pollReq of a request the CA keeps waiting. A
// refused pollReq ends the enrollment without a certificate.
func TestEnrollFaultsWhilePolling(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	for _, tc := range []struct {
		fault            string
		code             int
		failInfo, reason string
		sent             string
	}{
		{faultStaleRecipNonce, exitRejected, "badRecipientNonce", "recipNonce mismatch", "pollReq"},
		{faultWrongTransactionID, exitRejected, "badRequest", "no pending certificate", "pollReq"},
		{faultReuseSenderNonce, exitOK, "", "", "pollReq, certConf"},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			before := len(m.stdout.String())
			code, errOut, _ := mockEnroll(t, m, "--fault", tc.fault)
			if code != tc.code {
				t.Fatalf("enroll exited with %d, want %d:\n%s", code, tc.code, errOut)
			}
			if tc.reason != "" {
				log := m.stdout.String()[before:]
				if !errorContains(errOut, tc.reason) || !strings.Contains(log, "pollReq") || !strings.Contains(log, tc.reason) {
					t.Errorf("the refusal of the pollReq is not reported:\n%s\nmock log:\n%s", errOut, log)
				}
				if !errorContains(errOut, fieldFaults+" "+tc.fault+" ("+tc.sent+")") {
					t.Errorf("the report does not name the fault:\n%s", errOut)
				}
			}
		})
	}
}

// TestEnrollFaultJSON checks the faults member of the JSON document, also for a fault that the
// exchange gave no message to change.
func TestEnrollFaultJSON(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--grant-implicit-confirm")
	faults := func(t *testing.T, extra ...string) (int, []faultJSON, string) {
		t.Helper()
		dir := t.TempDir()
		args := append([]string{"enroll", "--server", m.url, "--ref", testRef, "--json",
			"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem")}, extra...)
		code, out, _ := run(t, args...)
		var doc struct {
			Faults []faultJSON `json:"faults"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%v:\n%s", err, out)
		}
		return code, doc.Faults, out
	}

	code, got, out := faults(t, "--fault", faultNoProtection, "--fault", faultWrongCertHash, "--fault", faultNoProtection)
	if code != exitUnconfirmed || len(got) != 2 || got[0].Name != faultWrongCertHash || got[1].Name != faultNoProtection ||
		strings.Join(got[0].Messages, ",") != "certConf" || strings.Join(got[1].Messages, ",") != "certConf" {
		t.Errorf("exit %d, faults %+v, want 5 with both faults once in help order on the certConf:\n%s", code, got, out)
	}

	code, got, out = faults(t, "--implicit-confirm", "--fault", faultWrongCertHash)
	if code != exitOK || len(got) != 1 || got[0].Messages == nil || len(got[0].Messages) != 0 {
		t.Errorf("exit %d, faults %+v, want 0 with an empty messages list:\n%s", code, got, out)
	}
	if !strings.Contains(out, `"messages": []`) {
		t.Errorf("a fault not sent has no empty messages list:\n%s", out)
	}

}

// TestEnrollFaultNotSentReport checks that the text report names a fault that found no message to change.
func TestEnrollFaultNotSentReport(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--grant-implicit-confirm")
	dir := t.TempDir()
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--implicit-confirm",
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"),
		"--fault", faultLateCertConf)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if !errorContains(out, fieldFaults+" "+faultLateCertConf+" (not sent)") {
		t.Errorf("the report does not say that the fault was not sent:\n%s", out)
	}
}

// TestEnrollFaultFlags checks the flag combinations that enroll refuses before sending anything.
func TestEnrollFaultFlags(t *testing.T) {
	useSecret(t, testSecret)
	dir := t.TempDir()
	base := []string{"enroll", "--server", "http://127.0.0.1:1/.well-known/cmp", "--ref", testRef,
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem")}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--fault", "wrong-nonce"}, `invalid --fault "wrong-nonce"`},
		{[]string{"--fault", faultWrongCertHash, "--poll-later", "--capture", filepath.Join(dir, "c.jsonl")},
			"which --poll-later leaves to certrally poll"},
		{[]string{"--fault", faultLateCertConf, "--confirm-delay", "-1s"}, "--confirm-delay must not be negative"},
		{[]string{"--confirm-delay", "5s"}, "--confirm-delay sets the wait of --fault late-certconf"},
	} {
		code, _, errOut := run(t, append(base, tc.args...)...)
		if code != exitLocal || !errorContains(errOut, tc.want) {
			t.Errorf("%v: exit %d, want %d with %q:\n%s", tc.args, code, exitLocal, tc.want, errOut)
		}
	}
}

// TestLateCertConfWait checks how long late-certconf waits for a response without confirmWaitTime
// and that it refuses a wait past --timeout.
func TestLateCertConfWait(t *testing.T) {
	plain := &pkicmp.PKIMessage{}
	in := newInjector(context.Background(), &faultOptions{faults: []string{faultLateCertConf}})
	if err := in.waitPastConfirmTime(plain); err == nil || !strings.Contains(err.Error(), "needs --confirm-delay") {
		t.Errorf("a response without confirmWaitTime and no --confirm-delay gave %v", err)
	}

	in.confirmDelay = 20 * time.Millisecond
	start := time.Now()
	if err := in.waitPastConfirmTime(plain); err != nil || time.Since(start) < in.confirmDelay {
		t.Errorf("--confirm-delay waited %s with %v, want at least %s", time.Since(start), err, in.confirmDelay)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	in = newInjector(ctx, &faultOptions{faults: []string{faultLateCertConf}, confirmDelay: time.Minute})
	if err := in.waitPastConfirmTime(plain); err == nil || !strings.Contains(err.Error(), "after --timeout ends") {
		t.Errorf("a wait past --timeout gave %v", err)
	}

	withDeadline := &pkicmp.PKIMessage{Header: pkicmp.PKIHeader{GeneralInfo: []pkicmp.InfoTypeAndValue{
		pkicmp.ConfirmWaitTimeInfoValue(-time.Hour),
	}}}
	in = newInjector(context.Background(), &faultOptions{faults: []string{faultLateCertConf}, confirmDelay: time.Hour})
	if err := in.waitPastConfirmTime(withDeadline); err != nil {
		t.Errorf("a confirmWaitTime in the past should not wait for --confirm-delay: %v", err)
	}
}
