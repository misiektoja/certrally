package scepca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/misiektoja/go-scep"
	"github.com/misiektoja/go-scep/scepclient"
	"github.com/misiektoja/go-scep/scepserver"
	"github.com/misiektoja/go-scep/x509util"
)

// testClient serves ca and returns a client for it with its CA certificates. busyRetries is passed
// to the client, so that tests of BusyInterval can see the 503 answer.
func testClient(t *testing.T, ca *CA, busyRetries int) (*scepclient.Client, *scepclient.CACertificates) {
	t.Helper()
	h, err := ca.Handler(scepserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client, err := scepclient.New(srv.URL+"/scep", scepclient.Options{BusyRetries: busyRetries})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := client.GetCACert(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return client, certs
}

// testRequest returns a PKCSReq for a new RSA key with challenge, signed with a self-signed
// certificate for that key.
func testRequest(t *testing.T, cn, challenge string) scepclient.EnrollRequest {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		Subject:           pkix.Name{CommonName: cn},
		ChallengePassword: challenge,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return scepclient.EnrollRequest{CSR: csr, SignerCertificate: selfSigned(t, key, cn), SignerKey: key}
}

// selfSigned returns a self-signed certificate for key.
func selfSigned(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// failInfo returns the failInfo of a FAILURE answer, or fails the test.
func failInfo(t *testing.T, res *scepclient.Result, err error) scep.FailInfo {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != scep.FAILURE {
		t.Fatalf("status %s, want FAILURE", res.Status)
	}
	return res.FailInfo
}

// TestEnrollChallenge checks that a PKCSReq needs the challenge and that a certificate the CA issued
// renews and can be fetched with GetCert.
func TestEnrollChallenge(t *testing.T) {
	ca, err := New(Options{Challenge: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	client, certs := testClient(t, ca, 0)
	ctx := context.Background()

	res, err := client.Enroll(ctx, certs, testRequest(t, "wrong", "nope"))
	if info := failInfo(t, res, err); info != scep.BadRequest {
		t.Errorf("wrong challenge: failInfo %s, want badRequest", info)
	}

	req := testRequest(t, "device", "pw")
	res, err = client.Enroll(ctx, certs, req)
	if err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("enroll: %v, status %v", err, res)
	}
	if err := res.Certificate.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("issued certificate is not signed by the issuing CA: %v", err)
	}
	if res.Certificate.Subject.CommonName != "device" || res.Certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Errorf("issued %s with key usage %v", res.Certificate.Subject, res.Certificate.KeyUsage)
	}

	renewal := testRequest(t, "device", "")
	renewal.MessageType = scep.RenewalReq
	renewal.SignerCertificate, renewal.SignerKey = res.Certificate, req.SignerKey
	if renewed, err := client.Enroll(ctx, certs, renewal); err != nil || renewed.Status != scep.SUCCESS {
		t.Errorf("renewal: %v, %v", err, renewed)
	}
	selfRenewal := testRequest(t, "other", "")
	selfRenewal.MessageType = scep.RenewalReq
	res2, err := client.Enroll(ctx, certs, selfRenewal)
	if info := failInfo(t, res2, err); info != scep.BadRequest {
		t.Errorf("renewal with a foreign certificate: failInfo %s, want badRequest", info)
	}

	query := scepclient.QueryRequest{SerialNumber: res.Certificate.SerialNumber, SignerCertificate: res.Certificate, SignerKey: req.SignerKey}
	got, err := client.GetCert(ctx, certs, query)
	if err != nil || len(got) != 1 || !got[0].Equal(res.Certificate) {
		t.Errorf("GetCert: %v, %d certificates", err, len(got))
	}
	query.SerialNumber = big.NewInt(42)
	var failure *scepclient.FailureError
	if _, err := client.GetCert(ctx, certs, query); !errors.As(err, &failure) || failure.FailInfo != scep.BadCertID {
		t.Errorf("GetCert of an unknown serial: %v, want badCertId", err)
	}
	crlDER, err := client.GetCRL(ctx, certs, query)
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil || crl.CheckSignatureFrom(ca.Certificate()) != nil {
		t.Errorf("CRL does not parse or is not signed by the issuing CA: %v", err)
	}
}

// TestEnrollAnyChallenge checks that a CA without a challenge issues whatever a request carries.
func TestEnrollAnyChallenge(t *testing.T) {
	ca, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	client, certs := testClient(t, ca, 0)
	if res, err := client.Enroll(context.Background(), certs, testRequest(t, "any", "whatever")); err != nil || res.Status != scep.SUCCESS {
		t.Errorf("enroll: %v, %v", err, res)
	}
}

// TestPendingPolls checks that a request stays PENDING for the configured number of polls, is then
// issued and is answered with the same certificate when polled again.
func TestPendingPolls(t *testing.T) {
	ca, err := New(Options{PendingPolls: 2})
	if err != nil {
		t.Fatal(err)
	}
	client, certs := testClient(t, ca, 0)
	ctx := context.Background()
	req := testRequest(t, "pending", "")
	res, err := client.Enroll(ctx, certs, req)
	if err != nil || res.Status != scep.PENDING {
		t.Fatalf("enroll: %v, %v", err, res)
	}
	if res, err = client.Poll(ctx, certs, req); err != nil || res.Status != scep.PENDING {
		t.Fatalf("first poll: %v, %v", err, res)
	}
	if res, err = client.Poll(ctx, certs, req); err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("second poll: %v, %v", err, res)
	}
	again, err := client.Poll(ctx, certs, req)
	if err != nil || again.Status != scep.SUCCESS || !again.Certificate.Equal(res.Certificate) {
		t.Errorf("poll after issue: %v, %v", err, again)
	}
	// A PKCSReq sent again with the same transaction ID is a poll.
	if resent, err := client.Enroll(ctx, certs, req); err != nil || !resent.Certificate.Equal(res.Certificate) {
		t.Errorf("resent request: %v, %v", err, resent)
	}
	res, err = client.Poll(ctx, certs, testRequest(t, "unknown", ""))
	if info := failInfo(t, res, err); info != scep.BadCertID {
		t.Errorf("poll of an unknown transaction: failInfo %s, want badCertId", info)
	}
}

// TestCANameRAAndNextCA checks the CA name, the RA certificate and GetNextCACert.
func TestCANameRAAndNextCA(t *testing.T) {
	ca, err := New(Options{Name: "Issuing", RA: true, NextCA: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ca.Handler(scepserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	ctx := context.Background()
	if _, err := ca.CACertificates(ctx, "Other"); !errors.Is(err, scepserver.ErrNotFound) {
		t.Errorf("unknown CA name: %v, want ErrNotFound", err)
	}
	resp, err := http.Get(srv.URL + "/scep?operation=GetCACert&message=Other")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetCACert for another name: HTTP %d, want 404", resp.StatusCode)
	}

	client, err := scepclient.New(srv.URL+"/scep", scepclient.Options{CAName: "Issuing"})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs.All) != 2 || !certs.CA.Equal(ca.Certificate()) || len(certs.Recipients) != 1 || certs.Recipients[0].Equal(ca.Certificate()) {
		t.Errorf("GetCACert: %d certificates, CA %s", len(certs.All), certs.CA.Subject)
	}
	chain, err := client.GetCACertChain(ctx)
	if err != nil || len(chain) != 2 || !chain[1].Equal(ca.Root()) {
		t.Errorf("GetCACertChain: %v, %d certificates", err, len(chain))
	}
	next, err := client.GetNextCACert(ctx, certs)
	if err != nil || next.CA == nil || next.CA.Equal(ca.Certificate()) || next.CA.CheckSignatureFrom(ca.Root()) != nil {
		t.Errorf("GetNextCACert: %v, %v", err, next)
	}
	if res, err := client.Enroll(ctx, certs, testRequest(t, "via-ra", "")); err != nil || res.Status != scep.SUCCESS {
		t.Errorf("enroll through the RA: %v, %v", err, res)
	}
}

// TestBusyInterval checks that a PKIOperation sent too soon after another is answered with 503 and
// no Retry-After.
func TestBusyInterval(t *testing.T) {
	ca, err := New(Options{BusyInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	client, certs := testClient(t, ca, -1)
	ctx := context.Background()
	if res, err := client.Enroll(ctx, certs, testRequest(t, "first", "")); err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("first request: %v, %v", err, res)
	}
	_, err = client.Enroll(ctx, certs, testRequest(t, "second", ""))
	var httpErr *scepclient.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable || httpErr.RetryAfter != 0 {
		t.Errorf("second request: %v, want HTTP 503 without Retry-After", err)
	}
}

// TestNewRejectsNegativeOptions checks the validation of Options.
func TestNewRejectsNegativeOptions(t *testing.T) {
	if _, err := New(Options{PendingPolls: -1}); err == nil {
		t.Error("negative PendingPolls accepted")
	}
	if _, err := New(Options{BusyInterval: -time.Second}); err == nil {
		t.Error("negative BusyInterval accepted")
	}
}
