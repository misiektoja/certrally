package profile

import (
	"slices"
	"testing"
)

// TestCheckSCEP checks the RFC 8894 rules for SCEP responses.
func TestCheckSCEP(t *testing.T) {
	tests := []struct {
		name string
		resp SCEPResponse
		want []string
	}{
		{"capabilities", SCEPResponse{Operation: "GetCACaps", HTTPStatus: 200, Body: []byte("SHA-256\r\nAES\n")}, nil},
		{"capabilities with NUL", SCEPResponse{Operation: "GetCACaps", HTTPStatus: 200, Body: []byte("SHA-1\nDES3\n\x00")}, []string{
			"The GetCACaps answer holds control characters, such as a NUL byte, besides the line breaks (RFC 8894 section 3.5.2).",
		}},
		{"CA certificate", SCEPResponse{Operation: "GetCACert", HTTPStatus: 200, ContentType: "application/x-x509-ca-cert",
			Body: []byte{0x30}, Certificates: 1}, nil},
		{"CA and RA certificates", SCEPResponse{Operation: "GetCACert", HTTPStatus: 200, ContentType: "application/x-x509-ca-cert",
			Body: []byte{0x30}, Certificates: 2}, []string{
			"The GetCACert answer has application/x-x509-ca-cert instead of application/x-x509-ca-ra-cert (RFC 8894 section 4.2.1.2).",
		}},
		{"CertRep", SCEPResponse{Operation: "PKIOperation", HTTPStatus: 200, ContentType: "application/x-pki-message",
			Body: []byte{0x30}, MessageType: "CertRep", SenderNonce: true}, nil},
		{"CertRep without senderNonce", SCEPResponse{Operation: "PKIOperation", HTTPStatus: 200,
			ContentType: "application/x-pki-message", Body: []byte{0x30}, MessageType: "CertRep"}, []string{
			"The PKIOperation answer has no senderNonce attribute (RFC 8894 section 3.2.1).",
		}},
		{"CertRep with HTTP 400", SCEPResponse{Operation: "PKIOperation", HTTPStatus: 400,
			ContentType: "application/x-pki-message", Body: []byte{0x30}, MessageType: "CertRep"}, []string{
			"The PKIOperation answer has no senderNonce attribute (RFC 8894 section 3.2.1).",
		}},
		{"PKIOperation without content type", SCEPResponse{Operation: "PKIOperation", HTTPStatus: 200, Body: []byte{0x30},
			MessageType: "CertRep", SenderNonce: true}, []string{
			"The PKIOperation answer has no content type instead of application/x-pki-message (RFC 8894 section 4.3.1).",
		}},
		{"next CA certificate", SCEPResponse{Operation: "GetNextCACert", HTTPStatus: 200, ContentType: "application/x-x509-next-ca-cert",
			Body: []byte{0x30}}, nil},
		{"no next CA certificate", SCEPResponse{Operation: "GetNextCACert", HTTPStatus: 200}, nil},
		{"refusal", SCEPResponse{Operation: "PKIOperation", HTTPStatus: 503, Body: []byte("busy")}, nil},
	}
	for _, tt := range tests {
		var got []string
		for _, f := range CheckSCEP(tt.resp) {
			got = append(got, f.String())
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}
