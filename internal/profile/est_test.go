package profile

import (
	"slices"
	"testing"
)

// TestCheckEST checks the RFC 7030 rules for EST responses.
func TestCheckEST(t *testing.T) {
	const certsOnly = "application/pkcs7-mime; smime-type=certs-only"
	tests := []struct {
		name string
		resp ESTResponse
		want []string
	}{
		{"issued certificate", ESTResponse{Operation: "simpleenroll", HTTPStatus: 200, ContentType: certsOnly, Certificates: 1}, nil},
		{"chain", ESTResponse{Operation: "simplereenroll", HTTPStatus: 200, ContentType: certsOnly, Certificates: 3}, []string{
			"The simplereenroll response carries 3 certificates instead of only the issued one (RFC 7030 section 4.2.3).",
		}},
		{"no smime-type", ESTResponse{Operation: "simpleenroll", HTTPStatus: 200, ContentType: "application/pkcs7-mime", Certificates: 1}, []string{
			"The simpleenroll response has no smime-type=certs-only parameter (RFC 7030 section 4.2.3).",
		}},
		{"serverkeygen part", ESTResponse{Operation: "serverkeygen", HTTPStatus: 200, ContentType: "application/pkcs7-mime", Certificates: 2}, []string{
			"The serverkeygen response carries 2 certificates instead of only the issued one (RFC 7030 section 4.4.2).",
			"The serverkeygen response has no smime-type=certs-only parameter (RFC 7030 section 4.4.2).",
		}},
		{"waiting", ESTResponse{Operation: "simpleenroll", HTTPStatus: 202, RetryAfter: true}, nil},
		{"waiting without a time", ESTResponse{Operation: "simpleenroll", HTTPStatus: 202}, []string{
			"The simpleenroll response has status 202 but no Retry-After header (RFC 7030 section 4.2.3).",
		}},
		{"CA certificates", ESTResponse{Operation: "cacerts", HTTPStatus: 200, ContentType: "application/pkcs7-mime", Certificates: 3}, nil},
		{"rejection", ESTResponse{Operation: "simpleenroll", HTTPStatus: 401}, nil},
	}
	for _, tt := range tests {
		var got []string
		for _, f := range CheckEST(tt.resp) {
			got = append(got, f.String())
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}
