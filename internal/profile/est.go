package profile

import (
	"fmt"
	"mime"
	"net/http"
)

// ESTResponse holds what the EST rules check in a response.
type ESTResponse struct {
	// Operation is the EST operation the response answers, such as "simpleenroll".
	Operation  string
	HTTPStatus int
	// ContentType is the type of the response, or of the certificate part of a serverkeygen response.
	ContentType string
	// RetryAfter reports whether the response has a valid Retry-After header.
	RetryAfter bool
	// Certificates counts the certificates of a certs-only response.
	Certificates int
}

// estRules names the section of RFC 7030 that describes the certificate response of each
// enrollment operation.
var estRules = map[string]string{
	"simpleenroll":   "RFC 7030 section 4.2.3",
	"simplereenroll": "RFC 7030 section 4.2.3",
	"serverkeygen":   "RFC 7030 section 4.4.2",
}

// CheckEST returns the rules of RFC 7030 that an EST response breaks. The go-pki-est client accepts
// these deviations when certrally asks it to.
func CheckEST(r ESTResponse) []Finding {
	rule, enrollment := estRules[r.Operation]
	if !enrollment {
		return nil
	}
	var findings []Finding
	add := func(format string, args ...any) {
		text := fmt.Sprintf("The %s response ", r.Operation) + fmt.Sprintf(format, args...)
		findings = append(findings, Finding{Text: text, Rule: rule})
	}
	switch r.HTTPStatus {
	case http.StatusOK:
		if r.Certificates > 1 {
			add("carries %d certificates instead of only the issued one", r.Certificates)
		}
		if _, params, err := mime.ParseMediaType(r.ContentType); err != nil || params["smime-type"] != "certs-only" {
			add("has no smime-type=certs-only parameter")
		}
	case http.StatusAccepted:
		if !r.RetryAfter {
			// RFC 7030 section 4.4.2 refers to section 4.2.3 for a delayed serverkeygen response.
			rule = estRules["simpleenroll"]
			add("has status 202 but no Retry-After header")
		}
	}
	return findings
}
