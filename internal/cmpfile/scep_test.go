package cmpfile

import (
	"testing"
)

// TestParseSCEPCapture checks that every request and response of a SCEP run is kept with its record.
func TestParseSCEPCapture(t *testing.T) {
	_, certsOnly, _ := estFixtures(t)
	data := captureLines(t,
		map[string]any{"kind": "start", "format": 1, "protocol": "scep", "server": "http://scep.example.com/scep"},
		map[string]any{"kind": "request", "method": "GET", "operation": "GetCACaps"},
		map[string]any{"kind": "response", "httpStatus": 200, "operation": "GetCACaps", "capabilities": []string{"SHA-1"}},
		map[string]any{"kind": "request", "method": "GET", "operation": "GetCACert", "caName": "Issuing"},
		map[string]any{"kind": "response", "httpStatus": 200, "operation": "GetCACert", "certificates": 1, "der": certsOnly},
		map[string]any{"kind": "failure", "problem": "connection reset"},
	)
	msgs, err := Parse("run.jsonl", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("got %d messages, want two requests and two responses", len(msgs))
	}
	if m := msgs[0]; !m.Request || m.SCEP == nil || m.EST != nil || m.SCEP.Operation != "GetCACaps" || m.Run != 1 {
		t.Errorf("request %+v", m)
	}
	if m := msgs[1]; m.Request || len(m.SCEP.Capabilities) != 1 || m.Source != "run.jsonl:3" {
		t.Errorf("caps response %+v", m)
	}
	if m := msgs[3]; m.SCEP.Certificates != 1 || string(m.DER) != string(certsOnly) || m.Server != "http://scep.example.com/scep" {
		t.Errorf("GetCACert response %+v", m)
	}
}
