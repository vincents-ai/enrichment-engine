package enricher

import (
	"encoding/json"
	"testing"
)

func FuzzExtractCWEs(f *testing.F) {
	f.Add([]byte(`{"cve":{"weaknesses":[{"description":[{"lang":"en","value":"CWE-79"}]}]}}`))
	f.Add([]byte{})
	f.Add([]byte(`{"cve":{"weaknesses"`))
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte(`{"cve":{"weaknesses":[{"description":[{"lang":"en","value":"CWE-\u00e9\u00f1\u00fc"}]}]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %q: %v", data, r)
			}
		}()
		extractCWEs(json.RawMessage(data))
	})
}

func FuzzExtractCPEs(f *testing.F) {
	f.Add([]byte(`{"cve":{"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}]}}`))
	f.Add([]byte{})
	f.Add([]byte(`{"cve":{"configurations"`))
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte(`{"cve":{"configurations":[{"nodes":[{"cpeMatch":123}]}]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %q: %v", data, r)
			}
		}()
		extractCPEs(json.RawMessage(data))
	})
}
