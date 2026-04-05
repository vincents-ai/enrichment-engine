package storage

import (
	"testing"
)

func FuzzExtractVulnCWEs(f *testing.F) {
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
		extractVulnCWEs(data)
	})
}
