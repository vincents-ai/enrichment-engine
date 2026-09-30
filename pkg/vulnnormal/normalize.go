// Package vulnnormal normalises vulnerability records to one internal shape.
//
// The engine used to read a single assumed shape, the NVD 2.0 RESPONSE wrapper
// with weaknesses and configurations nested under a "cve" key, while the ingest
// CLI required a TOP-LEVEL "id" to key the record by. Those two assumptions are
// mutually exclusive, and the real inputs did not satisfy either:
//
//   - The NVD client returns the unwrapped CVE, so "id" is at the top level and
//     ingest succeeds, but "weaknesses" is also at the top level, so the engine
//     finds no CWE and no CPE. The result is a valid CVE with zero mappings.
//   - A genuine NVD 2.0 response file has "id" nested under "cve", so ingest
//     fails outright with "record missing required id field".
//
// Both failures are silent in the sense that matters: the first produces a
// successful run that mapped nothing, and the second names a missing field
// without saying the file shape was unrecognised. The consequence is that valid
// ingestion yields no mappings and nothing reports why.
//
// One canonical representation plus explicit adapters fixes it, and makes an
// unsupported shape an error naming what was expected rather than an empty
// result.
package vulnnormal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// SchemaVersion identifies the canonical record shape. It is stored with every
// record so a future change to the representation can be detected rather than
// misread, which is what the brief requires of stored enrichment records.
const SchemaVersion = "vulnz-canonical-1"

// Canonical is the single internal representation of a vulnerability.
//
// It is deliberately flat: the engine reads ID, CWEs and CPEs directly and no
// longer has to know which upstream shape a record arrived in.
type Canonical struct {
	// SchemaVersion travels with the record.
	SchemaVersion string `json:"schema_version"`

	// ID is the vulnerability identifier, e.g. CVE-2026-1234.
	ID string `json:"id"`

	// Source identifies the provider the record came from, retained because the
	// brief requires provenance to survive normalisation.
	Source string `json:"source,omitempty"`

	// Published is the upstream publication timestamp when present.
	Published string `json:"published,omitempty"`

	// Description is the English description where the source provides one.
	Description string `json:"description,omitempty"`

	// CWEs are weakness identifiers such as CWE-79.
	CWEs []string `json:"cwes,omitempty"`

	// CPEs are affected-product criteria such as cpe:2.3:a:vendor:product.
	CPEs []string `json:"cpes,omitempty"`
}

// wire is the subset of the NVD CVE object this package reads. It covers both
// the unwrapped CVE and the object nested inside a response wrapper, because
// NVD uses the same object in both places.
type wire struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Description  struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// nvdResponse is the NVD 2.0 API response wrapper.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE wire `json:"cve"`
	} `json:"vulnerabilities"`
}

// vulnzEnvelope is the shape the vulnz library stores, which wraps the record
// under a schema/identifier/item envelope.
type vulnzEnvelope struct {
	Schema     string          `json:"schema"`
	Identifier string          `json:"identifier"`
	Item       json.RawMessage `json:"item"`
}

// SupportedShapes names the input shapes this package handles, used in errors so
// a caller is told what was expected rather than only what was wrong.
var SupportedShapes = []string{
	"a bare vulnerability object with a top-level id (the NVD client's unwrapped CVE)",
	"an NVD 2.0 response with a vulnerabilities[].cve array",
	"a vulnz storage envelope with schema/identifier/item",
}

// Normalize converts any supported input shape to Canonical.
//
// A record with no recognisable identifier is an error rather than an empty
// result. That distinction is the point of this package: a valid CVE with no
// CWE and no CPE is a legitimate, mappable absence, while a shape this package
// cannot read is a failure that must not look like the former.
func Normalize(raw []byte, source string) (Canonical, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Canonical{}, fmt.Errorf("cannot normalize an empty record")
	}

	// Already canonical. Re-normalizing must be idempotent, otherwise a
	// reprocessing run would double-wrap.
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(trimmed, &probe); err == nil && probe.SchemaVersion == SchemaVersion {
		var c Canonical
		if err := json.Unmarshal(trimmed, &c); err != nil {
			return Canonical{}, fmt.Errorf("record claims %s but does not parse: %w", SchemaVersion, err)
		}
		return c, nil
	}

	// Shape 1: a bare vulnerability object.
	var bare wire
	if err := json.Unmarshal(trimmed, &bare); err == nil && bare.ID != "" {
		return fromWire(bare, source), nil
	}

	// Shape 2: an NVD 2.0 response wrapper.
	var resp nvdResponse
	if err := json.Unmarshal(trimmed, &resp); err == nil && len(resp.Vulnerabilities) > 0 {
		return fromWire(resp.Vulnerabilities[0].CVE, source), nil
	}

	// Shape 3: a vulnz storage envelope.
	var env vulnzEnvelope
	if err := json.Unmarshal(trimmed, &env); err == nil && env.Item != nil {
		inner, err := Normalize(env.Item, source)
		if err != nil {
			return Canonical{}, fmt.Errorf("vulnz envelope %q: %w", env.Identifier, err)
		}
		if env.Identifier != "" && inner.ID == "" {
			inner.ID = strings.TrimPrefix(env.Identifier, "nvd:")
		}
		if env.Schema != "" {
			inner.Source = env.Schema
		}
		return inner, nil
	}

	return Canonical{}, fmt.Errorf(
		"unrecognised vulnerability record shape: no top-level id, no vulnerabilities[] array "+
			"and no storage envelope. Supported shapes are: %s. This is a failure to read the "+
			"record, not a vulnerability with no weaknesses, and the two must not be confused",
		strings.Join(SupportedShapes, "; "))
}

// NormalizeAll normalizes a collection, naming the index of anything it cannot
// read. A batch is not silently truncated.
func NormalizeAll(records []json.RawMessage, source string) ([]Canonical, error) {
	out := make([]Canonical, 0, len(records))
	for i, raw := range records {
		c, err := Normalize(raw, source)
		if err != nil {
			return nil, fmt.Errorf("record %d of %d: %w", i+1, len(records), err)
		}
		out = append(out, c)
	}
	return out, nil
}

func fromWire(w wire, source string) Canonical {
	c := Canonical{
		SchemaVersion: SchemaVersion,
		ID:            w.ID,
		Source:        source,
		Published:     firstNonEmpty(w.Published, w.LastModified),
	}
	if strings.EqualFold(w.Description.Lang, "en") || w.Description.Lang == "" {
		c.Description = w.Description.Value
	}

	seenCWE := map[string]bool{}
	for _, wkn := range w.Weaknesses {
		for _, d := range wkn.Description {
			// NVD puts the identifier in the English description; a bare
			// "CWE-79" string is also seen in the wild.
			for _, candidate := range extractIdentifiers(d.Value) {
				if !seenCWE[candidate] {
					seenCWE[candidate] = true
					c.CWEs = append(c.CWEs, candidate)
				}
			}
		}
	}

	seenCPE := map[string]bool{}
	for _, cfg := range w.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if m.Criteria != "" && !seenCPE[m.Criteria] {
					seenCPE[m.Criteria] = true
					c.CPEs = append(c.CPEs, m.Criteria)
				}
			}
		}
	}
	return c
}

func extractIdentifiers(s string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == ';'
	}) {
		field = strings.Trim(field, ".")
		if strings.HasPrefix(strings.ToUpper(field), "CWE-") {
			out = append(out, strings.ToUpper(field))
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
