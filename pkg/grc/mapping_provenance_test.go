package grc

import "testing"

// A mapping type that says "cpe" while no CPE comparison happened is worse
// than one that says nothing, because a consumer filtering on it concludes the
// product was verified affected. These mappings are shared-CWE proximity only.
func TestOnlyRealComparisonsClaimVerifiedApplicability(t *testing.T) {
	verified := []MappingType{MappingTypeCPE, MappingTypeManual}
	for _, m := range verified {
		if !m.IndicatesVerifiedApplicability() {
			t.Errorf("%q establishes applicability and must say so", m)
		}
	}

	// These are proximity signals. Treating them as verified is the defect that
	// produced 80 mappings for a single CVE under a CPE-based label.
	unverified := []MappingType{MappingTypeCWE, MappingTypeTag, MappingTypeCPEIndirect}
	for _, m := range unverified {
		if m.IndicatesVerifiedApplicability() {
			t.Errorf("%q is proximity only and must not claim verified applicability", m)
		}
	}
}

// The indirect type must be distinguishable from a real CPE mapping, and must
// not collide with it.
func TestCPEIndirectIsDistinctFromCPE(t *testing.T) {
	if MappingTypeCPEIndirect == MappingTypeCPE {
		t.Fatal("cpe_indirect must not equal cpe, or the distinction is lost")
	}
	if MappingTypeCPEIndirect == MappingTypeCWE {
		t.Fatal("cpe_indirect must not equal cwe")
	}
	if !MappingTypeCPEIndirect.IndicatesVerifiedApplicability() &&
		MappingTypeCWE.IndicatesVerifiedApplicability() {
		t.Fatal("both must be unverified for this test to mean anything")
	}
}
