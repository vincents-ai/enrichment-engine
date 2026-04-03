package verification

type expectedMapping struct {
	Framework string
	ControlID string
	CWE       string
}

type cveExpectation struct {
	ID              string
	Name            string
	CWE             string
	Positive        bool
	MinMappings     int
	MaxMappings     int
	ExpectedCWEHits []expectedMapping
}

var expectations = []cveExpectation{
	{
		ID:          "CVE-2021-44228",
		Name:        "Log4Shell (Apache Log4j)",
		CWE:         "CWE-502",
		Positive:    true,
		MinMappings: 10,
		MaxMappings: 60,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.5", CWE: "CWE-502"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.2", CWE: "CWE-502"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.25", CWE: "CWE-502"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.28", CWE: "CWE-502"},
			{Framework: "NIST_CSF_2_0", ControlID: "NIST_CSF_2_0/PR.IR-05", CWE: "CWE-502"},
			{Framework: "HIPAA_SECURITY_RULE_2013", ControlID: "HIPAA_SECURITY_RULE_2013/164.308(a)(5)(ii)(B)", CWE: "CWE-502"},
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/CC6.8", CWE: "CWE-502"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-3", CWE: "CWE-502"},
			{Framework: "CMMC_v2", ControlID: "CMMC_v2/SI.L1-3.14.1", CWE: "CWE-502"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/WS-2022.7.1", CWE: "CWE-502"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/RHEL-8.6.1", CWE: "CWE-502"},
		},
	},
	{
		ID:          "CVE-2014-0160",
		Name:        "Heartbleed (OpenSSL)",
		CWE:         "CWE-119",
		Positive:    true,
		MinMappings: 8,
		MaxMappings: 60,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.5", CWE: "CWE-119"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.25", CWE: "CWE-119"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.28", CWE: "CWE-119"},
			{Framework: "NIST_CSF_2_0", ControlID: "NIST_CSF_2_0/PR.IR-05", CWE: "CWE-119"},
			{Framework: "HIPAA_SECURITY_RULE_2013", ControlID: "HIPAA_SECURITY_RULE_2013/164.308(a)(5)(ii)(B)", CWE: "CWE-119"},
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/CC6.8", CWE: "CWE-119"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-3", CWE: "CWE-119"},
			{Framework: "CMMC_v2", ControlID: "CMMC_v2/SI.L1-3.14.1", CWE: "CWE-119"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/WS-2022.7.1", CWE: "CWE-119"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/RHEL-8.6.1", CWE: "CWE-119"},
		},
	},
	{
		ID:          "CVE-2022-22965",
		Name:        "Spring4Shell (Spring Framework)",
		CWE:         "CWE-94",
		Positive:    true,
		MinMappings: 15,
		MaxMappings: 60,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/5.1", CWE: "CWE-94"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.5", CWE: "CWE-94"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.25", CWE: "CWE-94"},
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/CC6.8", CWE: "CWE-94"},
			{Framework: "HIPAA_SECURITY_RULE_2013", ControlID: "HIPAA_SECURITY_RULE_2013/164.308(a)(5)(ii)(B)", CWE: "CWE-94"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-3", CWE: "CWE-94"},
			{Framework: "NIST_CSF_2_0", ControlID: "NIST_CSF_2_0/PR.IR-05", CWE: "CWE-94"},
			{Framework: "CMMC_v2", ControlID: "CMMC_v2/SI.L1-3.14.1", CWE: "CWE-94"},
			{Framework: "VERIS_VCDB_V2", ControlID: "VERIS_VCDB_V2/VERIS-ACT-1.1", CWE: "CWE-94"},
			{Framework: "TOMS_GDPR_ART32", ControlID: "TOMS_GDPR_ART32/TOM-TECH-1.13", CWE: "CWE-94"},
		},
	},
	{
		ID:          "CVE-2024-3094",
		Name:        "xz-utils Supply Chain Backdoor",
		CWE:         "CWE-506",
		Positive:    true,
		MinMappings: 5,
		MaxMappings: 25,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/CC6.8", CWE: "CWE-506"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/5.1", CWE: "CWE-506"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.7", CWE: "CWE-506"},
			{Framework: "HIPAA_SECURITY_RULE_2013", ControlID: "HIPAA_SECURITY_RULE_2013/164.308(a)(5)(ii)(B)", CWE: "CWE-506"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-3", CWE: "CWE-506"},
			{Framework: "CMMC_v2", ControlID: "CMMC_v2/SI.L1-3.14.1", CWE: "CWE-506"},
		},
	},
	{
		ID:          "CVE-2017-5638",
		Name:        "Apache Struts2 RCE (Equifax)",
		CWE:         "CWE-94",
		Positive:    true,
		MinMappings: 15,
		MaxMappings: 60,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/5.1", CWE: "CWE-94"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.5", CWE: "CWE-94"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.25", CWE: "CWE-94"},
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/CC6.8", CWE: "CWE-94"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-3", CWE: "CWE-94"},
			{Framework: "NIST_CSF_2_0", ControlID: "NIST_CSF_2_0/PR.IR-05", CWE: "CWE-94"},
			{Framework: "VERIS_VCDB_V2", ControlID: "VERIS_VCDB_V2/VERIS-ACT-1.1", CWE: "CWE-94"},
		},
	},
	{
		ID:          "CVE-2023-34362",
		Name:        "MOVEit Transfer SQL Injection",
		CWE:         "CWE-89",
		Positive:    true,
		MinMappings: 1,
		MaxMappings: 15,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.4", CWE: "CWE-89"},
			{Framework: "VERIS_VCDB_V2", ControlID: "VERIS_VCDB_V2/VERIS-ACT-1.4", CWE: "CWE-89"},
		},
	},
	{
		ID:          "CVE-2014-6271",
		Name:        "Shellshock (GNU Bash)",
		CWE:         "CWE-78",
		Positive:    true,
		MinMappings: 8,
		MaxMappings: 50,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "CMMC_v2", ControlID: "CMMC_v2/SI.L2-3.14.6", CWE: "CWE-78"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.4", CWE: "CWE-78"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.5", CWE: "CWE-78"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.25", CWE: "CWE-78"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.28", CWE: "CWE-78"},
			{Framework: "NIST_CSF_2_0", ControlID: "NIST_CSF_2_0/PR.IR-05", CWE: "CWE-78"},
			{Framework: "HIPAA_SECURITY_RULE_2013", ControlID: "HIPAA_SECURITY_RULE_2013/164.308(a)(5)(ii)(B)", CWE: "CWE-78"},
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/CC6.8", CWE: "CWE-78"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-3", CWE: "CWE-78"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/WS-2022.7.1", CWE: "CWE-78"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/RHEL-8.6.1", CWE: "CWE-78"},
			{Framework: "CIS_BENCHMARKS_V2", ControlID: "CIS_BENCHMARKS_V2/OS-4.2", CWE: "CWE-78"},
			{Framework: "SCAP_XCCDF_1_3", ControlID: "SCAP_XCCDF_1_3/SCAP-RHEL-8-5.1", CWE: "CWE-78"},
			{Framework: "SCAP_XCCDF_1_3", ControlID: "SCAP_XCCDF_1_3/SCAP-RHEL-8-5.2", CWE: "CWE-78"},
			{Framework: "VERIS_VCDB_V2", ControlID: "VERIS_VCDB_V2/VERIS-ACT-1.2", CWE: "CWE-78"},
			{Framework: "VERIS_VCDB_V2", ControlID: "VERIS_VCDB_V2/VERIS-VEC-1.1", CWE: "CWE-78"},
		},
	},
	{
		ID:          "CVE-2021-41773",
		Name:        "Apache HTTP Server Path Traversal",
		CWE:         "CWE-22",
		Positive:    true,
		MinMappings: 12,
		MaxMappings: 40,
		ExpectedCWEHits: []expectedMapping{
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.7.10", CWE: "CWE-22"},
			{Framework: "ISO_27001_2022", ControlID: "ISO_27001_2022/A.8.10", CWE: "CWE-22"},
			{Framework: "HIPAA_SECURITY_RULE_2013", ControlID: "HIPAA_SECURITY_RULE_2013/164.310(d)(2)(i)", CWE: "CWE-22"},
			{Framework: "SOC2_TSC_2017", ControlID: "SOC2_TSC_2017/C1.2", CWE: "CWE-22"},
			{Framework: "NIST_CSF_2_0", ControlID: "NIST_CSF_2_0/PR.DS-05", CWE: "CWE-22"},
			{Framework: "CMMC_v2", ControlID: "CMMC_v2/MP.L2-3.8.1", CWE: "CWE-22"},
			{Framework: "PCI_DSS_v4", ControlID: "PCI_DSS_v4/6.5", CWE: "CWE-22"},
			{Framework: "CIS_Controls_v8", ControlID: "CIS_Controls_v8/2.7", CWE: "CWE-22"},
			{Framework: "FEDRAMP_REV5", ControlID: "FEDRAMP_REV5/SI-10", CWE: "CWE-22"},
			{Framework: "DISA_STIGS_V2R1", ControlID: "DISA_STIGS_V2R1/APACHE-2.3.1", CWE: "CWE-22"},
			{Framework: "CIS_BENCHMARKS_V2", ControlID: "CIS_BENCHMARKS_V2/OS-1.2", CWE: "CWE-22"},
			{Framework: "SCAP_XCCDF_1_3", ControlID: "SCAP_XCCDF_1_3/SCAP-RHEL-8-1.5", CWE: "CWE-22"},
			{Framework: "VERIS_VCDB_V2", ControlID: "VERIS_VCDB_V2/VERIS-VAR-1.1", CWE: "CWE-22"},
		},
	},
}

func GetExpectation(cveID string) (cveExpectation, bool) {
	for _, exp := range expectations {
		if exp.ID == cveID {
			return exp, true
		}
	}
	return cveExpectation{}, false
}

func PositiveExpectations() []cveExpectation {
	var result []cveExpectation
	for _, exp := range expectations {
		if exp.Positive {
			result = append(result, exp)
		}
	}
	return result
}

func NegativeExpectations() []cveExpectation {
	var result []cveExpectation
	for _, exp := range expectations {
		if !exp.Positive {
			result = append(result, exp)
		}
	}
	return result
}
