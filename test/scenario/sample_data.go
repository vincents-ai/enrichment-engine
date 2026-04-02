package scenario

var sampleNVDCVEs = []map[string]interface{}{
	{
		"id": "CVE-2024-12345",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-12345",
			"published": "2024-01-15T12:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Cross-site scripting vulnerability in Apache Log4j"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-79"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-67890",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-67890",
			"published": "2024-03-20T08:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "SQL injection vulnerability in web application"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-89"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:*:webapp:1.0.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-11111",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-11111",
			"published": "2024-05-10T14:30:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Buffer overflow in cryptographic library"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-120"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:crypto:lib:3.1.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-22222",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-22222",
			"published": "2024-02-10T09:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Improper authentication bypass in NGINX reverse proxy"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-287"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-33333",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-33333",
			"published": "2024-04-01T11:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Sensitive data stored without encryption in PostgreSQL extension"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-311"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:postgresql:pgcrypto:1.3:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-44444",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-44444",
			"published": "2024-06-15T16:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Hardcoded administrative credentials in OpenSSH configuration tool"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-798"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
	{
		"id": "CVE-2024-55555",
		"cve": map[string]interface{}{
			"id":        "CVE-2024-55555",
			"published": "2024-07-20T10:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Information exposure through error messages in Redis"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": "CWE-200"}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": "cpe:2.3:a:redis:redis:7.0.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		},
	},
}

func makeVuln(id, cwe, cpe string) map[string]interface{} {
	return map[string]interface{}{
		"id": id,
		"cve": map[string]interface{}{
			"id":        id,
			"published": "2024-01-01T00:00:00.000Z",
			"descriptions": []map[string]string{
				{"lang": "en", "value": "Test vulnerability"},
			},
			"weaknesses": []map[string]interface{}{
				{"description": []map[string]string{{"lang": "en", "value": cwe}}},
			},
			"configurations": []map[string]interface{}{
				{"nodes": []map[string]interface{}{
					{"cpeMatch": []map[string]string{
						{"criteria": cpe},
					}},
				}},
			},
		},
	}
}
