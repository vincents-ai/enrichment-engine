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
}
