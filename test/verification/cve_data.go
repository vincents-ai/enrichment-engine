package verification

import (
	"encoding/json"
)

type cveRecord struct {
	ID  string `json:"id"`
	CVE struct {
		ID           string `json:"id"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Weaknesses []struct {
			Description []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description"`
		} `json:"weaknesses"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Criteria              string `json:"criteria"`
					Vulnerable            bool   `json:"vulnerable"`
					VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
					VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
		Metrics struct {
			CvssMetricV31 []struct {
				CvssData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
					VectorString string  `json:"vectorString"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
		References []struct {
			URL    string `json:"url"`
			Source string `json:"source"`
		} `json:"references"`
	} `json:"cve"`
}

func (r *cveRecord) ToMap() map[string]interface{} {
	data, _ := json.Marshal(r)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	return m
}

var (
	CVE_2021_44228 = cveRecord{
		ID: "CVE-2021-44228",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2021-44228",
			Published:    "2021-12-10T15:15:07.530Z",
			LastModified: "2024-11-21T05:32:23.950Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is distinct from CVE-2021-45046, CVE-2021-45105, CVE-2021-44832, and CVE-2021-45105."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-502"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "2.15.0"},
					}},
				}},
			},
			References: []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			}{
				{URL: "https://logging.apache.org/log4j/2.x/security.html", Source: "MISC"},
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", Source: "NVD"},
			},
		},
	}

	CVE_2014_0160 = cveRecord{
		ID: "CVE-2014-0160",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2014-0160",
			Published:    "2014-04-07T22:55:07.067Z",
			LastModified: "2024-11-21T02:42:01.060Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-119"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Vulnerable: true, VersionStartIncluding: "1.0.1", VersionEndExcluding: "1.0.1g"},
					}},
				}},
			},
		},
	}

	CVE_2022_22965 = cveRecord{
		ID: "CVE-2022-22965",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2022-22965",
			Published:    "2022-03-31T15:15:08.520Z",
			LastModified: "2024-11-21T05:19:52.950Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-94"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*", Vulnerable: true, VersionStartIncluding: "5.3.0", VersionEndExcluding: "5.3.18"},
						{Criteria: "cpe:2.3:a:vmware:spring_framework:5.2.0:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "5.2.20"},
					}},
				}},
			},
		},
	}

	CVE_2024_3094 = cveRecord{
		ID: "CVE-2024-3094",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2024-3094",
			Published:    "2024-03-29T22:15:49.630Z",
			LastModified: "2024-11-21T05:21:59.210Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "xz-utils 5.6.0 and 5.6.1 changed the build system to integrate a malicious object that hooks into liblzma's build process. The backdoor allows unauthorized access via SSH, potentially compromising the entire system. The malicious code modifies the authentication process, enabling remote code execution during SSH login."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-506"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", Vulnerable: true},
						{Criteria: "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*", Vulnerable: true},
					}},
				}},
			},
		},
	}

	CVE_2014_6271 = cveRecord{
		ID: "CVE-2014-6271",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2014-6271",
			Published:    "2014-09-24T10:55:07.067Z",
			LastModified: "2024-11-21T02:42:24.577Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka Shellshock."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-78"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "4.3"},
					}},
				}},
			},
		},
	}

	CVE_2017_5638 = cveRecord{
		ID: "CVE-2017-5638",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2017-5638",
			Published:    "2017-03-10T08:59:00.307Z",
			LastModified: "2024-11-21T02:42:24.880Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "The Jakarta Multipart parser in Apache Struts 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 mishandles file upload, which allows remote attackers to execute arbitrary commands via a crafted Content-Type header."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-94"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*", Vulnerable: true, VersionStartIncluding: "2.3.0", VersionEndExcluding: "2.3.32"},
					}},
				}},
			},
		},
	}

	CVE_2021_41773 = cveRecord{
		ID: "CVE-2021-41773",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2021-41773",
			Published:    "2021-10-05T16:15:07.563Z",
			LastModified: "2024-11-21T05:21:16.620Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "A path traversal and file disclosure vulnerability was found in Apache HTTP Server 2.4.49. A crafted request can map to files outside the expected document root. If files outside the document root are not protected by default configuration, a remote attacker can access them."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-22"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", Vulnerable: true},
					}},
				}},
			},
		},
	}

	CVE_2023_34362 = cveRecord{
		ID: "CVE-2023-34362",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2023-34362",
			Published:    "2023-06-14T15:15:07.807Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "A critical remote code execution (RCE) vulnerability in MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access via SQL injection. This vulnerability allows an attacker to execute arbitrary code on the affected system, leading to complete system compromise."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-89"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*", Vulnerable: true, VersionStartIncluding: "2023.0.0", VersionEndExcluding: "2023.0.6"},
					}},
				}},
			},
		},
	}

	CVE_2022_26134 = cveRecord{
		ID: "CVE-2022-26134",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2022-26134",
			Published:    "2022-06-02T18:15:09.337Z",
			LastModified: "2024-11-21T05:22:41.440Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "Broken access control in Atlassian Confluence Server and Data Center allowed an unauthenticated attacker to reset Confluence and perform RCE."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-287"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "7.14.0"},
					}},
				}},
			},
		},
	}

	CVE_2021_4034 = cveRecord{
		ID: "CVE-2021-4034",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2021-4034",
			Published:    "2022-01-25T21:15:08.020Z",
			LastModified: "2024-11-21T05:22:41.590Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "A local privilege escalation vulnerability was found in polkit's pkexec. This vulnerability allows any unprivileged user to gain full root privileges on the system."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-269"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:polkit_project:polkit:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "0.120"},
					}},
				}},
			},
		},
	}

	CVE_2023_42793 = cveRecord{
		ID: "CVE-2023-42793",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2023-42793",
			Published:    "2023-09-19T14:15:11.437Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "JetBrains TeamCity was vulnerable to an authentication bypass that allowed an unauthenticated attacker to perform RCE."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-862"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "2023.05.4"},
					}},
				}},
			},
		},
	}

	CVE_2023_44487 = cveRecord{
		ID: "CVE-2023-44487",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2023-44487",
			Published:    "2023-10-10T18:15:10.747Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "Multiple HTTP/2 implementations are vulnerable to a denial of service attack through rapid stream resets."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-400"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:cloudflare:cloudflare:*:*:*:*:*:*:*:*", Vulnerable: true},
					}},
				}},
			},
		},
	}

	CVE_2023_20198 = cveRecord{
		ID: "CVE-2023-20198",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2023-20198",
			Published:    "2023-10-16T20:15:11.397Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "A vulnerability in the web UI feature of Cisco IOS XE Software could allow an unauthenticated attacker to bypass authentication and execute arbitrary commands."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-306"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*", Vulnerable: true, VersionStartIncluding: "16.9.1", VersionEndExcluding: "17.3.8a"},
					}},
				}},
			},
		},
	}

	CVE_2019_11510 = cveRecord{
		ID: "CVE-2019-11510",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2019-11510",
			Published:    "2019-08-08T20:15:12.717Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "An arbitrary file reading vulnerability in Pulse Secure Pulse Connect Secure allows an unauthenticated attacker to read sensitive files."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-200"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:pulse_secure:pulse_connect_secure:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "9.1R11.4"},
					}},
				}},
			},
		},
	}

	CVE_2024_0001 = cveRecord{
		ID: "CVE-2024-0001",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2024-0001",
			Published:    "2024-01-18T23:15:09.287Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "A vulnerability in the DNSSEC verification mechanism for EdDSA signatures in BIND 9 allows an attacker to cause the resolver to crash."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-319"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:isc:bind:9.16.0:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "9.16.42"},
					}},
				}},
			},
		},
	}

	CVE_2021_22555 = cveRecord{
		ID: "CVE-2021-22555",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2021-22555",
			Published:    "2021-07-20T23:15:08.210Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "Use-after-free in netfilter nf_tables in Linux kernel allows local privilege escalation."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-122"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:kernel:linux_kernel:5.4.0:*:*:*:*:*:*:*:*", Vulnerable: true},
					}},
				}},
			},
		},
	}

	CVE_2020_9452 = cveRecord{
		ID: "CVE-2020-9452",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2020-9452",
			Published:    "2020-03-11T18:15:11.743Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "Cross-site scripting in Zimbra allows attackers to steal cookies and session tokens."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-352"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:zimbra:zimbra_collaboration_suite:*:*:*:*:*:*:*:*", Vulnerable: true, VersionEndExcluding: "8.8.15"},
					}},
				}},
			},
		},
	}

	CVE_2023_5363 = cveRecord{
		ID: "CVE-2023-5363",
		CVE: struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		}{
			ID:           "CVE-2023-5363",
			Published:    "2023-10-24T17:15:08.490Z",
			LastModified: "2024-11-21T05:20:44.630Z",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "Processing a certificate or certificate request with a very large PSS parameter can cause infinite loop."},
			},
			Weaknesses: []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			}{
				{Description: []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				}{{Lang: "en", Value: "CWE-125"}}},
			},
			Configurations: []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			}{
				{Nodes: []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					} `json:"cpeMatch"`
				}{
					{CPEMatch: []struct {
						Criteria              string `json:"criteria"`
						Vulnerable            bool   `json:"vulnerable"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
					}{
						{Criteria: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", Vulnerable: true, VersionStartIncluding: "3.1.0", VersionEndExcluding: "3.1.4"},
					}},
				}},
			},
		},
	}
)

func AllRealCVEs() []cveRecord {
	return []cveRecord{
		CVE_2021_44228,
		CVE_2014_0160,
		CVE_2022_22965,
		CVE_2024_3094,
		CVE_2014_6271,
		CVE_2017_5638,
		CVE_2021_41773,
		CVE_2023_34362,
		CVE_2022_26134,
		CVE_2021_4034,
		CVE_2023_42793,
		CVE_2023_44487,
		CVE_2023_20198,
		CVE_2019_11510,
		CVE_2024_0001,
		CVE_2021_22555,
		CVE_2020_9452,
		CVE_2023_5363,
	}
}

func CVEByID(id string) (cveRecord, bool) {
	for _, cve := range AllRealCVEs() {
		if cve.ID == id {
			return cve, true
		}
	}
	return cveRecord{}, false
}
