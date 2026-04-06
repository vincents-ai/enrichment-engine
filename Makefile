BINARY_NAME := enrich
BUILD_DIR := ./bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

.PHONY: all build test test-all test-unit test-integration test-behavioral test-scenario lint fmt clean

all: lint test build

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/enrich

test: test-unit test-integration test-behavioral

test-unit:
	CGO_ENABLED=0 go test ./pkg/...

test-integration:
	CGO_ENABLED=0 go test ./test/integration/...

test-behavioral:
	CGO_ENABLED=0 GODOG=1 go test ./test/behavioral/...

test-scenario:
	CGO_ENABLED=0 go test -tags integration ./test/scenario/...

test-all: test test-scenario

lint:
	CGO_ENABLED=0 golangci-lint run ./...

fmt:
	CGO_ENABLED=0 gofmt -w .
	CGO_ENABLED=0 goimports -local github.com/shift/enrichment-engine -w .

clean:
	rm -rf $(BUILD_DIR)

# GRC data acquisition targets (ADR-015: build-time fetch, airgap-safe)
.PHONY: fetch-grc fetch-grc/owasp_asvs fetch-grc/mitre_attack_ics fetch-grc/nist_sp800_53 \
        fetch-grc/nist_cscrm fetch-grc/eba_ict_guidelines fetch-grc/iso27017 \
        fetch-grc/iso27701 fetch-grc/iso42001 fetch-grc/iso_sae_21434 \
        fetch-grc/iso27018 fetch-grc/iec_62443

fetch-grc: fetch-grc/owasp_asvs fetch-grc/mitre_attack_ics fetch-grc/nist_sp800_53 \
           fetch-grc/nist_cscrm

## Pattern A: free public sources — download at build time
fetch-grc/owasp_asvs:
	@echo "Fetching OWASP ASVS v4.0.3 catalog..."
	@mkdir -p pkg/grc/owasp_asvs
	curl -fsSL 'https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/docs_en/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.csv' \
	  -o pkg/grc/owasp_asvs/owasp_asvs_v4.csv
	@echo "OWASP ASVS: done."

fetch-grc/mitre_attack_ics:
	@echo "Fetching MITRE ATT&CK for ICS v16..."
	@mkdir -p pkg/grc/mitre_attack_ics
	curl -fsSL 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json' \
	  -o pkg/grc/mitre_attack_ics/ics_attack.json
	@echo "MITRE ATT&CK ICS: done."

fetch-grc/nist_sp800_53:
	@echo "Fetching NIST SP 800-53 Rev.5 OSCAL catalog..."
	@mkdir -p pkg/grc/nist_sp800_53
	curl -fsSL 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json' \
	  -o pkg/grc/nist_sp800_53/nist_sp800_53_r5_catalog.json
	@echo "NIST SP 800-53: done."

fetch-grc/nist_cscrm:
	@echo "Fetching NIST SP 800-161r1 C-SCRM catalog..."
	@mkdir -p pkg/grc/nist_cscrm
	curl -fsSL 'https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/800-161r1/export/json' \
	  -o pkg/grc/nist_cscrm/nist_cscrm_800_161r1.json || \
	  curl -fsSL 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-161/rev1/json/NIST_SP-800-161r1_catalog.json' \
	  -o pkg/grc/nist_cscrm/nist_cscrm_800_161r1.json
	@echo "NIST C-SCRM: done."

## Pattern B: paid/restricted sources — user must provide the file
fetch-grc/eba_ict_guidelines:
	@echo "EBA ICT Guidelines: using pre-populated embedded controls (eba_ict_controls.json already in repo)."
	@test -f pkg/grc/eba_ict_guidelines/eba_ict_controls.json || \
	  (echo "ERROR: pkg/grc/eba_ict_guidelines/eba_ict_controls.json missing." && exit 1)

fetch-grc/iso27017:
	@test -f pkg/grc/iso27017/iso27017_controls.json || \
	  (echo "" && \
	   echo "ERROR: ISO/IEC 27017 controls file missing." && \
	   echo "ISO/IEC 27017 is a paid standard. To enable this provider:" && \
	   echo "  1. Purchase ISO/IEC 27017:2015 from https://www.iso.org/standard/43757.html" && \
	   echo "  2. Extract Annex A controls to JSON format:" && \
	   echo "     [{\"id\":\"CLD.6.3.1\",\"title\":\"...\",\"family\":\"...\",\"description\":\"...\",\"cwes\":[],\"tags\":[]}]" && \
	   echo "  3. Place at pkg/grc/iso27017/iso27017_controls.json" && \
	   echo "" && exit 1)

fetch-grc/iso27701:
	@test -f pkg/grc/iso27701/iso27701_controls.json || \
	  (echo "" && \
	   echo "ERROR: ISO/IEC 27701 controls file missing." && \
	   echo "ISO/IEC 27701 is a paid standard. To enable this provider:" && \
	   echo "  1. Purchase ISO/IEC 27701:2019 from https://www.iso.org/standard/71670.html" && \
	   echo "  2. Extract Annex B+C controls to JSON format" && \
	   echo "  3. Place at pkg/grc/iso27701/iso27701_controls.json" && \
	   echo "" && exit 1)

fetch-grc/iso42001:
	@test -f pkg/grc/iso42001/iso42001_controls.json || \
	  (echo "" && \
	   echo "ERROR: ISO/IEC 42001 controls file missing." && \
	   echo "ISO/IEC 42001 is a paid standard. To enable this provider:" && \
	   echo "  1. Purchase ISO/IEC 42001:2023 from https://www.iso.org/standard/81230.html" && \
	   echo "  2. Extract Annex A controls to JSON format" && \
	   echo "  3. Place at pkg/grc/iso42001/iso42001_controls.json" && \
	   echo "" && exit 1)

fetch-grc/iso_sae_21434:
	@test -f pkg/grc/iso_sae_21434/iso_sae_21434_controls.json || \
	  (echo "" && \
	   echo "ERROR: ISO/SAE 21434 controls file missing." && \
	   echo "ISO/SAE 21434 is a paid standard. To enable this provider:" && \
	   echo "  1. Purchase ISO/SAE 21434:2021 from https://www.iso.org/standard/70918.html" && \
	   echo "  2. Extract work products to JSON format" && \
	   echo "  3. Place at pkg/grc/iso_sae_21434/iso_sae_21434_controls.json" && \
	   echo "" && exit 1)

fetch-grc/iso27018:
	@test -f pkg/grc/iso27018/iso27018_controls.json || \
	  (echo "" && \
	   echo "ERROR: ISO/IEC 27018 controls file missing." && \
	   echo "ISO/IEC 27018 is a paid standard. To enable this provider:" && \
	   echo "  1. Purchase ISO/IEC 27018:2019 from https://www.iso.org/standard/76559.html" && \
	   echo "  2. Extract Annex A controls to JSON format" && \
	   echo "  3. Place at pkg/grc/iso27018/iso27018_controls.json" && \
	   echo "" && exit 1)

fetch-grc/iec_62443:
	@test -f pkg/grc/iec_62443/iec_62443_controls.json || \
	  (echo "" && \
	   echo "ERROR: IEC 62443 controls file missing." && \
	   echo "IEC 62443 is a paid standard series. To enable this provider:" && \
	   echo "  1. Purchase IEC 62443-3-3 and IEC 62443-4-2 from https://www.isa.org/isa99" && \
	   echo "  2. Extract SR/CR requirements to JSON format:" && \
	   echo "     [{\"id\":\"SR-1.1\",\"title\":\"...\",\"fr\":\"IAC\",\"sl\":\"1\",\"description\":\"...\",\"cwes\":[],\"tags\":[]}]" && \
	   echo "  3. Place at pkg/grc/iec_62443/iec_62443_controls.json" && \
	   echo "" && exit 1)
