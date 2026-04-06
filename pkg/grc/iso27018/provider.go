package iso27018

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const FrameworkID = "ISO_27018"

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "iso27018" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("loading ISO/IEC 27018 PII in public clouds controls")

	controls := staticControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote ISO 27018 controls to storage", "count", count)
	return count, nil
}

func staticControls() []grc.Control {
	ref := func(section string) []grc.Reference {
		return []grc.Reference{{Source: "ISO/IEC 27018:2019", Section: section}}
	}

	return []grc.Control{
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.1",
			Title:       "PII Protection Policy for Cloud Services",
			Family:      "PII Controls",
			Description: "Establish a policy specifically addressing how personally identifiable information is handled within public cloud environments, covering collection, storage, processing, and deletion. The policy must be communicated to all personnel involved in cloud service delivery and to customers whose data is processed.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.1"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.2",
			Title:       "Customer PII Processing Purpose Limitation",
			Family:      "PII Controls",
			Description: "Process personal data in cloud environments only for the purposes explicitly agreed upon with the customer, and do not use it for the provider's own interests such as marketing or profiling. Any deviation from the agreed purpose requires separate consent from the data subject.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-359"},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.2"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.3",
			Title:       "PII Retention and Deletion in the Cloud",
			Family:      "PII Controls",
			Description: "Remove customer personal data from cloud infrastructure promptly after the service relationship ends or upon customer request. Deletion must cover all copies, including backups, replicas, and data stored in disaster recovery locations.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200", "CWE-532"},
			Tags:        []string{"privacy"},
			References:  ref("7.3"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.4",
			Title:       "Transparency of PII Processing in Cloud Contracts",
			Family:      "Transparency",
			Description: "Disclose to customers the geographic locations where their personal data may be stored or processed, the sub-processors involved, and the security measures in place. Transparency enables customers to make informed decisions about compliance with their own regulatory obligations.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"privacy", "governance", "supply-chain"},
			References:  ref("7.4"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.5",
			Title:       "Data Breach Notification to Cloud Customers",
			Family:      "Transparency",
			Description: "Notify affected cloud customers without undue delay when a breach involving their personal data is detected, including the nature of the compromise and the data categories affected. Timely notification allows customers to meet their own breach reporting obligations under applicable law.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-200"},
			Tags:        []string{"privacy", "logging"},
			References:  ref("7.5"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.6",
			Title:       "Data Portability and Return Mechanisms",
			Family:      "Data Portability",
			Description: "Enable customers to retrieve their personal data from the cloud in a commonly used, machine-readable format, and assist with transferring it to another provider. Data portability prevents vendor lock-in and supports the customer's right to control where their data resides.",
			Level:       "standard",
			RelatedCWEs: []string{},
			Tags:        []string{"privacy"},
			References:  ref("7.6"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.7",
			Title:       "Encryption of Customer PII by Default",
			Family:      "Privacy by Design",
			Description: "Apply encryption to personal data stored and transmitted in the cloud environment by default, without requiring the customer to request or configure it separately. The cloud provider should offer key management options that allow the customer to retain control over decryption capabilities.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-311", "CWE-319"},
			Tags:        []string{"privacy", "cryptography"},
			References:  ref("7.7"),
		},
		{
			Framework:   FrameworkID,
			ControlID:   "CLD.PII.8",
			Title:       "Restriction of Secondary Use of Customer PII",
			Family:      "Privacy by Design",
			Description: "Prevent the cloud service provider from using customer personal data for purposes beyond delivering the contracted service, such as analytics, model training, or advertising targeting. Contractual and technical controls should enforce this restriction even across organisational boundaries within the provider.",
			Level:       "standard",
			RelatedCWEs: []string{"CWE-359"},
			Tags:        []string{"privacy", "governance"},
			References:  ref("7.8"),
		},
	}
}
