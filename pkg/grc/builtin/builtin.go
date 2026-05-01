package builtin

import (
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"

	"github.com/vincents-ai/enrichment-engine/pkg/grc/acn_psnc"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/anssi_ebios"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/bio"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/bsi_grundschutz"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cen_cenelec_cra"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cen_cenelec_cyber"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cert_eu"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cis_benchmarks"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cis_controls"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cmmc"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cobit"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/csa_ccm"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/cspm"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/disa_stigs"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/dora"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/enisa_cra_mapping"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/enisa_threat"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/ens"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/etsi_nis2"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/etsi_standards"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_common_criteria"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_cra"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_cybersecurity_act"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_data_act"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_red"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eucc"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/fedramp"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/gdpr"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/hipaa"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iam"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iso27001"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/k8s_terraform"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/misp"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/mitre_attack"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nis2"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nis2_implementing_acts"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nist_csf"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/pci_dss"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/ropa"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/scap_xccdf"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/secnumcloud"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/soc2"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/toms"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/veris_vcdb"

	"github.com/vincents-ai/enrichment-engine/pkg/grc/b3s"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/bait"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_ai_act"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/kait_zait"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/ncsc_caf"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nist_cscrm"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nist_ssdf"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/slsa"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/tisax"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/vait"

	"github.com/vincents-ai/enrichment-engine/pkg/grc/mitre_attack_ics"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nist_sp800_53"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/openssf_scorecard"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/owasp_asvs"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/psd2_rts"

	"github.com/vincents-ai/enrichment-engine/pkg/grc/cyber_essentials"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eba_ict_guidelines"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/enisa_healthcare"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/enisa_supply_chain"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_cer"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/eu_mdr_cyber"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iec_62443"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iso27017"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iso27018"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iso27701"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iso42001"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/iso_sae_21434"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/nerc_cip"
	"github.com/vincents-ai/enrichment-engine/pkg/grc/swift_cscf"
)

func DefaultRegistry() *grc.Registry {
	reg := grc.NewRegistry()

	reg.Register("acn_psnc", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return acn_psnc.New(s, l) })
	reg.Register("anssi_ebios", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return anssi_ebios.New(s, l) })
	reg.Register("bio", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return bio.New(s, l) })
	reg.Register("bsi_grundschutz", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return bsi_grundschutz.New(s, l) })
	reg.Register("cen_cenelec_cra", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cen_cenelec_cra.New(s, l) })
	reg.Register("cen_cenelec_cyber", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cen_cenelec_cyber.New(s, l) })
	reg.Register("cert_eu", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cert_eu.New(s, l) })
	reg.Register("cis_benchmarks", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cis_benchmarks.New(s, l) })
	reg.Register("cis_controls", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cis_controls.New(s, l) })
	reg.Register("cmmc", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cmmc.New(s, l) })
	reg.Register("cobit", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cobit.New(s, l) })
	reg.Register("csa_ccm", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return csa_ccm.New(s, l) })
	reg.Register("cspm", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cspm.New(s, l) })
	reg.Register("disa_stigs", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return disa_stigs.New(s, l) })
	reg.Register("dora", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return dora.New(s, l) })
	reg.Register("enisa_cra_mapping", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return enisa_cra_mapping.New(s, l) })
	reg.Register("enisa_threat", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return enisa_threat.New(s, l) })
	reg.Register("ens", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return ens.New(s, l) })
	reg.Register("etsi_nis2", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return etsi_nis2.New(s, l) })
	reg.Register("etsi_standards", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return etsi_standards.New(s, l) })
	reg.Register("eucc", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eucc.New(s, l) })
	reg.Register("eu_common_criteria", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_common_criteria.New(s, l) })
	reg.Register("eu_cra", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_cra.New(s, l) })
	reg.Register("eu_cybersecurity_act", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_cybersecurity_act.New(s, l) })
	reg.Register("eu_data_act", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_data_act.New(s, l) })
	reg.Register("eu_red", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_red.New(s, l) })
	reg.Register("fedramp", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return fedramp.New(s, l) })
	reg.Register("gdpr", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return gdpr.New(s, l) })
	reg.Register("hipaa", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return hipaa.New(s, l) })
	reg.Register("iam", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iam.New(s, l) })
	reg.Register("iso27001", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iso27001.New(s, l) })
	reg.Register("k8s_terraform", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return k8s_terraform.New(s, l) })
	reg.Register("misp", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return misp.New(s, l) })
	reg.Register("mitre_attack", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return mitre_attack.New(s, l) })
	reg.Register("nis2", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nis2.New(s, l) })
	reg.Register("nis2_implementing_acts", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nis2_implementing_acts.New(s, l) })
	reg.Register("nist_csf", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nist_csf.New(s, l) })
	reg.Register("pci_dss", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return pci_dss.New(s, l) })
	reg.Register("ropa", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return ropa.New(s, l) })
	reg.Register("scap_xccdf", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return scap_xccdf.New(s, l) })
	reg.Register("secnumcloud", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return secnumcloud.New(s, l) })
	reg.Register("soc2", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return soc2.New(s, l) })
	reg.Register("toms", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return toms.New(s, l) })
	reg.Register("veris_vcdb", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return veris_vcdb.New(s, l) })

	reg.Register("b3s", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return b3s.New(s, l) })
	reg.Register("bait", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return bait.New(s, l) })
	reg.Register("eu_ai_act", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_ai_act.New(s, l) })
	reg.Register("kait_zait", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return kait_zait.New(s, l) })
	reg.Register("ncsc_caf", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return ncsc_caf.New(s, l) })
	reg.Register("nist_cscrm", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nist_cscrm.New(s, l) })
	reg.Register("nist_ssdf", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nist_ssdf.New(s, l) })
	reg.Register("slsa", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return slsa.New(s, l) })
	reg.Register("tisax", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return tisax.New(s, l) })
	reg.Register("vait", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return vait.New(s, l) })

	reg.Register("mitre_attack_ics", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return mitre_attack_ics.New(s, l) })
	reg.Register("nist_sp800_53", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nist_sp800_53.New(s, l) })
	reg.Register("openssf_scorecard", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return openssf_scorecard.New(s, l) })
	reg.Register("owasp_asvs", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return owasp_asvs.New(s, l) })
	reg.Register("psd2_rts", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return psd2_rts.New(s, l) })
	reg.Register("eba_ict_guidelines", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eba_ict_guidelines.New(s, l) })
	reg.Register("cyber_essentials", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return cyber_essentials.New(s, l) })
	reg.Register("enisa_supply_chain", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return enisa_supply_chain.New(s, l) })
	reg.Register("enisa_healthcare", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return enisa_healthcare.New(s, l) })
	reg.Register("nerc_cip", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nerc_cip.New(s, l) })
	reg.Register("eu_cer", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_cer.New(s, l) })
	reg.Register("eu_mdr_cyber", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return eu_mdr_cyber.New(s, l) })
	reg.Register("iso_sae_21434", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iso_sae_21434.New(s, l) })
	reg.Register("swift_cscf", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return swift_cscf.New(s, l) })

	reg.Register("iec_62443", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iec_62443.New(s, l) })
	reg.Register("iso27017", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iso27017.New(s, l) })
	reg.Register("iso27018", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iso27018.New(s, l) })
	reg.Register("iso27701", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iso27701.New(s, l) })
	reg.Register("iso42001", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return iso42001.New(s, l) })

	return reg
}
