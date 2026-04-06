package builtin

import (
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"

	"github.com/shift/enrichment-engine/pkg/grc/acn_psnc"
	"github.com/shift/enrichment-engine/pkg/grc/anssi_ebios"
	"github.com/shift/enrichment-engine/pkg/grc/bio"
	"github.com/shift/enrichment-engine/pkg/grc/bsi_grundschutz"
	"github.com/shift/enrichment-engine/pkg/grc/cen_cenelec_cra"
	"github.com/shift/enrichment-engine/pkg/grc/cen_cenelec_cyber"
	"github.com/shift/enrichment-engine/pkg/grc/cert_eu"
	"github.com/shift/enrichment-engine/pkg/grc/cis_benchmarks"
	"github.com/shift/enrichment-engine/pkg/grc/cis_controls"
	"github.com/shift/enrichment-engine/pkg/grc/cmmc"
	"github.com/shift/enrichment-engine/pkg/grc/cobit"
	"github.com/shift/enrichment-engine/pkg/grc/csa_ccm"
	"github.com/shift/enrichment-engine/pkg/grc/cspm"
	"github.com/shift/enrichment-engine/pkg/grc/disa_stigs"
	"github.com/shift/enrichment-engine/pkg/grc/dora"
	"github.com/shift/enrichment-engine/pkg/grc/enisa_cra_mapping"
	"github.com/shift/enrichment-engine/pkg/grc/enisa_threat"
	"github.com/shift/enrichment-engine/pkg/grc/ens"
	"github.com/shift/enrichment-engine/pkg/grc/etsi_nis2"
	"github.com/shift/enrichment-engine/pkg/grc/etsi_standards"
	"github.com/shift/enrichment-engine/pkg/grc/eu_common_criteria"
	"github.com/shift/enrichment-engine/pkg/grc/eu_cra"
	"github.com/shift/enrichment-engine/pkg/grc/eu_cybersecurity_act"
	"github.com/shift/enrichment-engine/pkg/grc/eu_data_act"
	"github.com/shift/enrichment-engine/pkg/grc/eu_red"
	"github.com/shift/enrichment-engine/pkg/grc/eucc"
	"github.com/shift/enrichment-engine/pkg/grc/fedramp"
	"github.com/shift/enrichment-engine/pkg/grc/gdpr"
	"github.com/shift/enrichment-engine/pkg/grc/hipaa"
	"github.com/shift/enrichment-engine/pkg/grc/iam"
	"github.com/shift/enrichment-engine/pkg/grc/iso27001"
	"github.com/shift/enrichment-engine/pkg/grc/k8s_terraform"
	"github.com/shift/enrichment-engine/pkg/grc/misp"
	"github.com/shift/enrichment-engine/pkg/grc/mitre_attack"
	"github.com/shift/enrichment-engine/pkg/grc/nis2"
	"github.com/shift/enrichment-engine/pkg/grc/nis2_implementing_acts"
	"github.com/shift/enrichment-engine/pkg/grc/nist_csf"
	"github.com/shift/enrichment-engine/pkg/grc/nist_oscal"
	"github.com/shift/enrichment-engine/pkg/grc/pci_dss"
	"github.com/shift/enrichment-engine/pkg/grc/ropa"
	"github.com/shift/enrichment-engine/pkg/grc/scap_xccdf"
	"github.com/shift/enrichment-engine/pkg/grc/secnumcloud"
	"github.com/shift/enrichment-engine/pkg/grc/soc2"
	"github.com/shift/enrichment-engine/pkg/grc/toms"
	"github.com/shift/enrichment-engine/pkg/grc/veris_vcdb"

	"github.com/shift/enrichment-engine/pkg/grc/b3s"
	"github.com/shift/enrichment-engine/pkg/grc/bait"
	"github.com/shift/enrichment-engine/pkg/grc/eu_ai_act"
	"github.com/shift/enrichment-engine/pkg/grc/kait_zait"
	"github.com/shift/enrichment-engine/pkg/grc/ncsc_caf"
	"github.com/shift/enrichment-engine/pkg/grc/nist_ssdf"
	"github.com/shift/enrichment-engine/pkg/grc/slsa"
	"github.com/shift/enrichment-engine/pkg/grc/tisax"
	"github.com/shift/enrichment-engine/pkg/grc/vait"
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
	reg.Register("nist_oscal", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nist_oscal.New(s, l) })
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
	reg.Register("nist_ssdf", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return nist_ssdf.New(s, l) })
	reg.Register("slsa", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return slsa.New(s, l) })
	reg.Register("tisax", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return tisax.New(s, l) })
	reg.Register("vait", func(s storage.Backend, l *slog.Logger) grc.GRCProvider { return vait.New(s, l) })

	return reg
}
