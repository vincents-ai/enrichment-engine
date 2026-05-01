package secnumcloud

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "SECNUMCLOUD_EUCS_2024"
	CatalogURL  = ""
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "secnumcloud"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("running secnumcloud provider")
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded SecNumCloud/EUCS controls")
	controls := embeddedControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	p.logger.Info("wrote embedded controls to storage", "count", count)
	return count, nil
}

func embeddedControls() []grc.Control {
	controls := []grc.Control{}

	governance := []struct {
		id, title, desc, level string
	}{
		{"I.1.1", "Politique de sécurité de l'information cloud", "Le prestataire de services cloud doit établir, documenter et maintenir une politique de sécurité de l'information spécifique aux services cloud, approuvée par la direction, qui définit les objectifs, le périmètre et les engagements de sécurité.", "basic"},
		{"I.1.2", "Organisation de la sécurité", "Le prestataire doit définir une structure organisationnelle pour la sécurité de l'information, incluant la nomination d'un RSSI (Responsable de la Sécurité des Systèmes d'Information) avec l'autorité et les ressources nécessaires.", "basic"},
		{"I.1.3", "Gestion des risques", "Le prestataire doit mettre en œuvre un processus de gestion des risques couvrant l'ensemble des services cloud, incluant l'identification, l'évaluation et le traitement des risques de sécurité de l'information.", "substantial"},
	}

	hr := []struct {
		id, title, desc, level string
	}{
		{"I.2.1", "Vérification des antécédents du personnel", "Le prestataire doit effectuer des vérifications des antécédents de tout le personnel ayant accès aux systèmes, aux données ou aux installations cloud, avant leur recrutement et pendant toute la durée de leur emploi.", "basic"},
		{"I.2.2", "Formation et sensibilisation à la sécurité", "Le prestataire doit mettre en place un programme de formation et de sensibilisation à la sécurité de l'information pour tout le personnel, adapté aux rôles et responsabilités de chacun.", "basic"},
		{"I.2.3", "Processus disciplinaire", "Le prestataire doit établir un processus disciplinaire formel pour les cas de violation de la politique de sécurité de l'information par le personnel.", "substantial"},
	}

	asset := []struct {
		id, title, desc, level string
	}{
		{"I.3.1", "Inventaire des actifs", "Le prestataire doit maintenir un inventaire complet et à jour de tous les actifs informationnels, physiques et logiciels utilisés pour la prestation des services cloud.", "basic"},
		{"I.3.2", "Classification des informations", "Le prestataire doit classifier les informations traitées dans le cloud selon leur niveau de sensibilité et appliquer des mesures de protection proportionnelles à chaque niveau de classification.", "basic"},
		{"I.3.3", "Gestion du cycle de vie des données", "Le prestataire doit implémenter des processus de gestion du cycle de vie des données incluant la création, le stockage, l'utilisation, le partage, l'archivage et la destruction sécurisée des données.", "substantial"},
	}

	access := []struct {
		id, title, desc, level string
	}{
		{"I.4.1", "Contrôle d'accès logique", "Le prestataire doit implémenter des contrôles d'accès logique basés sur le principe du moindre privilège, avec une gestion stricte des droits d'accès aux systèmes, applications et données cloud.", "basic"},
		{"I.4.2", "Authentification forte", "Le prestataire doit fournir des mécanismes d'authentification forte (MFA) pour l'accès aux interfaces d'administration et de gestion des services cloud, et recommander leur utilisation pour les utilisateurs finaux.", "substantial"},
		{"I.4.3", "Gestion des identités", "Le prestataire doit implémenter un système de gestion des identités (IAM) couvrant le cycle de vie complet des identités, incluant la provisionnement, la modification et la révocation des accès.", "high"},
		{"I.4.4", "Gestion des accès privilégiés", "Le prestataire doit restreindre et contrôler strictement les accès privilégiés aux systèmes d'exploitation, aux bases de données et aux outils d'administration, avec traçabilité de toutes les actions.", "high"},
	}

	crypto := []struct {
		id, title, desc, level string
	}{
		{"I.5.1", "Politique cryptographique", "Le prestataire doit établir une politique cryptographique définissant les standards, algorithmes et protocoles de chiffrement utilisés pour protéger les données et les communications.", "basic"},
		{"I.5.2", "Gestion des clés cryptographiques", "Le prestataire doit implémenter un système de gestion des clés cryptographiques couvrant la génération, la distribution, le stockage, la rotation et la destruction des clés, de préférence via un module matériel de sécurité (HSM).", "substantial"},
		{"I.5.3", "Chiffrement des données", "Le prestataire doit chiffrer les données sensibles au repos et en transit, en utilisant des algorithmes approuvés par l'ANSSI et des longueurs de clé conformes aux recommandations en vigueur.", "substantial"},
	}

	ops := []struct {
		id, title, desc, level string
	}{
		{"I.6.1", "Gestion des configurations", "Le prestataire doit établir et maintenir des configurations de sécurité pour tous les composants de l'infrastructure cloud, incluant des procédures de durcissement (hardening) basées sur les recommandations de l'ANSSI.", "basic"},
		{"I.6.2", "Gestion des vulnérabilités", "Le prestataire doit mettre en place un processus de gestion des vulnérabilités incluant la veille, l'évaluation, la correction et le suivi des vulnérabilités dans les délais requis par le niveau de criticité.", "basic"},
		{"I.6.3", "Protection contre les logiciels malveillants", "Le prestataire doit déployer des mécanismes de détection et de protection contre les logiciels malveillants sur tous les systèmes, avec mise à jour régulière des signatures et des moteurs d'analyse.", "basic"},
		{"I.6.4", "Gestion des changements", "Le prestataire doit mettre en place un processus formel de gestion des changements pour toutes les modifications de l'infrastructure cloud, incluant l'évaluation de l'impact sur la sécurité avant déploiement.", "substantial"},
	}

	comms := []struct {
		id, title, desc, level string
	}{
		{"I.7.1", "Sécurité des réseaux", "Le prestataire doit segmenter les réseaux pour isoler les environnements clients et les systèmes d'administration, avec des contrôles de sécurité aux points d'interconnexion (firewalls, IDS/IPS).", "basic"},
		{"I.7.2", "Sécurité des communications", "Le prestataire doit protéger toutes les communications de gestion et de données par des protocoles cryptographiques robustes (TLS 1.3, IPSec), avec vérification de l'intégrité et de l'authenticité.", "substantial"},
		{"I.7.3", "Protection contre les attaques réseau", "Le prestataire doit implémenter des protections contre les attaques réseau courantes (DDoS, MITM, injection) et disposer de capacités de détection et de réponse aux incidents réseau.", "substantial"},
	}

	supply := []struct {
		id, title, desc, level string
	}{
		{"I.8.1", "Sécurité de la chaîne d'approvisionnement", "Le prestataire doit évaluer et gérer les risques de sécurité liés à la chaîne d'approvisionnement, incluant la sélection, l'évaluation et le suivi régulier des sous-traitants et fournisseurs.", "basic"},
		{"I.8.2", "Clause de sécurité dans les contrats", "Le prestataire doit inclure des clauses de sécurité de l'information dans tous les contrats avec les fournisseurs et sous-traitants, définissant les exigences de sécurité et les obligations de notification d'incidents.", "substantial"},
		{"I.8.3", "Vérification de l'origine des composants", "Le prestataire doit mettre en place des processus pour vérifier l'origine et l'intégrité des composants logiciels et matériels utilisés dans l'infrastructure cloud (Software Bill of Materials).", "high"},
	}

	physical := []struct {
		id, title, desc, level string
	}{
		{"I.9.1", "Sécurité physique des centres de données", "Le prestataire doit protéger physiquement les centres de données hébergeant les services cloud avec des contrôles d'accès, surveillance vidéo, détection d'intrusion et protection contre les risques environnementaux.", "basic"},
		{"I.9.2", "Contrôle d'accès physique", "L'accès aux zones sensibles des centres de données doit être strictement contrôlé, enregistré et limité au personnel autorisé, avec un système d'authentification multi-facteurs pour l'accès physique.", "substantial"},
		{"I.9.3", "Protection contre les sinistres", "Le prestataire doit mettre en place des mesures de protection contre les sinistres (incendie, inondation, panne électrique) incluant des systèmes de détection, d'extinction et des alimentations de secours.", "substantial"},
	}

	monitoring := []struct {
		id, title, desc, level string
	}{
		{"I.10.1", "Surveillance de la sécurité", "Le prestataire doit mettre en place une surveillance continue de la sécurité des systèmes et des réseaux cloud, incluant la détection d'anomalies, d'activités suspectes et de tentatives d'intrusion.", "basic"},
		{"I.10.2", "Gestion des incidents de sécurité", "Le prestataire doit établir un processus formel de gestion des incidents de sécurité incluant la détection, l'analyse, la confinement, l'éradication, le rétablissement et les leçons apprises.", "basic"},
		{"I.10.3", "Notification des incidents", "Le prestataire doit notifier les incidents de sécurité affectant les services clients dans les délais contractuels, incluant la nature de l'incident, l'impact et les mesures correctives prises.", "substantial"},
		{"I.10.4", "Centre opérationnel de sécurité (SOC)", "Le prestataire doit disposer d'un centre opérationnel de sécurité (SOC) assurant une surveillance 24/7 avec des analystes qualifiés et des processus d'escalade documentés.", "high"},
	}

	continuity := []struct {
		id, title, desc, level string
	}{
		{"I.11.1", "Plan de continuité d'activité", "Le prestataire doit établir et maintenir un plan de continuité d'activité (PCA) pour les services cloud, incluant les procédures, les ressources et les responsabilités pour assurer la continuité en cas d'incident majeur.", "basic"},
		{"I.11.2", "Plan de reprise après sinistre", "Le prestataire doit établir un plan de reprise après sinistre (PRA) avec des objectifs de temps de reprise (RTO) et de point de reprise (RPO) définis contractuellement pour chaque niveau de service.", "substantial"},
		{"I.11.3", "Tests de continuité", "Le prestataire doit effectuer régulièrement des tests des plans de continuité et de reprise pour vérifier leur efficacité et les mettre à jour en fonction des résultats.", "substantial"},
		{"I.11.4", "Redondance et haute disponibilité", "Le prestataire doit implémenter des architectures redondantes pour les services critiques, incluant la répartition géographique des infrastructures pour assurer la résilience face aux pannes.", "high"},
	}

	privacy := []struct {
		id, title, desc, level string
	}{
		{"I.12.1", "Protection des données personnelles", "Le prestataire doit mettre en œuvre des mesures techniques et organisationnelles pour assurer la protection des données personnelles traitées dans le cadre des services cloud, en conformité avec le RGPD.", "basic"},
		{"I.12.2", "Souveraineté des données", "Le prestataire doit garantir que les données clients sont stockées et traitées dans des juridictions déterminées, et ne sont pas accessibles par des autorités étrangères en dehors du cadre légal applicable.", "substantial"},
		{"I.12.3", "Droits des personnes concernées", "Le prestataire doit assister les clients dans l'exercice des droits des personnes concernées (accès, rectification, effacement, portabilité) et fournir les outils nécessaires à cet effet.", "substantial"},
	}

	iam := []struct {
		id, title, desc, level string
	}{
		{"I.13.1", "Gestion des identités fédérées", "Le prestataire doit supporter les mécanismes d'identité fédérée (SAML, OpenID Connect) permettant aux clients d'intégrer leurs propres systèmes d'authentification avec les services cloud.", "substantial"},
		{"I.13.2", "Séparation des responsabilités d'administration", "Le prestataire doit séparer les responsabilités d'administration entre le prestataire (administration de l'infrastructure) et le client (administration des services), avec des interfaces de gestion distinctes.", "high"},
	}

	vuln := []struct {
		id, title, desc, level string
	}{
		{"I.14.1", "Veille sur les vulnérabilités", "Le prestataire doit maintenir une veille proactive sur les vulnérabilités affectant les composants de l'infrastructure cloud, incluant le suivi des alertes CERT/ANSSI et des CVE.", "basic"},
		{"I.14.2", "Correction des vulnérabilités dans les délais", "Le prestataire doit corriger les vulnérabilités critiques dans un délai maximal de 15 jours, les vulnérabilités élevées dans un délai de 30 jours, et les autres vulnérabilités selon un planning défini.", "substantial"},
		{"I.14.3", "Partage des informations de vulnérabilité", "Le prestataire doit informer les clients des vulnérabilités affectant les composants qu'ils utilisent et des mesures correctives prises ou à prendre.", "substantial"},
	}

	logging := []struct {
		id, title, desc, level string
	}{
		{"I.15.1", "Journalisation des événements de sécurité", "Le prestataire doit enregistrer les événements de sécurité significatifs (authentifications, changements de configuration, accès aux données) dans des journaux protégés contre la modification et la suppression.", "basic"},
		{"I.15.2", "Rétention des journaux", "Le prestataire doit conserver les journaux de sécurité pendant une durée minimale d'un an, avec une capacité d'analyse en temps réel et des sauvegardes régulières des journaux.", "substantial"},
		{"I.15.3", "Analyse forensique", "Le prestataire doit avoir la capacité de mener des investigations forensiques en cas d'incident de sécurité, incluant la préservation des preuves et l'analyse des journaux.", "high"},
	}

	all := [][]struct {
		id, title, desc, level string
	}{governance, hr, asset, access, crypto, ops, comms, supply, physical, monitoring, continuity, privacy, iam, vuln, logging}

	families := []string{
		"I.1 Gouvernance et organisation",
		"I.2 Sécurité des ressources humaines",
		"I.3 Gestion des actifs",
		"I.4 Contrôle d'accès",
		"I.5 Cryptographie",
		"I.6 Sécurité opérationnelle",
		"I.7 Sécurité des communications",
		"I.8 Sécurité de la chaîne d'approvisionnement",
		"I.9 Sécurité physique",
		"I.10 Surveillance et réponse aux incidents",
		"I.11 Continuité d'activité",
		"I.12 Protection des données et vie privée",
		"I.13 Gestion des identités et des accès",
		"I.14 Gestion des vulnérabilités",
		"I.15 Journalisation et investigation",
	}

	for i, group := range all {
		for _, c := range group {
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   c.id,
				Title:       c.title,
				Family:      families[i],
				Description: c.desc,
				Level:       c.level,
				References: []grc.Reference{
					{Source: "SecNumCloud / EUCS 2024", Section: families[i]},
				},
			})
		}
	}

	return controls
}
