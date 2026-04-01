package anssi_ebios

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "ANSSI_EBIOS_RM_2024"
	CatalogURL  = "https://raw.githubusercontent.com/ANSSI-France/ebios-rm/main/knowledge_base.json"
)

// Provider fetches and parses ANSSI EBIOS Risk Manager knowledge base
// for French critical infrastructure (OIV/OSE) compliance.
type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

// New creates a new ANSSI EBIOS RM provider.
func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{
		store:  store,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *Provider) Name() string {
	return "anssi_ebios"
}

// Run fetches the EBIOS RM knowledge base, parses risk scenarios, and writes them to storage.
func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching ANSSI EBIOS RM knowledge base", "url", CatalogURL)

	destPath := filepath.Join(os.TempDir(), "ebios_rm_knowledge_base.json")
	if err := p.download(ctx, CatalogURL, destPath); err != nil {
		p.logger.Warn("failed to download catalog, using embedded fallback", "error", err)
		controls := p.parseEmbedded()
		return p.writeControls(ctx, controls)
	}
	defer os.Remove(destPath)

	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("failed to parse catalog, using embedded fallback", "error", err)
		controls = p.parseEmbedded()
	}

	return p.writeControls(ctx, controls)
}

func (p *Provider) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// ebiosKnowledgeBase is the top-level EBIOS RM knowledge base structure.
type ebiosKnowledgeBase struct {
	Metadata struct {
		Title       string `json:"title"`
		Version     string `json:"version"`
		Publisher   string `json:"publisher"`
		LastUpdated string `json:"last_updated"`
	} `json:"metadata"`
	Phases    []ebiosPhase    `json:"phases"`
	Threats   []ebiosThreat   `json:"threats"`
	Risks     []ebiosRisk     `json:"risks"`
	Scenarios []ebiosScenario `json:"scenarios"`
}

type ebiosPhase struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Steps       []ebiosStep   `json:"steps"`
	Outputs     []ebiosOutput `json:"outputs"`
}

type ebiosStep struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Order       int    `json:"order"`
}

type ebiosOutput struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ebiosThreat struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Techniques  []string `json:"techniques,omitempty"`
}

type ebiosRisk struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Likelihood  string `json:"likelihood"`
	Impact      string `json:"impact"`
}

type ebiosScenario struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Threats     []string `json:"threats,omitempty"`
	Risks       []string `json:"risks,omitempty"`
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var kb ebiosKnowledgeBase
	if err := json.NewDecoder(f).Decode(&kb); err != nil {
		return nil, fmt.Errorf("decode EBIOS RM knowledge base: %w", err)
	}

	var controls []grc.Control

	for _, phase := range kb.Phases {
		controls = append(controls, p.phaseToControl(phase))
		for _, step := range phase.Steps {
			controls = append(controls, p.stepToControl(step, phase))
		}
		for _, output := range phase.Outputs {
			controls = append(controls, p.outputToControl(output, phase))
		}
	}

	for _, threat := range kb.Threats {
		controls = append(controls, p.threatToControl(threat))
	}

	for _, risk := range kb.Risks {
		controls = append(controls, p.riskToControl(risk))
	}

	for _, scenario := range kb.Scenarios {
		controls = append(controls, p.scenarioToControl(scenario))
	}

	return controls, nil
}

func (p *Provider) phaseToControl(phase ebiosPhase) grc.Control {
	return grc.Control{
		Framework:              FrameworkID,
		ControlID:              fmt.Sprintf("P.%s", phase.ID),
		Title:                  phase.Name,
		Family:                 "Phases",
		Description:            phase.Description,
		Level:                  "standard",
		ImplementationGuidance: fmt.Sprintf("Phase %s of the EBIOS RM methodology", phase.ID),
		References: []grc.Reference{
			{
				Source:  "ANSSI",
				URL:     "https://cyber.gouv.fr/ebios-rm",
				Section: phase.ID,
			},
		},
	}
}

func (p *Provider) stepToControl(step ebiosStep, phase ebiosPhase) grc.Control {
	return grc.Control{
		Framework:              FrameworkID,
		ControlID:              fmt.Sprintf("P.%s.S.%s", phase.ID, step.ID),
		Title:                  step.Name,
		Family:                 fmt.Sprintf("Phases/%s", phase.Name),
		Description:            step.Description,
		Level:                  "standard",
		ImplementationGuidance: fmt.Sprintf("Step %s of phase %s", step.ID, phase.ID),
		References: []grc.Reference{
			{
				Source:  "ANSSI",
				URL:     "https://cyber.gouv.fr/ebios-rm",
				Section: fmt.Sprintf("%s.%s", phase.ID, step.ID),
			},
		},
	}
}

func (p *Provider) outputToControl(output ebiosOutput, phase ebiosPhase) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   fmt.Sprintf("P.%s.O.%s", phase.ID, output.ID),
		Title:       output.Name,
		Family:      fmt.Sprintf("Livrables/%s", phase.Name),
		Description: output.Description,
		Level:       "standard",
		References: []grc.Reference{
			{
				Source:  "ANSSI",
				URL:     "https://cyber.gouv.fr/ebios-rm",
				Section: output.ID,
			},
		},
	}
}

func (p *Provider) threatToControl(threat ebiosThreat) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   fmt.Sprintf("T.%s", threat.ID),
		Title:       threat.Name,
		Family:      fmt.Sprintf("Menaces/%s", threat.Category),
		Description: threat.Description,
		Level:       normalizeSeverity(threat.Severity),
		References: []grc.Reference{
			{
				Source:  "ANSSI",
				URL:     "https://cyber.gouv.fr/ebios-rm",
				Section: threat.ID,
			},
		},
	}
}

func (p *Provider) riskToControl(risk ebiosRisk) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   fmt.Sprintf("R.%s", risk.ID),
		Title:       risk.Name,
		Family:      fmt.Sprintf("Risques/%s", risk.Category),
		Description: risk.Description,
		Level:       normalizeSeverity(risk.Severity),
		References: []grc.Reference{
			{
				Source:  "ANSSI",
				URL:     "https://cyber.gouv.fr/ebios-rm",
				Section: risk.ID,
			},
		},
	}
}

func (p *Provider) scenarioToControl(scenario ebiosScenario) grc.Control {
	return grc.Control{
		Framework:   FrameworkID,
		ControlID:   fmt.Sprintf("S.%s", scenario.ID),
		Title:       scenario.Name,
		Family:      fmt.Sprintf("Scénarios/%s", scenario.Category),
		Description: scenario.Description,
		Level:       normalizeSeverity(scenario.Severity),
		References: []grc.Reference{
			{
				Source:  "ANSSI",
				URL:     "https://cyber.gouv.fr/ebios-rm",
				Section: scenario.ID,
			},
		},
	}
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	p.logger.Info("parsed EBIOS RM controls", "count", len(controls))

	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}

	p.logger.Info("wrote EBIOS RM controls to storage", "count", count)
	return count, nil
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "critique":
		return "critical"
	case "high", "élevé", "eleve":
		return "high"
	case "medium", "moyen":
		return "standard"
	case "low", "faible":
		return "low"
	default:
		return "standard"
	}
}

// embeddedKnowledgeBase is the fallback ANSSI EBIOS RM knowledge base
// when the remote catalog is unavailable.
func (p *Provider) parseEmbedded() []grc.Control {
	return []grc.Control{
		// Phase 1: Cadrage de sécurité (Security framing)
		{
			Framework:              FrameworkID,
			ControlID:              "P.1",
			Title:                  "Cadrage de sécurité",
			Family:                 "Phases",
			Description:            "Définir le périmètre et les objectifs de l'étude de gestion des risques. Identifier les missions métier essentielles et les biens supports associés.",
			Level:                  "standard",
			ImplementationGuidance: "Identifier les missions essentielles de l'organisation et définir le périmètre de l'analyse de risque.",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.1"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.1.S.1",
			Title:       "Identification des missions métier",
			Family:      "Phases/Cadrage de sécurité",
			Description: "Identifier et décrire les missions métier essentielles de l'organisation qui nécessitent une protection.",
			Level:       "standard",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.1.S.1"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.1.S.2",
			Title:       "Identification des biens supports",
			Family:      "Phases/Cadrage de sécurité",
			Description: "Identifier les biens supports (systèmes d'information, infrastructures, personnes) nécessaires à la réalisation des missions métier.",
			Level:       "standard",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.1.S.2"},
			},
		},
		// Phase 2: Fondements de sécurité (Security foundations)
		{
			Framework:              FrameworkID,
			ControlID:              "P.2",
			Title:                  "Fondements de sécurité",
			Family:                 "Phases",
			Description:            "Identifier les sources de risque, les objectifs de sécurité et l'écosystème de l'organisation. Analyser les menaces et les vulnérabilités pertinentes.",
			Level:                  "standard",
			ImplementationGuidance: "Analyser l'écosystème et identifier les sources de risque pertinentes pour l'organisation.",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.2"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.2.S.1",
			Title:       "Identification des sources de risque",
			Family:      "Phases/Fondements de sécurité",
			Description: "Identifier les sources de risque (États, groupes criminels, activistes, etc.) et leurs objectifs potentiels vis-à-vis de l'organisation.",
			Level:       "standard",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.2.S.1"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.2.S.2",
			Title:       "Analyse de l'écosystème",
			Family:      "Phases/Fondements de sécurité",
			Description: "Analyser les dépendances et les relations de l'organisation avec son écosystème (partenaires, fournisseurs, prestataires).",
			Level:       "standard",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.2.S.2"},
			},
		},
		// Phase 3: Scénarios stratégiques (Strategic scenarios)
		{
			Framework:              FrameworkID,
			ControlID:              "P.3",
			Title:                  "Construction des scénarios stratégiques",
			Family:                 "Phases",
			Description:            "Construire les scénarios de risque stratégiques depuis les sources de risque jusqu'aux impacts sur les missions métier. Évaluer la vraisemblance et la gravité.",
			Level:                  "high",
			ImplementationGuidance: "Développer des scénarios de risque complets reliant les sources de risque aux impacts métier.",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.3"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.3.S.1",
			Title:       "Construction des scénarios stratégiques",
			Family:      "Phases/Scénarios stratégiques",
			Description: "Développer les scénarios stratégiques en identifiant les chemins d'attaque depuis les sources de risque jusqu'aux impacts sur les missions métier.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.3.S.1"},
			},
		},
		// Phase 4: Scénarios opérationnels (Operational scenarios)
		{
			Framework:              FrameworkID,
			ControlID:              "P.4",
			Title:                  "Construction des scénarios opérationnels",
			Family:                 "Phases",
			Description:            "Détailler les scénarios opérationnels en identifiant les techniques d'attaque, les vulnérabilités exploitées et les séquences d'événements.",
			Level:                  "high",
			ImplementationGuidance: "Détailler les scénarios opérationnels avec les techniques d'attaque et les vulnérabilités associées.",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.4"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.4.S.1",
			Title:       "Identification des techniques d'attaque",
			Family:      "Phases/Scénarios opérationnels",
			Description: "Identifier les techniques d'attaque plausibles que les sources de risque pourraient employer contre les biens supports.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.4.S.1"},
			},
		},
		// Phase 5: Traitement du risque (Risk treatment)
		{
			Framework:              FrameworkID,
			ControlID:              "P.5",
			Title:                  "Traitement du risque",
			Family:                 "Phases",
			Description:            "Définir et évaluer les mesures de traitement du risque. Élaborer le plan d'action de sécurité et assurer le suivi des décisions.",
			Level:                  "critical",
			ImplementationGuidance: "Sélectionner et mettre en œuvre les mesures de traitement du risque appropriées.",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.5"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "P.5.S.1",
			Title:       "Sélection des mesures de traitement",
			Family:      "Phases/Traitement du risque",
			Description: "Identifier et sélectionner les mesures de sécurité appropriées pour traiter les risques identifiés (réduction, transfert, acceptation, évitement).",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "P.5.S.1"},
			},
		},
		// Threat categories - Menaces
		{
			Framework:   FrameworkID,
			ControlID:   "T.1",
			Title:       "Compromission de systèmes d'information",
			Family:      "Menaces/Techniques",
			Description: "Attaques visant à compromettre les systèmes d'information par exploitation de vulnérabilités logicielles, configuration défaillante ou ingénierie sociale.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.1"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.2",
			Title:       "Attaques par rançongiciel (Ransomware)",
			Family:      "Menaces/Techniques",
			Description: "Chiffrement malveillant des données et systèmes avec demande de rançon. Impact majeur sur la disponibilité des missions métier.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.2"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.3",
			Title:       "Déni de service distribué (DDoS)",
			Family:      "Menaces/Techniques",
			Description: "Attaques visant à rendre indisponibles les services en saturant les ressources réseau ou applicatives.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.3"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.4",
			Title:       "Ingénierie sociale et hameçonnage",
			Family:      "Menaces/Humaines",
			Description: "Manipulation des utilisateurs pour obtenir des informations sensibles ou des accès non autorisés via des techniques d'hameçonnage, d'appâts ou de prétextage.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.4"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.5",
			Title:       "Menace interne",
			Family:      "Menaces/Humaines",
			Description: "Actions malveillantes ou négligentes de personnes internes à l'organisation (employés, prestataires, anciens collaborateurs).",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.5"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.6",
			Title:       "Compromission de la chaîne d'approvisionnement",
			Family:      "Menaces/Techniques",
			Description: "Attaques ciblant les fournisseurs, prestataires ou partenaires de l'organisation pour atteindre indirectement ses systèmes.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.6"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.7",
			Title:       "Exfiltration de données sensibles",
			Family:      "Menaces/Techniques",
			Description: "Vol et exfiltration de données sensibles ou classifiées par des acteurs étatiques ou criminels organisés.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.7"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "T.8",
			Title:       "Sabotage d'infrastructures critiques",
			Family:      "Menages/Physiques",
			Description: "Actions de sabotage visant les infrastructures physiques et numériques des opérateurs d'importance vitale (OIV).",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "T.8"},
			},
		},
		// Risks - Risques
		{
			Framework:   FrameworkID,
			ControlID:   "R.1",
			Title:       "Perte de disponibilité des missions essentielles",
			Family:      "Risques/Opérationnels",
			Description: "Indisponibilité prolongée des systèmes supportant les missions essentielles de l'organisation suite à une attaque cyber ou un incident majeur.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "R.1"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "R.2",
			Title:       "Compromission de l'intégrité des données",
			Family:      "Risques/Opérationnels",
			Description: "Altération malveillante ou accidentelle des données critiques compromettant la fiabilité des décisions opérationnelles.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "R.2"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "R.3",
			Title:       "Divulgation d'informations sensibles",
			Family:      "Risques/Opérationnels",
			Description: "Accès non autorisé et divulgation d'informations sensibles, classifiées ou à caractère personnel.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "R.3"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "R.4",
			Title:       "Perte de traçabilité et de preuve",
			Family:      "Risques/Opérationnels",
			Description: "Impossibilité de reconstituer les événements suite à la destruction ou l'altération des journaux d'activité et des preuves numériques.",
			Level:       "medium",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "R.4"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "R.5",
			Title:       "Dépendance critique à un fournisseur",
			Family:      "Risques/Stratégiques",
			Description: "Risque lié à la dépendance excessive à un fournisseur unique pour des services critiques, avec impact potentiel sur la continuité d'activité.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "R.5"},
			},
		},
		// Scenarios - Scénarios de risque
		{
			Framework:   FrameworkID,
			ControlID:   "S.1",
			Title:       "Campagne de rançongiciel ciblant les OIV",
			Family:      "Scénarios/Stratégiques",
			Description: "Un groupe criminel organise une campagne de rançongiciel ciblant spécifiquement les opérateurs d'importance vitale, avec double extorsion (chiffrement + menace de publication).",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.1"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "S.2",
			Title:       "Compromission de la chaîne d'approvisionnement logiciel",
			Family:      "Scénarios/Stratégiques",
			Description: "Un acteur étatique compromet un logiciel ou une bibliothèque largement utilisé par les OIV pour établir des accès persistants à grande échelle.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.2"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "S.3",
			Title:       "Attaque coordonnée multi-vecteurs",
			Family:      "Scénarios/Stratégiques",
			Description: "Un État-nation lance une attaque coordonnée combinant cyberattaques, ingénierie sociale et actions physiques contre les infrastructures critiques.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.3"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "S.4",
			Title:       "Exfiltration massive de données de santé",
			Family:      "Scénarios/Opérationnels",
			Description: "Un groupe criminel exploite une vulnérabilité dans un système d'information de santé pour exfiltrer des données médicales sensibles à grande échelle.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.4"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "S.5",
			Title:       "Sabotage d'un système industriel (ICS/SCADA)",
			Family:      "Scénarios/Opérationnels",
			Description: "Un acteur malveillant compromet un système de contrôle industriel pour perturber ou endommager un processus de production critique.",
			Level:       "critical",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.5"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "S.6",
			Title:       "Déni de service contre un service public en ligne",
			Family:      "Scénarios/Opérationnels",
			Description: "Une attaque DDoS massive rend indisponible un service public en ligne essentiel, impactant les citoyens et l'image de l'État.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.6"},
			},
		},
		{
			Framework:   FrameworkID,
			ControlID:   "S.7",
			Title:       "Manipulation de l'information à des fins de déstabilisation",
			Family:      "Scénarios/Stratégiques",
			Description: "Un État étranger mène une campagne de désinformation ciblée pour saper la confiance dans les institutions et les services publics essentiels.",
			Level:       "high",
			References: []grc.Reference{
				{Source: "ANSSI", URL: "https://cyber.gouv.fr/ebios-rm", Section: "S.7"},
			},
		},
	}
}
