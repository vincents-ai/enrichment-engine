package bio

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "BIO_2_1"
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
	return "bio"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("running bio provider")
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded BIO controls")
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

	b1 := []struct {
		id, title, desc, level string
	}{
		{"B.1.1", "Informatiebeveiligingsbeleid vaststellen", "De organisatie moet een informatiebeveiligingsbeleid vaststellen, goedkeuren en publiceren dat is afgestemd op de doelstellingen van de organisatie en de wettelijke verplichtingen. Het beleid moet de basis vormen voor alle informatiebeveiligingsmaatregelen en regelmatig worden herzien.", "basis"},
		{"B.1.2", "Informatiebeveiligingsbeleid herzien", "Het informatiebeveiligingsbeleid moet minimaal één keer per jaar of bij belangrijke veranderingen in de organisatie of de bedreigingen worden herzien op actualiteit en doeltreffendheid.", "basis"},
		{"B.1.3", "Richtlijnen voor informatiebeveiliging", "De organisatie moet richtlijnen en procedures vaststellen die het informatiebeveiligingsbeleid ondersteunen en uitwerken voor specifieke onderwerpen, systemen of processen.", "versterkt"},
	}

	b2 := []struct {
		id, title, desc, level string
	}{
		{"B.2.1", "Verantwoordelijkheden voor informatiebeveiliging", "De organisatie moet verantwoordelijkheden voor informatiebeveiliging toewijzen en vastleggen voor alle functieniveaus, inclusief de benoeming van een functionaris voor informatiebeveiliging (CISO).", "basis"},
		{"B.2.2", "Scheiding van taken", "De organisatie moet conflicterende taken en verantwoordelijkheden scheiden om de mogelijkheid van ongeautoriseerde of onbedoelde wijziging of misbruik van informatie en middelen te beperken.", "basis"},
		{"B.2.3", "Contact met bevoegde autoriteiten", "De organisatie moet passende contacten onderhouden met bevoegde autoriteiten op het gebied van informatiebeveiliging, zoals de politie, toezichthouders en CERTs.", "versterkt"},
		{"B.2.4", "Contact met brancheverenigingen", "De organisatie moet deelnemen aan relevante brancheverenigingen en expertisegroepen op het gebied van informatiebeveiliging om op de hoogte te blijven van ontwikkelingen en bedreigingen.", "versterkt"},
	}

	b3 := []struct {
		id, title, desc, level string
	}{
		{"B.3.1", "Screening voorafgaand aan indiensttreding", "De organisatie moet achtergrondverificaties uitvoeren op alle kandidaten voordat zij in dienst treden, in overeenstemming met de wetgeving en evenredig met de bedrijfsvereisten en de classificatie van de informatie.", "basis"},
		{"B.3.2", "Voorwaarden van tewerkstelling", "De arbeidsovereenkomst of het dienstverband moet de verplichtingen van de werknemer op het gebied van informatiebeveiliging vastleggen, inclusief geheimhoudingsplicht en meldplicht van incidenten.", "basis"},
		{"B.3.3", "Informatiebeveiligingsbewustwording en -opleiding", "Alle medewerkers moeten regelmatig informatiebeveiligingsbewustwording en -opleiding ontvangen die is afgestemd op hun functie en verantwoordelijkheden.", "basis"},
		{"B.3.4", "Disciplinaire maatregelen", "De organisatie moet een formeel disciplinair proces vaststellen voor medewerkers die een inbreuk op de informatiebeveiliging plegen.", "versterkt"},
	}

	b4 := []struct {
		id, title, desc, level string
	}{
		{"B.4.1", "Inventarisatie van informatie-activa", "De organisatie moet een inventaris bijhouden van alle informatie-activa, inclusief de eigenaar, de locatie, de classificatie en de verantwoordelijkheden voor elk actief.", "basis"},
		{"B.4.2", "Classificatie van informatie", "Informatie moet worden geclassificeerd volgens de behoeften van de organisatie op het gebied van vertrouwelijkheid, integriteit en beschikbaarheid, en moet worden behandeld overeenkomstig de classificatie.", "basis"},
		{"B.4.3", "Beheer van informatiedragers", "Informatiedragers moeten gedurende hun hele levenscyclus worden beheerd en beschermd, inclusief verwerving, gebruik, opslag, transport en vernietiging.", "versterkt"},
	}

	b5 := []struct {
		id, title, desc, level string
	}{
		{"B.5.1", "Toegangsbeheerbeleid", "De organisatie moet een toegangsbeheerbeleid vaststellen op basis van de vereisten voor bedrijfsvoering en informatiebeveiliging, met nadruk op het need-to-know en het principe van minste bevoegdheid.", "basis"},
		{"B.5.2", "Gebruikersregistratie en -beheer", "De organisatie moet formele procedures vaststellen voor het registreren, wijzigen en intrekken van gebruikersaccounts en toegangsrechten, inclusief periodieke herziening van toegangsrechten.", "basis"},
		{"B.5.3", "Authenticatiebeheer", "De organisatie moet sterke authenticatiemechanismen implementeren, zoals meervoudige authenticatie (MFA), voor toegang tot systemen die gevoelige informatie verwerken.", "versterkt"},
		{"B.5.4", "Toegangscontrole op netwerkniveau", "De organisatie moet netwerktoegang beperken tot geautoriseerde gebruikers en apparaten, met behulp van netwerksegmentatie en toegangscontrolelijsten.", "versterkt"},
	}

	b6 := []struct {
		id, title, desc, level string
	}{
		{"B.6.1", "Cryptografisch beleid", "De organisatie moet een cryptografisch beleid vaststellen voor het gebruik van cryptografische maatregelen, inclusief de keuze van algoritmen, sleutellengtes en sleutelbeheer.", "basis"},
		{"B.6.2", "Sleutelbeheer", "De organisatie moet procedures vaststellen voor het genereren, distribueren, opslaan, roteren en vernietigen van cryptografische sleutels gedurende hun gehele levenscyclus.", "basis"},
		{"B.6.3", "Versleuteling van data-at-rest", "Gevoelige informatie moet in rust worden versleuteld met goedgekeurde algoritmen, met beheer van de versleutelingssleutels volgens het cryptografisch beleid.", "versterkt"},
	}

	b7 := []struct {
		id, title, desc, level string
	}{
		{"B.7.1", "Fysieke beveiligingsperimeters", "De organisatie moet fysieke beveiligingsperimeters definiëren en gebruiken om gebieden te beschermen die gevoelige of kritieke informatie en bijbehorende activa bevatten.", "basis"},
		{"B.7.2", "Toegangscontrole tot gebouwen", "De toegang tot gebouwen en beveiligde gebieden moet worden gecontroleerd en geregistreerd, met passende identificatie- en authenticatiemechanismen.", "basis"},
		{"B.7.3", "Beveiliging van kantoren en werkplekken", "Fysieke beveiligingsmaatregelen moeten worden ontworpen en geïmplementeerd voor kantoren, ruimtes en faciliteiten waar informatie wordt verwerkt.", "versterkt"},
	}

	b8 := []struct {
		id, title, desc, level string
	}{
		{"B.8.1", "Operationele procedures en verantwoordelijkheden", "De organisatie moet documenteerde operationele procedures vaststellen voor het beheer en de bediening van informatiesystemen, inclusief start-, stop- en back-upprocedures.", "basis"},
		{"B.8.2", "Bescherming tegen malware", "De organisatie moet detectie-, preventie- en herstelmaatregelen implementeren tegen malware, inclusief antivirussoftware, intrusion detection systems en regelmatige updates.", "basis"},
		{"B.8.3", "Beheer van technische kwetsbaarheden", "De organisatie moet informatie over technische kwetsbaarheden verzamelen, de blootstelling evalueren en passende maatregelen nemen binnen afgesproken termijnen.", "basis"},
		{"B.8.4", "Configuratiebeheer", "Configuraties van hardware, software, services en netwerken moeten worden vastgelegd, geïmplementeerd, gemonitord en regelmatig herzien.", "versterkt"},
		{"B.8.5", "Back-up en herstel", "Back-upkopieën van informatie, software en systemen moeten regelmatig worden gemaakt en getest om de beschikbaarheid en integriteit te waarborgen.", "basis"},
	}

	b9 := []struct {
		id, title, desc, level string
	}{
		{"B.9.1", "Netwerkbeveiliging", "Netwerken moeten worden beveiligd om de informatie in systemen en applicaties te beschermen, met behulp van netwerksegmentatie, firewalls en versleutelde communicatie.", "basis"},
		{"B.9.2", "Beveiliging van informatietransfer", "Informatie die wordt overgedragen binnen de organisatie of met externe partijen moet worden beschermd tegen onderschepping, wijziging en niet-levering.", "basis"},
		{"B.9.3", "Beveiliging van elektronische communicatie", "Elektronische communicatie zoals e-mail en instant messaging moet worden beschermd met passende technische en organisatorische maatregelen.", "versterkt"},
	}

	b10 := []struct {
		id, title, desc, level string
	}{
		{"B.10.1", "Beveiliging in de levenscyclus van systemen", "Beveiligingseisen moeten worden geïdentificeerd, gespecificeerd en goedgekeurd bij het ontwikkelen of verwerven van informatiesystemen, en moeten worden geïntegreerd in de gehele levenscyclus.", "basis"},
		{"B.10.2", "Veilig ontwikkelen van software", "Regels voor veilig programmeren moeten worden vastgesteld en toegepast bij de ontwikkeling van software, inclusief het gebruik van beveiligde ontwikkelmethodieken en -tools.", "versterkt"},
		{"B.10.3", "Beveiligingstesten", "Beveiligingstesten moeten worden uitgevoerd tijdens de ontwikkeling en voor ingebruikname van systemen, inclusief vulnerability scanning en penetration testing.", "versterkt"},
	}

	b11 := []struct {
		id, title, desc, level string
	}{
		{"B.11.1", "Beveiliging in leveranciersrelaties", "De organisatie moet processen en procedures vaststellen voor het beheren van informatiebeveiligingsrisico's in relatie tot leveranciers, inclusief het vastleggen van beveiligingseisen in contracten.", "basis"},
		{"B.11.2", "Beheer van leveranciersprestaties", "De prestaties van leveranciers op het gebied van informatiebeveiliging moeten regelmatig worden gemonitord, geëvalueerd en gecorrigeerd indien nodig.", "versterkt"},
		{"B.11.3", "Ketenbeveiliging", "De organisatie moet ook de beveiliging van de toeleveringsketen van haar leveranciers in acht nemen, inclusief het beoordelen van subleveranciers.", "versterkt"},
	}

	b12 := []struct {
		id, title, desc, level string
	}{
		{"B.12.1", "Melding van informatiebeveiligingsincidenten", "De organisatie moet een mechanisme vaststellen voor het melden van informatiebeveiligingsincidenten door middel van passende kanalen en in een tijdige manner.", "basis"},
		{"B.12.2", "Beheer van informatiebeveiligingsincidenten", "De organisatie moet processen vaststellen voor het beheren van informatiebeveiligingsincidenten, inclusief het vaststellen van verantwoordelijkheden, procedures voor respons en herstel.", "basis"},
		{"B.12.3", "Leren van incidenten", "Kennis opgedaan uit informatiebeveiligingsincidenten moet worden gebruikt om de informatiebeveiliging te versterken en te verbeteren, inclusief het delen van lessons learned.", "versterkt"},
		{"B.12.4", "Bewijsmateriaal verzamelen", "De organisatie moet procedures vaststellen voor het identificeren, verzamelen, verwerven en bewaren van bewijsmateriaal in verband met informatiebeveiligingsincidenten.", "versterkt"},
	}

	b13 := []struct {
		id, title, desc, level string
	}{
		{"B.13.1", "Bedrijfscontinuïteitsplanning", "De organisatie moet plannen vaststellen om bedrijfscontinuïteit te waarborgen in het geval van verstoringen van kritieke processen, met prioritering op basis van een business impact analyse.", "basis"},
		{"B.13.2", "ICT-gereedheid voor bedrijfscontinuïteit", "ICT-gereedheid voor bedrijfscontinuïteit moet worden gepland, geïmplementeerd, onderhouden en getest op basis van bedrijfscontinuïteitsdoelstellingen en ICT-continuïteitseisen.", "basis"},
		{"B.13.3", "Redundantie en hoge beschikbaarheid", "De organisatie moet maatregelen voor redundantie en hoge beschikbaarheid implementeren voor systemen en services die kritiek zijn voor de bedrijfscontinuïteit.", "versterkt"},
		{"B.13.4", "Oefening en testen", "De plannen voor bedrijfscontinuïteit moeten regelmatig worden getest en geoefend om de effectiviteit te verifiëren en waar nodig bij te werken.", "versterkt"},
	}

	all := [][]struct {
		id, title, desc, level string
	}{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13}

	families := []string{
		"B.1 Informatiebeveiligingsbeleid",
		"B.2 Organisatie van informatiebeveiliging",
		"B.3 Persoonszekerheid",
		"B.4 Activa management",
		"B.5 Toegangscontrole",
		"B.6 Cryptografie",
		"B.7 Fysieke beveiliging",
		"B.8 Operationele beveiliging",
		"B.9 Communicatiebeveiliging",
		"B.10 Systeemontwikkeling en -beheer",
		"B.11 Leveranciersrelaties",
		"B.12 Incidentmanagement",
		"B.13 Bedrijfscontinuïteit",
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
					{Source: "BIO v2.1 - Baseline Informatiebeveiliging Overheid", Section: families[i]},
				},
			})
		}
	}

	return controls
}
