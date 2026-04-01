package acn_psnc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "ACN_PSNC_DL105_2019"
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
	return "acn_psnc"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("running acn_psnc provider")
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded ACN PSNC controls")
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

	art2 := []struct {
		id, title, desc string
	}{
		{"ART.2-1", "Identificazione e classificazione degli asset", "I soggetti pubblici e privati che gestiscono servizi essenziali o infrastrutture digitali devono identificare e classificare tutti gli asset ICT che supportano i servizi essenziali, inclusi hardware, software, dati, reti e processi, tenendo conto della criticità e dell'impatto potenziale di un incidente di sicurezza."},
		{"ART.2-2", "Mappatura delle dipendenze", "I soggetti devono mappare le dipendenze tra gli asset ICT e i servizi essenziali, identificando i punti critici e le interconnessioni con altri soggetti, fornitori e infrastrutture esterne."},
		{"ART.2-3", "Notifica alla Presidenza del Consiglio", "I soggetti inclusi nel perimetro devono notificare alla Presidenza del Consiglio dei Ministri l'avvenuta identificazione degli asset e delle infrastrutture digitali di propria competenza, secondo le modalità e i tempi stabiliti dal decreto."},
	}

	art3 := []struct {
		id, title, desc string
	}{
		{"ART.3-1", "Notifica degli incidenti di sicurezza", "I soggetti inclusi nel perimetro devono notificare alla Presidenza del Consiglio dei Ministri, attraverso il CSIRT Italia, gli incidenti di sicurezza informatica che coinvolgono le infrastrutture digitali e i servizi essenziali, secondo le tempistiche previste dalla normativa."},
		{"ART.3-2", "Tempi di notifica per incidenti critici", "Gli incidenti di sicurezza di gravità critica devono essere notificati al CSIRT Italia entro 1 ora dalla consapevolezza dell'evento, includendo le informazioni preliminari sulla natura, l'entità e l'impatto dell'incidente."},
		{"ART.3-3", "Tempi di notifica per incidenti di elevata gravità", "Gli incidenti di sicurezza di elevata gravità devono essere notificati al CSIRT Italia entro 6 ore dalla consapevolezza dell'evento, con una notifica di follow-up più dettagliata entro 72 ore."},
		{"ART.3-4", "Notifica di incidenti non gravi", "Gli incidenti di sicurezza non classificati come critici o di elevata gravità devono essere notificati al CSIRT Italia secondo le modalità stabilite, con cadenza almeno trimestrale o come richiesto dal CSIRT."},
	}

	art4 := []struct {
		id, title, desc string
	}{
		{"ART.4-1", "Misure organizzative di sicurezza", "I soggetti devono adottare adeguate misure organizzative per la sicurezza delle infrastrutture digitali, inclusa la nomina di un responsabile della sicurezza informatica (CISO) con competenze adeguate e autonomia operativa."},
		{"ART.4-2", "Misure tecniche di sicurezza di rete", "I soggetti devono implementare misure tecniche per la sicurezza delle reti e dei sistemi, inclusi sistemi di rilevamento delle intrusioni (IDS/IPS), firewall, segmentazione di rete e monitoraggio continuo del traffico di rete."},
		{"ART.4-3", "Gestione delle vulnerabilità", "I soggetti devono implementare un processo strutturato di gestione delle vulnerabilità che includa l'identificazione, la valutazione, la classificazione e il trattamento tempestivo delle vulnerabilità note, con priorità assegnata in base al rischio."},
		{"ART.4-4", "Sicurezza della catena di fornitura", "I soggetti devono valutare e gestire i rischi di sicurezza derivanti dalla catena di fornitura ICT, includendo requisiti di sicurezza nei contratti con i fornitori e verificando il rispetto di tali requisiti."},
		{"ART.4-5", "Protezione dei dati", "I soggetti devono implementare misure adeguate per la protezione dei dati elaborati dalle infrastrutture digitali, inclusa la cifratura dei dati sensibili, sia in transito che a riposo, e il controllo degli accessi ai dati stessi."},
		{"ART.4-6", "Continuità operativa", "I soggetti devono adottare misure per garantire la continuità operativa dei servizi essenziali in caso di incidenti di sicurezza informatica, inclusi piani di continuità operativa, procedure di disaster recovery e meccanismi di ridondanza."},
		{"ART.4-7", "Autenticazione e controllo degli accessi", "I soggetti devono implementare robusti meccanismi di autenticazione e controllo degli accessi logici e fisici alle infrastrutture digitali, applicando il principio del minimo privilegio e la separazione dei compiti."},
		{"ART.4-8", "Cifratura e gestione delle chiavi", "I soggetti devono utilizzare soluzioni di cifratura conformi agli standard nazionali ed europei per la protezione delle comunicazioni e dei dati, implementando adeguate procedure di gestione del ciclo di vita delle chiavi crittografiche."},
	}

	audit := []struct {
		id, title, desc string
	}{
		{"AUD.1", "Valutazione della conformità", "I soggetti devono sottoporre le proprie infrastrutture digitali a periodiche valutazioni di conformità alle misure di sicurezza prescritte, effettuate da soggetti indipendenti e qualificati secondo le modalità stabilite dall'ACN."},
		{"AUD.2", "Audit di sicurezza periodici", "I soggetti devono eseguire audit di sicurezza periodici delle infrastrutture digitali e dei servizi essenziali, con frequenza almeno annuale o più frequente in caso di cambiamenti significativi nell'ambiente di sicurezza."},
		{"AUD.3", "Test di penetrazione", "I soggetti devono eseguire test di penetrazione periodici sulle infrastrutture digitali per identificare vulnerabilità sfruttabili e verificare l'efficacia delle misure di sicurezza implementate."},
		{"AUD.4", "Monitoraggio continuo", "I soggetti devono implementare sistemi di monitoraggio continuo della sicurezza delle infrastrutture digitali, con capacità di rilevamento in tempo reale di anomalie e tentativi di intrusione."},
	}

	for _, c := range art2 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Art. 2 - Identificazione e Classificazione degli Asset",
			Description: c.desc,
			Level:       "essenziale",
			References: []grc.Reference{
				{Source: "D.L. 105/2019 - Perimetro di Sicurezza Nazionale Cibernetica", Section: "Articolo 2"},
			},
		})
	}

	for _, c := range art3 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Art. 3 - Obblighi di Notifica",
			Description: c.desc,
			Level:       "critico",
			References: []grc.Reference{
				{Source: "D.L. 105/2019 - Perimetro di Sicurezza Nazionale Cibernetica", Section: "Articolo 3"},
			},
		})
	}

	for _, c := range art4 {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Art. 4 - Misure di Sicurezza",
			Description: c.desc,
			Level:       "essenziale",
			References: []grc.Reference{
				{Source: "D.L. 105/2019 - Perimetro di Sicurezza Nazionale Cibernetica", Section: "Articolo 4"},
			},
		})
	}

	for _, c := range audit {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Audit e Valutazione",
			Description: c.desc,
			Level:       "essenziale",
			References: []grc.Reference{
				{Source: "D.L. 105/2019 - Perimetro di Sicurezza Nazionale Cibernetica", Section: "Disposizioni attuative ACN"},
			},
		})
	}

	return controls
}
