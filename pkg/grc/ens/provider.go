package ens

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "ENS_RD311_2022"
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
	return "ens"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("running ens provider")
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	p.logger.Info("using embedded ENS controls")
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

	policy := []struct {
		id, title, desc string
	}{
		{"PM.I-1", "Política de seguridad de la información", "La entidad debe aprobar y mantener una política de seguridad de la información, que defina los principios, objetivos y compromisos de la dirección en materia de seguridad, y que sea revisada periódicamente para asegurar su continua adecuación."},
		{"PM.I-2", "Política de seguridad de las TIC", "La política de seguridad de las TIC debe ser coherente con la política de seguridad de la información y definir los principios y requisitos específicos para la protección de los sistemas, redes y servicios de información."},
		{"PM.I-3", "Organización de la seguridad", "La entidad debe establecer una estructura organizativa adecuada para la gestión de la seguridad, definiendo roles, responsabilidades y cometidos de seguridad, incluyendo la figura del responsable de seguridad."},
		{"PM.I-4", "Análisis y gestión de riesgos", "La entidad debe realizar un análisis y gestión de riesgos que cubra todos los activos de información, identificando amenazas, vulnerabilidades y evaluando el impacto potencial de los incidentes de seguridad sobre los servicios esenciales."},
		{"PM.I-5", "Plan de seguridad", "La entidad debe elaborar un plan de seguridad que defina las medidas de seguridad aplicables a los sistemas de información, de acuerdo con los resultados del análisis y gestión de riesgos y la categoría del sistema."},
		{"PM.I-6", "Gestión de cambios", "La entidad debe establecer un procedimiento de gestión de cambios que asegure que las modificaciones en los sistemas de información se realizan de forma controlada y que se evalúa su impacto en la seguridad antes de su implementación."},
		{"PM.I-7", "Gestión de proveedores", "La entidad debe establecer requisitos de seguridad que deben cumplir los proveedores de servicios de información, incluyendo cláusulas de seguridad en los contratos y mecanismos de supervisión del cumplimiento."},
		{"PM.I-8", "Acuerdos de nivel de servicio de seguridad", "Los acuerdos de nivel de servicio deben incluir requisitos específicos de seguridad de la información, tales como tiempos de respuesta ante incidentes, niveles de disponibilidad y requisitos de confidencialidad."},
		{"PM.I-9", "Formación y concienciación", "La entidad debe establecer un programa de formación y concienciación en seguridad de la información dirigido a todo el personal con acceso a sistemas de información, que se actualizará periódicamente."},
		{"PM.I-10", "Revisión y auditoría", "La entidad debe realizar revisiones periódicas y auditorías de seguridad para verificar el cumplimiento de las medidas de seguridad establecidas y la eficacia de los controles implementados."},
	}

	operational := []struct {
		id, title, desc string
	}{
		{"OP.I-1", "Identificación y autenticación", "La entidad debe implementar mecanismos de identificación y autenticación que aseguren la verificación de la identidad de los usuarios, sistemas y servicios, utilizando mecanismos robustos acordes a la categoría del sistema."},
		{"OP.I-2", "Control de acceso lógico", "La entidad debe implementar controles de acceso lógico que limiten el acceso a los recursos de información únicamente a usuarios autorizados, aplicando el principio de mínimo privilegio y segregación de funciones."},
		{"OP.I-3", "Gestión de usuarios", "La entidad debe establecer procedimientos de alta, baja y modificación de usuarios que aseguren la correcta gestión del ciclo de vida de las cuentas de usuario y sus derechos de acceso."},
		{"OP.I-4", "Protección de las comunicaciones", "La entidad debe implementar medidas de protección de las comunicaciones que aseguren la confidencialidad, integridad y autenticidad de la información transmitida a través de redes de telecomunicaciones."},
		{"OP.I-5", "Cifrado", "La entidad debe utilizar cifrado para proteger la confidencialidad e integridad de la información, empleando algoritmos y longitudes de clave aprobados por el Centro Criptológico Nacional (CCN)."},
		{"OP.I-6", "Protección contra código malicioso", "La entidad debe implementar mecanismos de detección, prevención y respuesta contra código malicioso, incluyendo la actualización periódica de firmas y motores de análisis."},
		{"OP.I-7", "Protección de registros de actividad", "La entidad debe proteger los registros de actividad (logs) contra modificaciones no autorizadas y garantizar su disponibilidad para su análisis y posible uso como evidencia."},
		{"OP.I-8", "Gestión de vulnerabilidades", "La entidad debe establecer un procedimiento de gestión de vulnerabilidades que incluya la identificación, evaluación, tratamiento y seguimiento de las vulnerabilidades detectadas en los sistemas de información."},
	}

	systems := []struct {
		id, title, desc string
	}{
		{"SI.I-1", "Inventario de sistemas", "La entidad debe mantener un inventario actualizado de todos los sistemas de información, incluyendo hardware, software, redes y datos, con información suficiente para su identificación y gestión."},
		{"SI.I-2", "Configuración segura", "La entidad debe establecer y mantener configuraciones de seguridad para todos los sistemas de información, aplicando directrices de endurecimiento (hardening) acordes a las buenas prácticas y a la categoría del sistema."},
		{"SI.I-3", "Protección de las instalaciones", "La entidad debe establecer controles físicos para proteger las instalaciones donde se alojan los sistemas de información contra accesos no autorizados, desastres naturales e incidentes físicos."},
		{"SI.I-4", "Mantenimiento de sistemas", "La entidad debe establecer procedimientos de mantenimiento que aseguren la disponibilidad, integridad y seguridad de los sistemas de información, incluyendo la aplicación de parches de seguridad en plazos adecuados."},
		{"SI.I-5", "Copias de seguridad", "La entidad debe realizar copias de seguridad periódicas de la información y los sistemas, verificando regularmente su integridad y la posibilidad de restauración en tiempos aceptables."},
		{"SI.I-6", "Registro de actividad", "La entidad debe generar, recopilar y almacenar registros de actividad de los sistemas de información relevantes para la detección de incidentes de seguridad, la investigación forense y el cumplimiento normativo."},
		{"SI.I-7", "Gestión de incidencias de seguridad", "La entidad debe establecer un procedimiento de gestión de incidencias que permita la detección, clasificación, respuesta, recuperación y aprendizaje de los incidentes de seguridad."},
		{"SI.I-8", "Protección de la información almacenada", "La entidad debe implementar medidas para proteger la información almacenada contra accesos no autorizados, pérdidas o destrucción, aplicando controles de cifrado y control de acceso."},
	}

	continuity := []struct {
		id, title, desc string
	}{
		{"CO.I-1", "Plan de continuidad de actividad", "La entidad debe establecer un plan de continuidad de actividad que defina las medidas necesarias para asegurar la continuidad de los servicios esenciales en caso de incidentes graves o desastres."},
		{"CO.I-2", "Plan de recuperación ante desastres", "La entidad debe elaborar y mantener un plan de recuperación ante desastres que defina los procedimientos, recursos y responsabilidades para la restauración de los sistemas y servicios críticos."},
		{"CO.I-3", "Pruebas de continuidad", "La entidad debe realizar pruebas periódicas de los planes de continuidad y recuperación para verificar su eficacia y actualizarlos en función de los resultados obtenidos."},
		{"CO.I-4", "Redundancia y alta disponibilidad", "La entidad debe implementar medidas de redundancia y alta disponibilidad para los sistemas y servicios esenciales, acordes a los requisitos de continuidad establecidos."},
		{"CO.I-5", "Seguridad en la recuperación", "Las operaciones de recuperación de sistemas y datos deben asegurar la integridad y confidencialidad de la información restaurada, verificando la ausencia de código malicioso o alteraciones."},
	}

	monitoring := []struct {
		id, title, desc string
	}{
		{"VI.I-1", "Supervisión continua", "La entidad debe implementar mecanismos de supervisión continua de la seguridad de los sistemas de información que permitan la detección temprana de anomalías y posibles incidentes de seguridad."},
		{"VI.I-2", "Auditoría periódica", "La entidad debe someter los sistemas de información a auditorías periódicas de seguridad realizadas por personal independiente y cualificado, con una frecuencia acorde a la categoría del sistema."},
		{"VI.I-3", "Revisión del análisis de riesgos", "La entidad debe revisar el análisis y gestión de riesgos con una periodicidad mínima anual, o cuando se produzcan cambios significativos en los sistemas, el entorno o las amenazas."},
		{"VI.I-4", "Indicadores de seguridad", "La entidad debe definir y monitorizar indicadores de seguridad que permitan evaluar el estado de la seguridad de los sistemas de información y la eficacia de las medidas implementadas."},
	}

	for _, c := range policy {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Medidas de Política (Capítulo II)",
			Description: c.desc,
			Level:       "alto",
			References:  []grc.Reference{{Source: "Real Decreto 311/2022", Section: "Capítulo II - Política de Seguridad"}},
		})
	}

	for _, c := range operational {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Medidas Operacionales (Capítulo III)",
			Description: c.desc,
			Level:       "alto",
			References:  []grc.Reference{{Source: "Real Decreto 311/2022", Section: "Capítulo III - Medidas Operacionales"}},
		})
	}

	for _, c := range systems {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Medidas de Sistemas (Capítulo III)",
			Description: c.desc,
			Level:       "medio",
			References:  []grc.Reference{{Source: "Real Decreto 311/2022", Section: "Capítulo III - Medidas de Sistemas"}},
		})
	}

	for _, c := range continuity {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Medidas de Continuidad (Capítulo V)",
			Description: c.desc,
			Level:       "alto",
			References:  []grc.Reference{{Source: "Real Decreto 311/2022", Section: "Capítulo V - Continuidad de Actividad"}},
		})
	}

	for _, c := range monitoring {
		controls = append(controls, grc.Control{
			Framework:   FrameworkID,
			ControlID:   c.id,
			Title:       c.title,
			Family:      "Medidas de Supervisión (Capítulo VI)",
			Description: c.desc,
			Level:       "medio",
			References:  []grc.Reference{{Source: "Real Decreto 311/2022", Section: "Capítulo VI - Supervisión y Auditoría"}},
		})
	}

	return controls
}
