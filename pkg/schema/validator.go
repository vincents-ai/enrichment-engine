package schema

import (
	"embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var schemaFS embed.FS

const (
	VulnerabilitySchemaURL = "https://raw.githubusercontent.com/shift/vulnz/main/internal/schema/schemas/vulnerability-1.0.3.json"
	GRCControlSchemaURL    = "https://raw.githubusercontent.com/shift/enrichment-engine/main/pkg/schema/schemas/grc-control-1.0.0.json"
)

var (
	registry     = make(map[string]*jsonschema.Schema)
	registryOnce sync.Once
	registryMu   sync.RWMutex
)

// Validator validates data against registered JSON schemas.
type Validator struct {
	schemas map[string]*jsonschema.Schema
	mu      sync.RWMutex
}

// NewValidator creates a new validator with all embedded schemas loaded.
func NewValidator() (*Validator, error) {
	registryOnce.Do(func() {
		entries, err := schemaFS.ReadDir("schemas")
		if err != nil {
			return
		}
		compiler := jsonschema.NewCompiler()
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := schemaFS.ReadFile("schemas/" + entry.Name())
			if err != nil {
				continue
			}
			schema, err := compiler.Compile(string(data))
			if err != nil {
				continue
			}
			registry[entry.Name()] = schema
		}
	})

	v := &Validator{
		schemas: make(map[string]*jsonschema.Schema),
	}

	for name, schema := range registry {
		v.schemas[name] = schema
	}

	return v, nil
}

// Validate validates data against a schema by filename.
func (v *Validator) Validate(filename string, data interface{}) error {
	v.mu.RLock()
	schema, ok := v.schemas[filename]
	v.mu.RUnlock()

	if !ok {
		return fmt.Errorf("schema not found: %s", filename)
	}

	return schema.Validate(data)
}

// HasSchema returns true if a schema is registered.
func (v *Validator) HasSchema(filename string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.schemas[filename]
	return ok
}

// SchemaNames returns all registered schema filenames.
func (v *Validator) SchemaNames() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	names := make([]string, 0, len(v.schemas))
	for name := range v.schemas {
		names = append(names, name)
	}
	return names
}
