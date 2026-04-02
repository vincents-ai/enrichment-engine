package schema

import (
	"testing"
)

func setupValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func TestNewValidator(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestHasSchema(t *testing.T) {
	v := setupValidator(t)

	if !v.HasSchema("grc-control-1.0.0.json") {
		t.Error("expected grc-control-1.0.0.json to be registered")
	}
	if v.HasSchema("nonexistent-schema.json") {
		t.Error("expected nonexistent schema to return false")
	}
}

func TestSchemaNames(t *testing.T) {
	v := setupValidator(t)

	names := v.SchemaNames()
	if len(names) < 1 {
		t.Fatalf("expected at least 1 schema, got %d", len(names))
	}

	found := false
	for _, n := range names {
		if n == "grc-control-1.0.0.json" {
			found = true
			break
		}
	}
	if !found {
		t.Error("grc-control-1.0.0.json not found in SchemaNames")
	}
}

func TestValidate_ValidControl(t *testing.T) {
	v := setupValidator(t)

	validControl := map[string]interface{}{
		"Framework":   "NIST_800_53_r5",
		"ControlID":   "AC-2",
		"Title":       "Account Management",
		"Family":      "Access Control",
		"Description": "Manage system accounts",
		"Level":       "standard",
		"RelatedCWEs": []interface{}{"CWE-287"},
	}

	if err := v.Validate("grc-control-1.0.0.json", validControl); err != nil {
		t.Errorf("valid control failed validation: %v", err)
	}
}

func TestValidate_InvalidControl(t *testing.T) {
	v := setupValidator(t)

	invalidControl := map[string]interface{}{
		"Description": "Missing required fields",
	}

	if err := v.Validate("grc-control-1.0.0.json", invalidControl); err == nil {
		t.Error("expected validation error for control missing required fields, got nil")
	}
}

func TestValidate_UnknownSchema(t *testing.T) {
	v := setupValidator(t)

	data := []byte(`{"test": true}`)
	if err := v.Validate("nonexistent.json", data); err == nil {
		t.Error("expected error for unknown schema, got nil")
	}
}

func TestValidate_NilData(t *testing.T) {
	v := setupValidator(t)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Validate panicked with nil data: %v", r)
		}
	}()

	err := v.Validate("grc-control-1.0.0.json", nil)
	if err == nil {
		t.Error("expected error for nil data, got nil")
	}
}
