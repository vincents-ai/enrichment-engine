package vulnz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient()
	if c.baseURL != "https://services.nvd.nist.gov/rest/json/cves/2.0" {
		t.Errorf("expected default baseURL, got %s", c.baseURL)
	}
	if c.httpClient != http.DefaultClient {
		t.Error("expected default HTTP client")
	}
}

func TestWithBaseURL(t *testing.T) {
	c := NewClient(WithBaseURL("http://localhost:8080/api"))
	if c.baseURL != "http://localhost:8080/api" {
		t.Errorf("expected custom baseURL, got %s", c.baseURL)
	}
}

func TestFetchCVE(t *testing.T) {
	cveData := map[string]interface{}{
		"id": "CVE-2021-44228",
		"cve": map[string]interface{}{
			"id":        "CVE-2021-44228",
			"published": "2021-12-10T15:15:00.000",
		},
	}
	respBody := map[string]interface{}{
		"totalResults": 1,
		"vulnerabilities": []interface{}{
			map[string]interface{}{"cve": cveData["cve"]},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2021-44228" {
			t.Errorf("expected cveId=CVE-2021-44228, got %s", r.URL.Query().Get("cveId"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(respBody)
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	result, err := client.FetchCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	if parsed["id"] != "CVE-2021-44228" {
		t.Errorf("expected CVE ID CVE-2021-44228, got %v", parsed["id"])
	}
}

func TestFetchCVE_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults":    0,
			"vulnerabilities": []interface{}{},
		})
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	_, err := client.FetchCVE(context.Background(), "CVE-9999-0000")
	if err == nil {
		t.Fatal("expected error for not found CVE")
	}
}

func TestFetchByCPE(t *testing.T) {
	cve1 := map[string]interface{}{"id": "CVE-2021-44228"}
	cve2 := map[string]interface{}{"id": "CVE-2021-45046"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cpeName"); got != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
			t.Errorf("expected cpeName, got %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults": 2,
			"vulnerabilities": []interface{}{
				map[string]interface{}{"cve": cve1},
				map[string]interface{}{"cve": cve2},
			},
		})
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	results, err := client.FetchByCPE(context.Background(), "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for i, id := range []string{"CVE-2021-44228", "CVE-2021-45046"} {
		var parsed map[string]interface{}
		if err := json.Unmarshal(results[i], &parsed); err != nil {
			t.Fatalf("failed to parse result %d: %v", i, err)
		}
		if parsed["id"] != id {
			t.Errorf("result %d: expected %s, got %v", i, id, parsed["id"])
		}
	}
}

func TestFetchCVE_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	_, err := client.FetchCVE(context.Background(), "CVE-2021-44228")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestFetchCVE_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	_, err := client.FetchCVE(context.Background(), "CVE-2021-44228")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFetchByCPE_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"totalResults":    0,
			"vulnerabilities": []interface{}{},
		})
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	results, err := client.FetchByCPE(context.Background(), "cpe:2.3:a:nonexistent:lib:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}
