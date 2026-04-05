package vulnz

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type ClientOption func(*Client)

func WithBaseURL(u string) ClientOption {
	return func(c *Client) { c.baseURL = u }
}

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		baseURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

func (c *Client) FetchCVE(ctx context.Context, cveID string) (json.RawMessage, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	q := u.Query()
	q.Set("cveId", cveID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CVE %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("fetch CVE %s: HTTP %d: %s", cveID, resp.StatusCode, string(body))
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode response for CVE %s: %w", cveID, err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}

	return nvdResp.Vulnerabilities[0].CVE, nil
}

func (c *Client) FetchByCPE(ctx context.Context, cpe string) ([]json.RawMessage, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	q := u.Query()
	q.Set("cpeName", cpe)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch by CPE %s: %w", cpe, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("fetch by CPE %s: HTTP %d: %s", cpe, resp.StatusCode, string(body))
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode response for CPE %s: %w", cpe, err)
	}

	results := make([]json.RawMessage, 0, len(nvdResp.Vulnerabilities))
	for _, v := range nvdResp.Vulnerabilities {
		results = append(results, v.CVE)
	}
	return results, nil
}
