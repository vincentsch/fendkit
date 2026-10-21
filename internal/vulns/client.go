package vulns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vincentsch/fendkit/internal/inventory"
	"github.com/vincentsch/fendkit/internal/version"
)

const OSVURL = "https://api.osv.dev"
const KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type Client struct {
	HTTP *http.Client
	OSV  string
	KEV  string
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, OSV: OSVURL, KEV: KEVURL}
}
func (c *Client) request(ctx context.Context, method, endpoint string, body any, result any) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	reason := "request failed"
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("request cancelled")
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		req, err := http.NewRequestWithContext(requestCtx, method, endpoint, bytes.NewReader(data))
		if err != nil {
			cancel()
			return fmt.Errorf("invalid lookup URL")
		}
		req.Header.Set("User-Agent", "fendkit/"+version.Version)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			reason = "connection failed or timed out after 20 s"
			cancel()
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			decoded := reflect.New(reflect.TypeOf(result).Elem())
			err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(decoded.Interface())
			if err == nil {
				reflect.ValueOf(result).Elem().Set(decoded.Elem())
			}
			resp.Body.Close()
			cancel()
			if err == nil {
				return nil
			}
			reason = "invalid JSON response"
		} else {
			reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
			cancel()
			if resp.StatusCode < 500 && resp.StatusCode != 429 {
				break
			}
		}
	}
	return fmt.Errorf("%s; run fendkit scan again", reason)
}

type query struct {
	Package   Package `json:"package"`
	Version   string  `json:"version"`
	PageToken string  `json:"page_token,omitempty"`
}
type queryResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	Next string `json:"next_page_token"`
}

func (c *Client) Lookup(ctx context.Context, inv inventory.Inventory, offline bool) ([]Finding, []string) {
	findings := []Finding{}
	reasons := []string{}
	if offline {
		return findings, []string{"Offline scan: vulnerability lookups have not run"}
	}
	var kev struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	known := map[string]bool{}
	if err := c.request(ctx, http.MethodGet, c.KEV, nil, &kev); err != nil {
		reasons = append(reasons, "CISA KEV: "+err.Error())
	} else if kev.Vulnerabilities == nil {
		reasons = append(reasons, "CISA KEV: missing vulnerabilities list; run fendkit scan again")
	} else {
		for _, v := range kev.Vulnerabilities {
			known[v.CVEID] = true
		}
	}
	components := []inventory.Component{}
	queries := []query{}
	for _, comp := range inv.Components {
		if ecosystem(comp) == "" || comp.LookupVersion == nil || *comp.LookupVersion == "" {
			continue
		}
		components = append(components, comp)
		queries = append(queries, query{Package: Package{Name: comp.Name, Ecosystem: ecosystem(comp)}, Version: *comp.LookupVersion})
	}
	ids := make([][]string, len(queries))
	for start := 0; start < len(queries); start += 1000 {
		end := min(start+1000, len(queries))
		pending := slices.Clone(queries[start:end])
		indexes := []int{}
		seen := map[int]map[string]bool{}
		for i := start; i < end; i++ {
			indexes = append(indexes, i)
			seen[i] = map[string]bool{}
		}
		for len(pending) > 0 {
			var response struct {
				Results []queryResult `json:"results"`
			}
			if err := c.request(ctx, http.MethodPost, strings.TrimRight(c.OSV, "/")+"/v1/querybatch", struct {
				Queries []query `json:"queries"`
			}{pending}, &response); err != nil {
				reasons = append(reasons, "OSV.dev querybatch: "+err.Error())
				break
			}
			if len(response.Results) != len(pending) {
				reasons = append(reasons, "OSV.dev querybatch: result count differs from query count; run fendkit scan again")
				break
			}
			next := []query{}
			nextIndexes := []int{}
			for i, r := range response.Results {
				idx := indexes[i]
				for _, v := range r.Vulns {
					if v.ID == "" {
						reasons = append(reasons, "OSV.dev querybatch: advisory id missing")
					} else {
						ids[idx] = append(ids[idx], v.ID)
					}
				}
				if r.Next != "" {
					if seen[idx][r.Next] {
						reasons = append(reasons, "OSV.dev querybatch: repeated page token; run fendkit scan again")
						continue
					}
					seen[idx][r.Next] = true
					q := pending[i]
					q.PageToken = r.Next
					next = append(next, q)
					nextIndexes = append(nextIndexes, idx)
				}
			}
			pending = next
			indexes = nextIndexes
		}
	}
	all := []string{}
	for _, list := range ids {
		all = append(all, list...)
	}
	all = unique(all)
	cache := map[string]Advisory{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	for range min(8, len(all)) {
		wg.Go(func() {
			for id := range jobs {
				var a Advisory
				err := c.request(ctx, http.MethodGet, strings.TrimRight(c.OSV, "/")+"/v1/vulns/"+url.PathEscape(id), nil, &a)
				mu.Lock()
				if err != nil {
					reasons = append(reasons, "OSV.dev "+id+": "+err.Error())
				} else if a.ID != id || a.Affected == nil {
					reasons = append(reasons, "OSV.dev "+id+": invalid advisory details; run fendkit scan again")
				} else {
					cache[id] = a
				}
				mu.Unlock()
			}
		})
	}
	for _, id := range all {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	for i, comp := range components {
		advisories := []Advisory{}
		for _, id := range unique(ids[i]) {
			if a, ok := cache[id]; ok {
				advisories = append(advisories, a)
			}
		}
		findings = append(findings, Group(comp, advisories, known)...)
	}
	return findings, unique(reasons)
}
