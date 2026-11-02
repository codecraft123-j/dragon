package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	red    = "\033[1;31m"
	blue   = "\033[1;34m"
	green  = "\033[1;32m"
	yellow = "\033[1;33m"
	reset  = "\033[0m"
)

const banner = red + `
   ____  ____  ___    ____________  _   __
  / __ \/ __ \/   |  / ____/ __ \/ | / /
 / / / / /_/ / /| | / / __/ / / /  |/ /
/ /_/ / _, _/ ___ |/ /_/ / /_/ / /|  /
\____/_/ |_/_/  |_|\____/\____/_/ |_/
` + yellow + `      [ DRAGON SCANNER v1.0.0 (Go) - BY LAFTMAN ]` + reset + "\n"

// ---------- helpers ----------

var validHost = regexp.MustCompile(`^[a-z0-9._-]+$`)

func normalizeTarget(t string) string {
	t = strings.TrimSpace(strings.ToLower(t))
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	if i := strings.IndexAny(t, "/:?#"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSuffix(t, ".")
}

// cleanHost normaliza e filtra: só aceita host válido dentro do escopo do alvo.
func cleanHost(h, target string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	for strings.HasPrefix(h, "*.") {
		h = h[2:]
	}
	if h == "" || !strings.Contains(h, ".") || !validHost.MatchString(h) {
		return "", false
	}
	if h != target && !strings.HasSuffix(h, "."+target) {
		return "", false
	}
	return h, true
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func runCmd(ctx context.Context, name string, args ...string) ([]string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, fmt.Errorf("%s não encontrado no PATH", name)
	}
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return splitLines(string(out)), nil
}

func httpGet(ctx context.Context, c *http.Client, u string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) dragon/2.0")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// ---------- fontes ----------

type source struct {
	name string
	fn   func(ctx context.Context, c *http.Client, target string) ([]string, error)
}

var sources = []source{
	{"Subfinder", func(ctx context.Context, _ *http.Client, t string) ([]string, error) {
		return runCmd(ctx, "subfinder", "-d", t, "-silent")
	}},
	{"AlienVault OTX", func(ctx context.Context, c *http.Client, t string) ([]string, error) {
		body, err := httpGet(ctx, c, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500", t))
		if err != nil {
			return nil, err
		}
		defer body.Close()
		var r struct {
			URLList []struct {
				Hostname string `json:"hostname"`
			} `json:"url_list"`
		}
		if err := json.NewDecoder(body).Decode(&r); err != nil {
			return nil, err
		}
		out := make([]string, 0, len(r.URLList))
		for _, u := range r.URLList {
			out = append(out, u.Hostname)
		}
		return out, nil
	}},
	{"Wayback CDX", func(ctx context.Context, c *http.Client, t string) ([]string, error) {
		q := url.Values{}
		q.Set("url", "*."+t+"/*")
		q.Set("collapse", "urlkey")
		q.Set("output", "text")
		q.Set("fl", "original")
		body, err := httpGet(ctx, c, "https://web.archive.org/cdx/search/cdx?"+q.Encode())
		if err != nil {
			return nil, err
		}
		defer body.Close()
		seen := map[string]struct{}{}
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			u, err := url.Parse(strings.TrimSpace(sc.Text()))
			if err != nil || u.Hostname() == "" {
				continue
			}
			seen[u.Hostname()] = struct{}{}
		}
		out := make([]string, 0, len(seen))
		for h := range seen {
			out = append(out, h)
		}
		return out, sc.Err()
	}},
	{"crt.sh", func(ctx context.Context, c *http.Client, t string) ([]string, error) {
		body, err := httpGet(ctx, c, "https://crt.sh/?q=%25."+t+"&output=json")
		if err != nil {
			return nil, err
		}
		defer body.Close()
		var rows []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.NewDecoder(body).Decode(&rows); err != nil {
			return nil, err
		}
		var out []string
		for _, r := range rows {
			out = append(out, splitLines(r.NameValue)...)
		}
		return out, nil
	}},
	{"Assetfinder", func(ctx context.Context, _ *http.Client, t string) ([]string, error) {
		return runCmd(ctx, "assetfinder", "--subs-only", t)
	}},
	{"VirusTotal", func(ctx context.Context, c *http.Client, t string) ([]string, error) {
		body, err := httpGet(ctx, c, fmt.Sprintf("https://www.virustotal.com/ui/domains/%s/subdomains?limit=40", t))
		if err != nil {
			return nil, err
		}
		defer body.Close()
		raw, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(t))
		return re.FindAllString(string(raw), -1), nil
	}},
}

// ---------- scan ----------

func scan(ctx context.Context, c *http.Client, target string) map[string]struct{} {
	fmt.Fprintf(os.Stderr, "%s[*] O Dragão está sobrevoando: %s%s\n", blue, target, reset)

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		found = map[string]struct{}{}
	)

	for _, s := range sources {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			res, err := s.fn(ctx, c, target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s[!] %s falhou: %v%s\n", yellow, s.name, err, reset)
				return
			}
			n := 0
			mu.Lock()
			for _, h := range res {
				if ch, ok := cleanHost(h, target); ok {
					found[ch] = struct{}{}
					n++
				}
			}
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "%s[+] %-15s %d hosts%s\n", red, s.name, n, reset)
		}(s)
	}
	wg.Wait()
	return found
}

func main() {
	var (
		single  = flag.String("u", "", "Alvo único (ex: example.com)")
		list    = flag.String("l", "", "Arquivo com lista de alvos")
		outFile = flag.String("o", "subdomains.txt", "Arquivo de saída")
		timeout = flag.Duration("t", 90*time.Second, "Timeout por alvo")
		quiet   = flag.Bool("silent", false, "Sem banner")
	)
	flag.Parse()

	if !*quiet {
		fmt.Fprint(os.Stderr, banner)
	}

	var targets []string
	switch {
	case *single != "":
		targets = append(targets, normalizeTarget(*single))
	case *list != "":
		f, err := os.Open(*list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Erro: %v%s\n", red, err, reset)
			os.Exit(1)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if t := normalizeTarget(sc.Text()); t != "" {
				targets = append(targets, t)
			}
		}
	default:
		flag.Usage()
		os.Exit(1)
	}

	client := &http.Client{Timeout: *timeout}
	all := map[string]struct{}{}

	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		for h := range scan(ctx, client, t) {
			all[h] = struct{}{}
		}
		cancel()
	}

	sorted := make([]string, 0, len(all))
	for h := range all {
		sorted = append(sorted, h)
	}
	sort.Strings(sorted)

	f, err := os.Create(*outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] Erro ao salvar: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, h := range sorted {
		fmt.Fprintln(w, h)
	}
	w.Flush()

	fmt.Fprintf(os.Stderr, "\n%s=======================================%s\n", green, reset)
	fmt.Fprintf(os.Stderr, "%s[+] O DRAGÃO FINALIZOU A CAÇADA!%s\n", green, reset)
	fmt.Fprintf(os.Stderr, "%s[+] %d Subdomínios únicos encontrados.%s\n", green, len(sorted), reset)
	fmt.Fprintf(os.Stderr, "%s[+] Resultados em: %s%s\n", green, *outFile, reset)
	fmt.Fprintf(os.Stderr, "%s=======================================%s\n", green, reset)
}
