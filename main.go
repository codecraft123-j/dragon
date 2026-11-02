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

const version = "v1.2.1"

const (
	red    = "\033[1;31m"
	blue   = "\033[1;34m"
	green  = "\033[1;32m"
	yellow = "\033[1;33m"
	gray   = "\033[0;90m"
	reset  = "\033[0m"
)

// printBanner draws the banner with a fire gradient (red -> yellow)
// and a cyan frame around the tagline.
func printBanner() {
	art := []string{
		`██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗`,
		`██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║`,
		`██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║`,
		`██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║`,
		`██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║`,
		`╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝`,
	}
	fire := []int{196, 202, 208, 214, 220, 226}
	const (
		cyan   = "\033[1;38;5;51m"
		orange = "\033[1;38;5;208m"
		white  = "\033[1;38;5;255m"
		dim    = "\033[0;38;5;245m"
	)
	rule := strings.Repeat("─", 52)

	fmt.Fprintln(os.Stderr)
	// letters (█) use the bright fire color; the box-drawing shadow uses a darker shade
	shade := []int{52, 88, 94, 130, 136, 172}
	for i, l := range art {
		var sb strings.Builder
		sb.WriteString("  ")
		for _, r := range l {
			if r == '█' {
				fmt.Fprintf(&sb, "\033[1;38;5;%dm%c", fire[i], r)
			} else {
				fmt.Fprintf(&sb, "\033[0;38;5;%dm%c", shade[i], r)
			}
		}
		sb.WriteString(reset)
		fmt.Fprintln(os.Stderr, sb.String())
	}
	fmt.Fprintf(os.Stderr, "  %s%s%s\n", cyan, rule, reset)
	fmt.Fprintf(os.Stderr, "   %s⚡ %sPassive Subdomain Hunter %s•%s %s %s•%s by %slaftman%s\n",
		orange, white, dim, cyan, version, dim, white, orange, reset)
	fmt.Fprintf(os.Stderr, "  %s%s%s\n\n", cyan, rule, reset)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n  dragon -u <domain> [options]\n  dragon -l <file>   [options]\n\nOptions:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  dragon -u example.com\n")
	fmt.Fprintf(os.Stderr, "  dragon -l targets.txt -o out.txt -t 180s\n")
	fmt.Fprintf(os.Stderr, "  dragon -u example.com -silent && cat subdomains.txt | httpx -silent\n")
}

var (
	verbose bool
	strict  bool
)

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

var wwN = regexp.MustCompile(`^ww[0-9]+$`)

// glued reports whether the target text appears inside the prefix stuck to
// other characters (e.g. "exemple.commail"), which is a scraping artifact.
func glued(prefix, target string) bool {
	i := 0
	for i < len(prefix) {
		j := strings.Index(prefix[i:], target)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(target)
		if end < len(prefix) && prefix[end] != '.' {
			return true
		}
		if start > 0 && prefix[start-1] != '.' {
			return true
		}
		i = end
	}
	return false
}

var ipLike = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)

// malformed drops clear scraping artifacts: empty or oversized labels,
// IP-like fragments (a.b.c numbers) and target text glued to other characters.
func malformed(prefix, target string) bool {
	if glued(prefix, target) || ipLike.MatchString(prefix) {
		return true
	}
	for _, l := range strings.Split(prefix, ".") {
		if l == "" || len(l) > 63 {
			return true
		}
	}
	return false
}

// cleanHost normalizes and filters: only valid hosts inside the target scope pass.
func cleanHost(h, target string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	for strings.HasPrefix(h, "*.") {
		h = h[2:]
	}
	if h == "" || !strings.Contains(h, ".") || !validHost.MatchString(h) {
		return "", false
	}
	if h == target {
		return h, true
	}
	if !strings.HasSuffix(h, "."+target) {
		return "", false
	}
	prefix := strings.TrimSuffix(h, "."+target)
	if malformed(prefix, target) {
		return "", false
	}
	// -strict: drop hosts shaped like ww<N>.<something>.target
	if strict {
		labels := strings.Split(prefix, ".")
		if len(labels) > 1 && wwN.MatchString(labels[0]) {
			return "", false
		}
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
		return nil, fmt.Errorf("%s not found in PATH", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = nil // Descarta o stderr igual ao subprocess.DEVNULL do Python
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return splitLines(string(out)), nil
}

func open(ctx context.Context, c *http.Client, u string, headers map[string]string) (io.ReadCloser, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 { // transient server errors: wait 2s, then 4s
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) dragon/1.2")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		resp.Body.Close()
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		switch resp.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			continue
		}
		break
	}
	return nil, lastErr
}

func fetch(ctx context.Context, c *http.Client, u string, headers map[string]string) ([]byte, error) {
	body, err := open(ctx, c, u, headers)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, 200<<20))
}

func fetchJSON(ctx context.Context, c *http.Client, u string, headers map[string]string, v any) error {
	b, err := fetch(ctx, c, u, headers)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---------- sources ----------

type source struct {
	name string
	env  string // optional API key environment variable (empty = no key used)
	fn   func(ctx context.Context, c *http.Client, key, target string) ([]string, error)
}

// scrapeSource builds a source that downloads a page and extracts hosts by regex.
func scrapeSource(name, format string) source {
	return source{name: name, fn: func(ctx context.Context, c *http.Client, _, t string) ([]string, error) {
		b, err := fetch(ctx, c, fmt.Sprintf(format, t), nil)
		if err != nil {
			return nil, err
		}
		re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(t))
		return re.FindAllString(string(b), -1), nil
	}}
}

var sources = []source{
	// ===== external tools (optional) =====
	{name: "Subfinder", fn: func(ctx context.Context, _ *http.Client, _, t string) ([]string, error) {
		return runCmd(ctx, "subfinder", "-d", t, "-silent")
	}},
	{name: "Assetfinder", fn: func(ctx context.Context, _ *http.Client, _, t string) ([]string, error) {
		return runCmd(ctx, "assetfinder", "--subs-only", t)
	}},

	// ===== free: Certificate Transparency =====
	{name: "crt.sh", fn: func(ctx context.Context, c *http.Client, _, t string) ([]string, error) {
		var rows []struct {
			NameValue string `json:"name_value"`
		}
		if err := fetchJSON(ctx, c, "https://crt.sh/?q=%25."+t+"&output=json", nil, &rows); err != nil {
			return nil, err
		}
		var out []string
		for _, r := range rows {
			out = append(out, splitLines(r.NameValue)...)
		}
		return out, nil
	}},
	{name: "CertSpotter", env: "CERTSPOTTER_API_KEY", fn: func(ctx context.Context, c *http.Client, key, t string) ([]string, error) {
		headers := map[string]string{}
		if key != "" {
			headers["Authorization"] = "Bearer " + key
		}
		base := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", t)
		var out []string
		after := ""
		for page := 0; page < 5; page++ {
			u := base
			if after != "" {
				u += "&after=" + after
			}
			var rows []struct {
				ID       string   `json:"id"`
				DNSNames []string `json:"dns_names"`
			}
			if err := fetchJSON(ctx, c, u, headers, &rows); err != nil {
				if key == "" && strings.Contains(err.Error(), "429") {
					err = fmt.Errorf("%w (rate limited; set CERTSPOTTER_API_KEY)", err)
				}
				return out, err
			}
			if len(rows) == 0 {
				break
			}
			for _, r := range rows {
				out = append(out, r.DNSNames...)
			}
			after = rows[len(rows)-1].ID
		}
		return out, nil
	}},

	// ===== free: passive DNS and aggregators =====
	{name: "AlienVault OTX", fn: func(ctx context.Context, c *http.Client, _, t string) ([]string, error) {
		var out []string
		var urls struct {
			URLList []struct {
				Hostname string `json:"hostname"`
			} `json:"url_list"`
		}
		err1 := fetchJSON(ctx, c, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500", t), nil, &urls)
		for _, u := range urls.URLList {
			out = append(out, u.Hostname)
		}
		var pdns struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		err2 := fetchJSON(ctx, c, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", t), nil, &pdns)
		for _, p := range pdns.PassiveDNS {
			out = append(out, p.Hostname)
		}
		if err1 != nil && err2 != nil {
			return nil, err1
		}
		return out, nil
	}},
	{name: "URLScan.io", env: "URLSCAN_API_KEY", fn: func(ctx context.Context, c *http.Client, key, t string) ([]string, error) {
		headers := map[string]string{}
		if key != "" {
			headers["API-Key"] = key
		}
		u := "https://urlscan.io/api/v1/search/?size=1000&q=" + url.QueryEscape("domain:"+t)
		var r struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
				Task struct {
					Domain string `json:"domain"`
				} `json:"task"`
			} `json:"results"`
		}
		if err := fetchJSON(ctx, c, u, headers, &r); err != nil {
			return nil, err
		}
		var out []string
		for _, x := range r.Results {
			out = append(out, x.Page.Domain, x.Task.Domain)
		}
		return out, nil
	}},
	scrapeSource("RapidDNS", "https://rapiddns.io/subdomain/%s?full=1"),
	scrapeSource("DNSRepo", "https://dnsrepo.noc.org/?domain=%s"),

	// ===== free: web archive =====
	{name: "Wayback CDX", fn: func(ctx context.Context, c *http.Client, _, t string) ([]string, error) {
		q := url.Values{}
		q.Set("url", "*."+t+"/*")
		q.Set("collapse", "urlkey")
		q.Set("output", "text")
		q.Set("fl", "original")
		body, err := open(ctx, c, "https://web.archive.org/cdx/search/cdx?"+q.Encode(), nil)
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
}

// ---------- scan ----------

func scan(ctx context.Context, c *http.Client, target string) map[string]struct{} {
	fmt.Fprintf(os.Stderr, "%s[*] The Dragon is flying over: %s%s\n", blue, target, reset)

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		found = map[string]struct{}{}
	)

	for _, s := range sources {
		key := ""
		if s.env != "" {
			key = os.Getenv(s.env)
		}
		wg.Add(1)
		go func(s source, key string) {
			defer wg.Done()
			res, err := s.fn(ctx, c, key, target)
			n := 0
			mu.Lock()
			for _, h := range res {
				if ch, ok := cleanHost(h, target); ok {
					found[ch] = struct{}{}
					n++
				}
			}
			mu.Unlock()
			if err != nil {
				msg := ""
				if verbose {
					msg = ": " + err.Error()
				}
				fmt.Fprintf(os.Stderr, "%s[!] %-17s failed%s (%d hosts)%s\n", yellow, s.name, msg, n, reset)
				return
			}
			fmt.Fprintf(os.Stderr, "%s[+] %-17s %d hosts%s\n", red, s.name, n, reset)
		}(s, key)
	}
	wg.Wait()
	return found
}

func listSources() {
	fmt.Fprintln(os.Stderr, "Sources:")
	for _, s := range sources {
		switch {
		case s.env == "":
			fmt.Fprintf(os.Stderr, "  [ok] %s\n", s.name)
		case os.Getenv(s.env) == "":
			fmt.Fprintf(os.Stderr, "  [ok] %s (no key; %s is optional and raises the rate limit)\n", s.name, s.env)
		default:
			fmt.Fprintf(os.Stderr, "  [ok] %s (using %s)\n", s.name, s.env)
		}
	}
}

func main() {
	var (
		single  = flag.String("u", "", "Single target (e.g. example.com)")
		list    = flag.String("l", "", "File with a list of targets, one per line")
		outFile = flag.String("o", "subdomains.txt", "Output file")
		timeout = flag.Duration("t", 90*time.Second, "Timeout per target")
		quiet   = flag.Bool("silent", false, "Hide the banner")
		ls      = flag.Bool("ls", false, "List the sources")
	)
	flag.BoolVar(&verbose, "v", false, "Show why each failed source failed")
	flag.BoolVar(&strict, "strict", false, "Also drop hosts shaped like ww<N>.<subdomain>.target (noisy pattern)")
	flag.Usage = usage
	flag.Parse()

	if !*quiet {
		printBanner()
	}
	if *ls {
		listSources()
		return
	}

	var targets []string
	switch {
	case *single != "":
		targets = append(targets, normalizeTarget(*single))
	case *list != "":
		f, err := os.Open(*list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!] Error: %v%s\n", red, err, reset)
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
		fmt.Fprintf(os.Stderr, "%s[!] Could not save results: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, h := range sorted {
		fmt.Fprintln(w, h)
	}
	w.Flush()

	fmt.Fprintf(os.Stderr, "\n%s=======================================%s\n", green, reset)
	fmt.Fprintf(os.Stderr, "%s[+] THE DRAGON FINISHED THE HUNT!%s\n", green, reset)
	fmt.Fprintf(os.Stderr, "%s[+] %d unique subdomains found.%s\n", green, len(sorted), reset)
	fmt.Fprintf(os.Stderr, "%s[+] Results saved to: %s%s\n", green, *outFile, reset)
	fmt.Fprintf(os.Stderr, "%s=======================================%s\n", green, reset)
}
