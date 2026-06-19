// Command simulator drives concurrent simulated clients against a running
// Sentinel instance (FR6): each simulated client is its own goroutine with
// a configurable RPS, optional initial burst, duration, and jitter. It
// reports per-client allow/reject counts and p50/p99 latency, plus an
// overall summary.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ClientProfile describes one simulated client's traffic shape.
type ClientProfile struct {
	APIKey    string
	RPS       float64
	BurstSize int
	Duration  time.Duration
	Jitter    time.Duration
}

type clientResult struct {
	APIKey    string
	Allowed   int64
	Rejected  int64
	Errors    int64
	Latencies []time.Duration
}

func main() {
	serverURL := flag.String("server", "https://localhost:8080", "Sentinel client API base URL")
	numClients := flag.Int("clients", 10, "number of simulated clients")
	rps := flag.Float64("rps", 10, "requests per second, per client")
	burst := flag.Int("burst", 0, "number of requests to fire immediately at start, per client")
	duration := flag.Duration("duration", 10*time.Second, "total run duration")
	jitter := flag.Duration("jitter", 0, "uniform jitter applied to each inter-request interval")
	insecure := flag.Bool("insecure", true, "skip TLS certificate verification (dev self-signed certs)")
	keyPrefix := flag.String("key-prefix", "sim-client", "prefix for generated API keys")
	flag.Parse()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	if *insecure {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	profiles := make([]ClientProfile, *numClients)
	for i := range profiles {
		profiles[i] = ClientProfile{
			APIKey:    fmt.Sprintf("%s-%03d", *keyPrefix, i),
			RPS:       *rps,
			BurstSize: *burst,
			Duration:  *duration,
			Jitter:    *jitter,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration+5*time.Second)
	defer cancel()

	results := make(chan clientResult, len(profiles))
	var wg sync.WaitGroup
	for _, p := range profiles {
		wg.Add(1)
		go func(profile ClientProfile) {
			defer wg.Done()
			runClient(ctx, httpClient, *serverURL, profile, results)
		}(p)
	}

	fmt.Printf("Simulating %d clients @ %.1f rps each (burst=%d, duration=%s, jitter=%s) against %s\n\n",
		*numClients, *rps, *burst, *duration, *jitter, *serverURL)

	wg.Wait()
	close(results)

	var all []clientResult
	for r := range results {
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].APIKey < all[j].APIKey })

	printReport(all)
}

func runClient(ctx context.Context, client *http.Client, serverURL string, profile ClientProfile, out chan<- clientResult) {
	res := clientResult{APIKey: profile.APIKey}
	url := strings.TrimRight(serverURL, "/") + "/api/v1/request"

	doRequest := func() {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		if err != nil {
			res.Errors++
			return
		}
		req.Header.Set("X-API-Key", profile.APIKey)

		resp, err := client.Do(req)
		latency := time.Since(start)
		res.Latencies = append(res.Latencies, latency)
		if err != nil {
			res.Errors++
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			res.Allowed++
		} else {
			res.Rejected++
		}
	}

	for i := 0; i < profile.BurstSize; i++ {
		select {
		case <-ctx.Done():
			out <- res
			return
		default:
		}
		doRequest()
	}

	interval := time.Second
	if profile.RPS > 0 {
		interval = time.Duration(float64(time.Second) / profile.RPS)
	}

	deadline := time.Now().Add(profile.Duration)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			out <- res
			return
		default:
		}

		doRequest()

		sleep := interval
		if profile.Jitter > 0 {
			delta := time.Duration(rand.Int63n(int64(profile.Jitter)*2+1)) - profile.Jitter
			sleep += delta
			if sleep < 0 {
				sleep = 0
			}
		}
		time.Sleep(sleep)
	}

	out <- res
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func printReport(results []clientResult) {
	var totalAllowed, totalRejected, totalErrors int64
	var allLatencies []time.Duration

	fmt.Printf("%-20s %10s %10s %10s %10s %10s\n", "CLIENT", "ALLOWED", "REJECTED", "ERRORS", "P50", "P99")
	for _, r := range results {
		sorted := append([]time.Duration(nil), r.Latencies...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		p50 := percentile(sorted, 0.50)
		p99 := percentile(sorted, 0.99)
		fmt.Printf("%-20s %10d %10d %10d %10s %10s\n", r.APIKey, r.Allowed, r.Rejected, r.Errors, p50.Round(time.Microsecond), p99.Round(time.Microsecond))

		totalAllowed += r.Allowed
		totalRejected += r.Rejected
		totalErrors += r.Errors
		allLatencies = append(allLatencies, r.Latencies...)
	}

	sort.Slice(allLatencies, func(i, j int) bool { return allLatencies[i] < allLatencies[j] })
	total := totalAllowed + totalRejected + totalErrors

	fmt.Println(strings.Repeat("-", 76))
	fmt.Printf("TOTAL: %d requests, %d allowed, %d rejected, %d errors\n", total, totalAllowed, totalRejected, totalErrors)
	if total > 0 {
		fmt.Printf("Allow rate: %.1f%%\n", 100*float64(totalAllowed)/float64(total))
	}
	fmt.Printf("Latency p50=%s  p99=%s\n",
		percentile(allLatencies, 0.50).Round(time.Microsecond),
		percentile(allLatencies, 0.99).Round(time.Microsecond))

	if totalErrors > 0 {
		os.Exit(1)
	}
}
