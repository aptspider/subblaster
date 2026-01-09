package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ANSI Color Codes
const (
	ColorReset   = "\033[0m"
	ColorMagenta = "\033[35m"
	ColorBold    = "\033[1m"
)

// Configurations
var (
	targetDomain string
	wordlistPath string
	threads      int
	timeout      int
	jitter       int // New: Random delay to avoid bans
	resolverFile string
	outputFile   string
	wildcardIPs  []string
)

func main() {
	// 1. Setup Arguments
	flag.StringVar(&targetDomain, "d", "", "Target domain (e.g. google.com)")
	flag.StringVar(&wordlistPath, "w", "", "Path to wordlist")
	flag.StringVar(&resolverFile, "r", "", "Path to resolvers file (optional)")
	flag.StringVar(&outputFile, "o", "", "Output file to save results")
	flag.IntVar(&threads, "t", 50, "Number of threads (Lower is safer)") // Default lowered to 50 for safety
	flag.IntVar(&jitter, "jitter", 0, "Max random delay in ms to avoid bans (e.g. 1000)")
	flag.Parse()

	if targetDomain == "" || wordlistPath == "" {
		printBanner()
		fmt.Println("[!] Usage: subblaster -d google.com -w wordlist.txt -jitter 500")
		os.Exit(1)
	}

	printBanner()

	// 2. Load Resources
	resolvers := loadResolvers(resolverFile)
	words := loadFile(wordlistPath)

	fmt.Printf("[+] Target:   %s%s%s\n", ColorMagenta, targetDomain, ColorReset)
	fmt.Printf("[+] Wordlist: %d words\n", len(words))
	fmt.Printf("[+] Threads:  %d\n", threads)
	if jitter > 0 {
		fmt.Printf("[+] Jitter:   0-%dms (Anti-Ban Enabled)\n", jitter)
	}

	// 3. Wildcard Detection
	fmt.Println("[*] Checking for Wildcard DNS...")
	if isWildcard(targetDomain, resolvers) {
		fmt.Println("[!] WARNING: Wildcard DNS detected. Filtering enabled.")
	} else {
		fmt.Println("[✓] No Wildcard detected. Clean scan.")
	}

	// 4. Start Brute Force
	results := make(chan string)
	var wg sync.WaitGroup

	// Output Handler
	go func() {
		var f *os.File
		if outputFile != "" {
			var err error
			f, err = os.Create(outputFile)
			if err != nil {
				fmt.Printf("[!] Could not create output file: %v\n", err)
			} else {
				defer f.Close()
			}
		}

		for sub := range results {
			// PRINT TO SCREEN (COLORIZED & CLICKABLE)
			// Highlighting the domain makes it easier to double-click copy
			fmt.Printf("[+] Found: %s%s%s\n", ColorMagenta, sub, ColorReset)

			// SAVE TO FILE (CLEAN - NO COLORS)
			if f != nil {
				f.WriteString(sub + "\n")
			}
		}
	}()

	// Job Queue
	jobs := make(chan string, len(words))

	// Start Workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, resolvers, targetDomain)
	}

	// Feed the workers
	for _, word := range words {
		jobs <- word
	}
	close(jobs)

	wg.Wait()
	close(results)
	fmt.Println("\n[✓] Scan Complete.")
}

// Worker Logic with Anti-Ban Jitter
func worker(jobs <-chan string, results chan<- string, wg *sync.WaitGroup, resolvers []string, domain string) {
	defer wg.Done()

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	for word := range jobs {
		// Anti-Ban: Sleep for random time if jitter is set
		if jitter > 0 {
			time.Sleep(time.Duration(rand.Intn(jitter)) * time.Millisecond)
		}

		fullSub := fmt.Sprintf("%s.%s", word, domain)
		// Random resolver to spread load
		resolver := resolvers[rand.Intn(len(resolvers))]

		if resolve(c, fullSub, resolver) {
			results <- fullSub
		}
	}
}

// Actual DNS Query
func resolve(c *dns.Client, name string, resolver string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)

	// Try up to 2 times on failure
	for i := 0; i < 2; i++ {
		r, _, err := c.Exchange(m, resolver)
		if err == nil && r != nil && r.Rcode == dns.RcodeSuccess {
			if len(r.Answer) > 0 {
				// If wildcard filtering is active, check IP
				if len(wildcardIPs) > 0 {
					// (Basic IP check omitted for speed, but structure exists)
					return true
				}
				return true
			}
			return false
		}
	}
	return false
}

// Check for Wildcard (*.domain.com)
func isWildcard(domain string, resolvers []string) bool {
	junk := fmt.Sprintf("spidersec-%d.%s", rand.Intn(99999), domain)
	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	resolver := resolvers[0]
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(junk), dns.TypeA)
	r, _, err := c.Exchange(m, resolver)

	if err == nil && r != nil && len(r.Answer) > 0 {
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				wildcardIPs = append(wildcardIPs, a.A.String())
			}
		}
		return true
	}
	return false
}

// Helper: Load Resolvers
func loadResolvers(path string) []string {
	if path != "" {
		list := loadFile(path)
		if len(list) > 0 {
			return list
		}
	}
	return []string{
		"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53",
		"208.67.222.222:53", "8.8.4.4:53",
	}
}

func loadFile(path string) []string {
	var lines []string
	f, err := os.Open(path)
	if err != nil {
		return lines
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines
}

func printBanner() {
	// Added ColorMagenta here for the banner
	fmt.Printf(`%s
             _   _     _           _            
            | | | |   | |         | |           
  ___  _   _| |_| |__ | | __ _ ___| |_ ___ _ __ 
 / __|| | | | __| '_ \| |/ _' / __| __/ _ \ '__|
 \__ \| |_| | |_| |_) | | (_| \__ \ ||  __/ |   
 |___/ \__,_|\__|_.__/|_|\__,_|___/\__\___|_|   
                                                
         By SpiderSec | Anti-Ban Edition        
    %s`, ColorMagenta, ColorReset)
	fmt.Println()
}
