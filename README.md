# SubBlaster

**The Anti-Ban DNS Brute Forcer.**

SubBlaster is a high-performance subdomain enumeration tool designed for active reconnaissance. Unlike passive tools that rely on outdated logs, SubBlaster performs high-speed DNS brute forcing to find live, hidden subdomains that other hunters miss.

It features a custom **Anti-Ban Engine (Jitter)** that randomizes request timing, allowing you to scan sensitive targets without triggering WAFs or Rate Limits.

## 🔥 Key Features

- **Pure Brute Force:** No API keys, no logs. Direct DNS querying for fresh results.
- **WAF Evasion:** Built-in "Jitter" mode adds randomized delays to mimic human traffic.
- **Wildcard Filtering:** Auto-detects and filters wildcard DNS records.
- **High Concurrency:** Multi-threaded Go architecture capable of high-speed scanning.

---

## 📦 Installation

Install the latest binary directly using Go:

```

go install github.com/aptspider/subblaster/v2@v2.0.3

````


wordlist link 


```

wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
````


Disclaimer

This tool is strictly for educational purposes and authorized security research only. Any actions and/or activities related to the material contained within this repository are solely your responsibility. The developers will not be held responsible for any misuse or damage caused by this program. Do not use this tool on systems you do not have explicit permission to test.
