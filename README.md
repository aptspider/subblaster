<h1 align="center">
  <br>
  <a href="https://github.com/aptspider/subblaster"><img src="https://i.imgur.com/example.png" alt="subblaster" width="200"></a>
  <br>
  subblaster
  <br>
</h1>

<h4 align="center">A high-performance, anti-ban DNS brute forcer.</h4>
<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#features">Features</a>
</p>

---

### 🔥 Features
- **Fast:** Pure Go implementation using `miekg/dns`.
- **Anti-Ban:** Built-in Jitter (random delays) to evade WAFs and rate limits.
- **Smart:** Auto-detects Wildcard DNS to reduce false positives.
- **Stealth:** Configurable thread control for low-noise scanning.

### 📦 Installation

```bash
go install [github.com/aptspider/subblaster@latest](https://github.com/aptspider/subblaster@latest)
