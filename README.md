# SSRFisher 🎣  
**Hook requests. Reel logs.**  
by **@Gromak123** (and **LLM** <3)

SSRFisher is a lightweight **HTTP/HTTPS lure server** built for **SSRF testing** (CTF & pentest).  
Spin up a server in seconds, control **status codes**, **redirects**, **response bodies**, **file downloads**, and get **beautiful request logs** in your terminal — plus **clean JSONL** logs for automation/SIEM.

---

## ✨ Features

- ✅ **Any HTTP status code** (200, 302, 404, 500… you name it)
- 🔁 **Redirects** (any 3xx code) with optional `Location`
- 🧾 Response body from:
  - `--body` (inline text)
  - `--body-file` (loads a file into memory)
  - `--download-file` (streams a local file)
- 📦 **Download mode** with automatic `Content-Disposition` (or custom)
- 🧷 Add arbitrary response headers with `--add-header`
- 🕵️ **Stealth mode / mimicry**:
  - remove SSRFisher fingerprints (`--no-ssrfisher-headers`)
  - override the `Server` header (`--server`)
  - apply presets (`--mimic nginx|apache|iis`)
- 🌍 **Open / permissive CORS** (credentials, reflect Origin, etc.)
- 🧵 Pretty **Rich** console logs (headers, params, body preview)
- 🧾 **JSONL file logging** (great for `jq`, Splunk, ELK, SIEM ingestion)
- 🔐 **HTTPS**:
  - `--ssl` auto-signed (self-signed) certificate
  - or provide real PEM cert/key

---

## ⚠️ Legal / Safety Note

This tool is meant for **authorized security testing** (labs, CTFs, pentests with permission).  
You are responsible for how you use it.

---

## 📦 Installation

### Requirements
- Python **3.10+** recommended  
- `rich` (mandatory)

```bash
pip install rich
````

### Optional (recommended for clean auto-signed TLS)

If installed, SSRFisher uses it to generate self-signed certificates cleanly:

```bash
pip install cryptography
```

> Without `cryptography`, SSRFisher will try to fallback to `openssl` (if available on your system).

---

## 🚀 Quick Start

### Basic HTTP lure

```bash
python ssrfisher.py --port 8000 --code 200 --body "OK"
```

### Redirect with Location

```bash
python ssrfisher.py --bind 0.0.0.0 --port 80 --code 302 --location "http://127.0.0.1/admin"
```

### Serve a local file as a download (streamed)

```bash
python ssrfisher.py --port 8000 --download-file "C:\tmp\poc.png"
```

### Add custom headers

```bash
python ssrfisher.py --port 8000 --add-header "X-Test: 1" --add-header "X-Env: staging"
```

---

## 🔐 HTTPS / TLS

### Auto-signed HTTPS

Generates a self-signed certificate automatically:

```bash
python ssrfisher.py --bind 0.0.0.0 --port 443 --ssl
```

### Use a real certificate

```bash
python ssrfisher.py --bind 0.0.0.0 --port 443 --ssl "C:\certs\fullchain.pem" --ssl-key "C:\certs\privkey.pem"
```

### Customize CN / SAN (auto-signed)

```bash
python ssrfisher.py --bind 10.0.0.12 --port 443 --ssl --ssl-cn "demo.local" --ssl-san "demo.local,10.0.0.12"
```

---

## 🕵️ Mimic / Stealth (Fingerprinting)

### Remove SSRFisher headers

By default SSRFisher sends:

* `X-SSRFisher: 1`
* `X-SSRFisher-ReqID: <id>`

Disable them:

```bash
python ssrfisher.py --port 8000 --no-ssrfisher-headers
```

### Set a realistic Server header

```bash
python ssrfisher.py --port 8000 --server "nginx"
```

### Use a preset (recommended)

Applies:

* disables SSRFisher fingerprint headers
* sets a realistic `Server` header
* adds common headers typical of that stack

```bash
python ssrfisher.py --port 8000 --mimic iis
```

Available presets:

* `nginx`
* `apache`
* `iis`

---

## 🌍 CORS (Permissive / Open)

### “Open CORS” mode

Enables permissive settings designed to be useful in browser-based scenarios:

* reflects `Origin` when present
* sets `Access-Control-Allow-Credentials: true`
* allows common methods & headers
* (optional) exposes `*`

```bash
python ssrfisher.py --port 8000 --cors-open
```

### Advanced CORS tuning

```bash
python ssrfisher.py --port 8000 \
  --cors-origin "https://example.com" \
  --cors-credentials \
  --cors-allow-methods "GET,POST,OPTIONS" \
  --cors-allow-headers "Authorization,Content-Type,X-Requested-With" \
  --cors-expose-headers "X-Token,X-Trace" \
  --cors-max-age 1200
```

### Private Network Access (PNA)

If a request includes `Access-Control-Request-Private-Network: true`, SSRFisher can reply with:
`Access-Control-Allow-Private-Network: true`

```bash
python ssrfisher.py --port 8000 --cors-open --cors-private-network
```

---

## 🧾 Logging

### Pretty console logs

By default, SSRFisher shows:

* request summary (client, method, path, HTTP version, timing)
* query params
* headers (unless disabled)
* request body preview (unless disabled)

Disable parts:

```bash
python ssrfisher.py --port 8000 --no-headers
python ssrfisher.py --port 8000 --no-body
python ssrfisher.py --port 8000 --quiet
```

### JSONL logs

Write one JSON document per request:

```bash
python ssrfisher.py --port 8000 --log-file .\ssrfisher.jsonl --file-log-headers --file-log-body
```

Body preview includes:

* `preview_utf8`
* `preview_b64`
* `length` and `truncated`

Example `jq` usage:

```bash
jq '.request.method, .request.raw_path, .client.ip, .response.status' ssrfisher.jsonl
```

---

## 🎛️ CLI Reference

Show help (Rich help by default):

```bash
python ssrfisher.py --help
```

Disable colors & use plain argparse help:

```bash
python ssrfisher.py --no-color --help
```

---

## 🗺️ Roadmap Ideas

* Multiple routes / per-path behaviors (rules engine)
* Response templates
* Built-in DNS rebinding helper mode
* Optional HTML error pages for realistic stacks

PRs welcome 😉

---

## ❤️ Credits

Built by **@Gromak123** and **LLM**
If you use SSRFisher in a writeup, talk, or CTF challenge: a mention is always appreciated.

---
