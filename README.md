# VECTRA // Website Auditing Tool & Systematic SEO Debugger

An engineered Python tool that autonomously crawls and parses HTML across pages to identify SEO and structural issues, generating automated audit reports with systematic debugging recipes.

---

## 🎨 Unique Visual Identity & Palette

Engineered specifically with a bespoke editorial aesthetic that departs completely from generic dark-mode blues and purples:

- **Canvas Background**: Deep Vintage Basalt Ink (`#080D0B`) with architectural micro-grid and warm linen borders.
- **Primary Accent**: Solar Persimmon Flame (`#FF5E36`) — bold, high-contrast, energizing.
- **Score & Passed Metric**: Lichen Acid / Solar Wasabi (`#D2F834`) — luminescent, crisp readability.
- **Alert Tones**: Crimson Guava (`#FF3B5C`) for Critical issues, Solar Marigold (`#FFA826`) for Warnings, Opal Lapis (`#2DD4BF`) for Notices.
- **Typography Stack**:
  - **Headings & Display**: Google Font **Syne** (Weights 700, 800) — avant-garde geometric sans with sculptural characters.
  - **Body & Controls**: Google Font **Plus Jakarta Sans** (Weights 400, 500, 600, 700) — clean, modern, ultra-legible.
  - **Terminal, Code & Diagnostics**: Google Font **JetBrains Mono** — high-precision monospaced font.

---

## ⚙️ Core Engineered Features

### 1. Multi-Page HTML Crawler (`auditor/crawler.py`)
- Asynchronous Breadth-First Search (BFS) crawl engine.
- Configurable crawl depth (1 to 3 hops) and maximum pages limit (1 to 50 pages).
- Respects internal domain boundaries, normalizes URLs, and avoids crawl loops.
- Probes `/robots.txt` and `/sitemap.xml` automatically on the target host.
- Dispatches real-time telemetry events via Server-Sent Events (SSE).

### 2. Systematic HTML & SEO Parser (`auditor/parser.py`)
- **Meta Tags**:
  - Missing, short (<30 chars), or excessively long (>60 chars) `<title>` tags.
  - Missing, short (<70 chars), or overly verbose (>160 chars) `<meta name="description">`.
  - Canonical link presence (`<link rel="canonical">`) and relative vs absolute verification.
  - Viewport configuration (`width=device-width`).
  - Dangerous robots directives (`noindex`, `nofollow`).
  - Character encoding (`<meta charset="utf-8">`) and `lang` attribute on `<html>`.
  - OpenGraph (`og:title`, `og:description`, `og:image`, `og:url`) and Twitter Card metadata.
  - Favicon presence.
- **Heading Structure Errors (Systematic Hierarchy Analysis)**:
  - Missing `<h1>` (critical structural flaw).
  - Multiple `<h1>` tags on a single page.
  - **Skipped Heading Levels**: Detects unnatural jumps (e.g., `<h1>` followed directly by `<h3>` skipping `<h2>`, or `<h2>` jumping to `<h4>`).
  - Empty heading tags (`<h2>  </h2>` with zero textual content).
  - Chronological heading tree outline generation.
- **Images & Accessibility**:
  - Missing `alt` attributes on `<img>` tags with exact element snippets.
  - Empty `alt` on non-decorative images.
- **Structural Semantics & Hygiene**:
  - Missing `<main>` landmark.
  - Deprecated HTML5 elements (`<center>`, `<font>`, `<marquee>`, `<blink>`, etc.).
- **Transport & Content Density**:
  - SSL/HTTPS encryption check and security headers (`HSTS`, `X-Content-Type-Options`).
  - Word count and reading time estimation.

### 3. Concurrent Link & Dead Anchor Checker (`auditor/link_checker.py`)
- Multi-threaded link tester using `httpx` and `ThreadPoolExecutor`.
- Differentiates Internal vs External links.
- Detects HTTP 404 Not Found, 500 Server Errors, Connection Refused, and Timeouts.
- **Dead Fragment Anchor Detection**: Identifies on-page links like `<a href="#pricing">` where no element has `id="pricing"` or `name="pricing"`.
- Records latency per hyperlink in milliseconds.

### 4. Systematic Debugger & Remediation Recipes (`auditor/reporter.py`)
- Generates transparent, weighted Health Scores (0 to 100) and Letter Grades (A+, A, B, C, D, F).
- Provides actionable code recipes for every issue with a 1-click **Copy Code** button.
- Severity classification: **Critical (🚨)**, **Warning (⚠️)**, **Notice (💡)**, **Passed (✓)**.

### 5. Automated Export Suite
- **Markdown Export**: Complete, beautifully formatted audit document (`.md`) ready for clients.
- **JSON Export**: Full structured audit data (`.json`) for CI/CD integrations.
- **Print / PDF Ready**: Custom `@media print` CSS for clean PDF generation.

### 6. Built-in Sandbox Playground (`demo/mock_site.py`)
- Includes an internal test site at `/demo-target` loaded with intentional SEO, heading, and link flaws for immediate verification without requiring an external target.

---

## 🚀 Quickstart & Local Deployment

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- Dependencies installed:
  ```bash
  pip install -r requirements.txt
  ```

### Start the Auditing Server
```bash
python app.py
```

Open your browser at:
```
http://127.0.0.1:5000
```

To test immediately, click **"🧪 Load Flawed Demo Sandbox"** in the top navigation bar or enter any public URL.

---

## 🌐 Production Deployment Options

### Option A: Deploying with Gunicorn / Waitress
```bash
# Windows (Waitress)
pip install waitress
waitress-serve --port=5000 app:app

# Linux / macOS (Gunicorn)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Option B: Docker Container
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```
Build and run:
```bash
docker build -t website-audit .
docker run -p 5000:5000 website-audit
```

---

## 📂 Repository Structure

```
d:/Website-Audit/
├── auditor/
│   ├── __init__.py
│   ├── models.py         # Dataclasses & audit schemas
│   ├── parser.py         # HTML parser, meta audit, heading hierarchy, image checks
│   ├── link_checker.py   # Concurrent link & dead anchor tester
│   ├── crawler.py        # Asynchronous BFS multi-page crawler & robots/sitemap probe
│   └── reporter.py       # Algorithmic scoring, grade assignment, markdown exporter
├── demo/
│   ├── __init__.py
│   └── mock_site.py      # Multi-page test sandbox with intentional SEO & structural flaws
├── templates/
│   └── index.html        # Bespoke frontend template with unique typography & layouts
├── static/
│   ├── css/
│   │   └── styles.css    # Basalt Ink, Solar Persimmon, Lichen Acid stylesheet
│   └── js/
│       └── app.js        # SSE live stream client, SVG gauge, heading visualizer
├── app.py                # Flask application with REST API & SSE streaming
├── test_auditor.py       # Automated test suite
└── requirements.txt      # Project dependencies
```
