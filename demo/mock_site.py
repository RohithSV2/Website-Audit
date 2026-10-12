from flask import Blueprint, Response

demo_bp = Blueprint("demo", __name__, url_prefix="/demo-target")


@demo_bp.route("")
@demo_bp.route("/")
def demo_home():
    """
    Demo page engineered with intentional SEO & structural flaws:
    - Short title
    - Missing meta description
    - Skipped heading level (H1 -> H3 directly)
    - Dead anchor link (#missing-anchor)
    - Broken internal link (/demo-target/page-404)
    - Image missing alt tag
    - Deprecated <center> tag
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Apex Tech</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="canonical" href="/demo-target">
  <!-- Missing meta description intentionally! -->
</head>
<body>
  <header>
    <nav>
      <a href="/demo-target">Home</a> | 
      <a href="/demo-target/about">About Us</a> | 
      <a href="/demo-target/services">Services</a> | 
      <a href="/demo-target/non-existent-page">Dead 404 Link</a> | 
      <a href="#missing-anchor">Dead Hash Anchor</a>
    </nav>
  </header>

  <main>
    <h1>Engineering Next-Gen Cloud Architecture</h1>
    
    <!-- STRUCTURAL FLAW: Skipped level H1 -> H3 (no H2 in between!) -->
    <h3>Deep Dive: Infrastructure Resilience</h3>
    <p>This section is directly under an H3, skipping the standard H2 semantic hierarchy level.</p>

    <!-- FLAW: Image without alt attribute -->
    <img src="https://images.unsplash.com/photo-1518770660439-4636190af475?w=500" width="500" height="300">
    
    <!-- FLAW: Deprecated HTML elements -->
    <center>
      <font size="3" color="blue">Legacy notice: High availability cloud clusters.</font>
    </center>

    <h2>Database Replication Strategies</h2>
    <p>Ensuring multi-region zero data loss synchronisation with sub-millisecond latencies across enterprise networks.</p>

    <!-- FLAW: Empty heading -->
    <h4>   </h4>
  </main>

  <footer>
    <p>&copy; 2026 Apex Tech Demonstration Sandbox.</p>
  </footer>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@demo_bp.route("/about")
def demo_about():
    """
    Demo about page with intentional flaws:
    - Missing <h1> entirely!
    - Incomplete OpenGraph tags
    - Broken external link simulation
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>About Apex Technologies - Pioneers in Distributed Systems</title>
  <meta name="description" content="Learn more about Apex Technologies, our mission, vision, and deep technical roots in modern computing systems.">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta property="og:title" content="About Apex Technologies">
  <!-- Missing og:image, og:description, og:url -->
</head>
<body>
  <header>
    <nav>
      <a href="/demo-target">Home</a> | 
      <a href="/demo-target/about">About</a> | 
      <a href="/demo-target/services">Services</a>
    </nav>
  </header>

  <main>
    <!-- STRUCTURAL FLAW: Missing H1! Starts directly with H2 -->
    <h2>Our Founding Philosophy</h2>
    <p>We build resilient distributed backends that empower global transactions with rock-solid security guarantees.</p>

    <h3>Core Leadership Team</h3>
    <p>Our leaders possess decades of distributed computing expertise.</p>

    <a href="https://httpbin.org/status/404">External Broken Link (HTTP 404)</a>
  </main>

  <footer>
    <p>&copy; 2026 Apex Tech.</p>
  </footer>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@demo_bp.route("/services")
def demo_services():
    """
    Demo services page with:
    - Multiple <h1> tags!
    - Optimal meta tags
    - Proper images
    """
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Enterprise Cloud Consulting Services | Apex Tech</title>
  <meta name="description" content="Explore our complete catalog of enterprise cloud audit, automated testing, and scalable backend infrastructure services.">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="canonical" href="https://apextech.io/demo-target/services">
</head>
<body>
  <header>
    <nav>
      <a href="/demo-target">Home</a> | 
      <a href="/demo-target/about">About</a> | 
      <a href="/demo-target/services">Services</a>
    </nav>
  </header>

  <main>
    <!-- STRUCTURAL FLAW: Two separate H1 tags on the same page -->
    <h1>Enterprise Cloud Engineering Services</h1>
    <p>Delivering end-to-end cloud migrations and infrastructure assessments.</p>

    <h1>Automated Performance Auditing</h1>
    <p>Comprehensive observability and real-time error telemetry for microservices.</p>

    <h2>Security & Compliance Reviews</h2>
    <p>Full SOC2 and ISO compliance verification workflows.</p>

    <img src="https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=500" alt="Cloud metrics dashboard showing latency and throughput" width="500" height="300">
  </main>

  <footer>
    <p>&copy; 2026 Apex Tech.</p>
  </footer>
</body>
</html>"""
    return Response(html, mimetype="text/html")
