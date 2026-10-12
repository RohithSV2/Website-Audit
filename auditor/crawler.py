import time
from collections import deque
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Callable
from urllib.parse import urlparse, urljoin, urldefrag
import httpx
from bs4 import BeautifulSoup

from .models import SiteAuditReport, PageAuditResult, AuditIssue, Severity, IssueCategory
from .parser import HTMLPageAuditor
from .link_checker import ConcurrentLinkChecker
from .reporter import AuditReporter


class WebsiteCrawler:
    """
    Crawls and parses HTML across pages to automatically identify SEO,
    structural, and broken-link issues through systematic debugging.
    """

    USER_AGENT = "Mozilla/5.0 (compatible; WebsiteAuditBot/2.0; +https://github.com/website-audit)"

    def __init__(
        self,
        root_url: str,
        max_depth: int = 2,
        max_pages: int = 10,
        check_external_links: bool = True,
        timeout_seconds: float = 8.0,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        # Normalize starting URL
        self.raw_root_url = root_url.strip()
        if not self.raw_root_url.startswith(("http://", "https://")):
            self.raw_root_url = "https://" + self.raw_root_url

        self.root_url, _ = urldefrag(self.raw_root_url)
        self.parsed_root = urlparse(self.root_url)
        self.root_domain = self.parsed_root.netloc.lower()
        self.scheme = self.parsed_root.scheme

        self.max_depth = max(0, min(5, max_depth))
        self.max_pages = max(1, min(50, max_pages))
        self.check_external_links = check_external_links
        self.timeout = timeout_seconds
        self.progress_callback = progress_callback

        self.link_checker = ConcurrentLinkChecker(max_workers=10, timeout_seconds=timeout_seconds)

    def _notify(self, event_type: str, data: Dict[str, Any]) -> None:
        if self.progress_callback:
            payload = {"type": event_type, "timestamp": time.time(), **data}
            try:
                self.progress_callback(payload)
            except Exception:
                pass

    def _normalize_url(self, url: str) -> str:
        clean, _ = urldefrag(url)
        parsed = urlparse(clean)
        # Normalise lowercase domain, preserve path
        path = parsed.path or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _is_internal(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc.lower() == self.root_domain

    def check_robots_and_sitemap(self, client: httpx.Client) -> List[AuditIssue]:
        """Probes robots.txt and sitemap.xml on the target host."""
        issues = []
        base = f"{self.scheme}://{self.root_domain}"

        # 1. robots.txt
        robots_url = f"{base}/robots.txt"
        try:
            r = client.get(robots_url, headers={"User-Agent": self.USER_AGENT})
            if r.status_code == 200 and "user-agent:" in r.text.lower():
                issues.append(AuditIssue(
                    id="robots_txt_found",
                    category=IssueCategory.META.value,
                    severity=Severity.PASSED.value,
                    title="robots.txt Found and Valid",
                    description=f"Accessible at {robots_url} with valid directives.",
                    location=robots_url,
                    impact="Instructs search engine web crawlers on indexation boundaries.",
                    recommendation="Ensure staging or sensitive admin URLs are disallowed."
                ))
            else:
                issues.append(AuditIssue(
                    id="robots_txt_missing",
                    category=IssueCategory.META.value,
                    severity=Severity.NOTICE.value,
                    title="robots.txt Not Found or Empty",
                    description=f"Server returned HTTP {r.status_code} for {robots_url}.",
                    location=robots_url,
                    impact="Crawlers will explore all accessible paths without guidance.",
                    recommendation="Add a standard robots.txt file in the root directory.",
                    code_fix="User-agent: *\nDisallow: /admin/\nSitemap: " + f"{base}/sitemap.xml"
                ))
        except Exception:
            issues.append(AuditIssue(
                id="robots_txt_unreachable",
                category=IssueCategory.META.value,
                severity=Severity.NOTICE.value,
                title="Could Not Connect to robots.txt",
                description=f"Failed to fetch {robots_url}.",
                location=robots_url,
                impact="Crawlers cannot verify crawling policies.",
                recommendation="Ensure web server responds properly to /robots.txt."
            ))

        # 2. sitemap.xml
        sitemap_url = f"{base}/sitemap.xml"
        try:
            r = client.get(sitemap_url, headers={"User-Agent": self.USER_AGENT})
            if r.status_code == 200 and ("<urlset" in r.text.lower() or "<sitemapindex" in r.text.lower()):
                issues.append(AuditIssue(
                    id="sitemap_xml_found",
                    category=IssueCategory.META.value,
                    severity=Severity.PASSED.value,
                    title="XML Sitemap Detected",
                    description=f"Found valid XML sitemap at {sitemap_url}.",
                    location=sitemap_url,
                    impact="Accelerates indexation of new and updated pages in Google Search Console.",
                    recommendation="Keep XML sitemap dynamically updated with new articles and pages."
                ))
            else:
                issues.append(AuditIssue(
                    id="sitemap_xml_missing",
                    category=IssueCategory.META.value,
                    severity=Severity.WARNING.value,
                    title="Missing XML Sitemap (/sitemap.xml)",
                    description=f"No standard XML sitemap found at {sitemap_url} (HTTP {r.status_code}).",
                    location=sitemap_url,
                    impact="Slows discovery of deeply nested pages by search engine spiders.",
                    recommendation="Generate and publish an XML sitemap and submit to Google Search Console.",
                    code_fix="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n  <url>\n    <loc>" + self.root_url + "</loc>\n  </url>\n</urlset>"
                ))
        except Exception:
            pass

        return issues

    def run_audit(self) -> SiteAuditReport:
        """Executes the complete crawl and multi-page audit pipeline."""
        start_time = time.time()
        self._notify("crawl_started", {
            "root_url": self.root_url,
            "max_depth": self.max_depth,
            "max_pages": self.max_pages
        })

        visited_urls: Set[str] = set()
        queue: deque = deque([(self.root_url, 0)])  # (url, depth)
        
        pages_results: List[PageAuditResult] = []
        all_extracted_links: List[Dict[str, Any]] = []
        all_issues: List[AuditIssue] = []

        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            # 1. Probe robots.txt and sitemap.xml
            self._notify("status_update", {"message": "Probing robots.txt and sitemap.xml..."})
            root_issues = self.check_robots_and_sitemap(client)
            all_issues.extend(root_issues)

            # 2. Multi-page Crawl Loop
            while queue and len(visited_urls) < self.max_pages:
                current_url, depth = queue.popleft()
                norm_url = self._normalize_url(current_url)

                if norm_url in visited_urls:
                    continue

                visited_urls.add(norm_url)
                self._notify("crawling_page", {
                    "url": norm_url,
                    "depth": depth,
                    "crawled_count": len(visited_urls),
                    "max_pages": self.max_pages,
                    "queue_length": len(queue)
                })

                # Fetch page HTML
                page_start = time.time()
                try:
                    resp = client.get(norm_url, headers=headers)
                    latency = (time.time() - page_start) * 1000
                    status_code = resp.status_code
                    html_content = resp.text
                    resp_headers = dict(resp.headers)
                except Exception as e:
                    latency = (time.time() - page_start) * 1000
                    status_code = 0
                    html_content = ""
                    resp_headers = {}
                    all_issues.append(AuditIssue(
                        id=f"page_fetch_failed_{len(visited_urls)}",
                        category=IssueCategory.PERFORMANCE.value,
                        severity=Severity.CRITICAL.value,
                        title=f"Failed to Fetch Page: {norm_url}",
                        description=f"HTTP connection failed: {str(e)[:80]}",
                        location=norm_url,
                        impact="Page is offline or unreachable by crawlers.",
                        recommendation="Check DNS settings and server uptime."
                    ))

                if status_code == 200 and html_content:
                    # Run Page Auditor
                    auditor = HTMLPageAuditor(
                        url=norm_url,
                        html_content=html_content,
                        status_code=status_code,
                        response_time_ms=latency,
                        headers=resp_headers
                    )
                    page_res = auditor.audit()
                    pages_results.append(page_res)
                    all_issues.extend([AuditIssue(**i) for i in page_res.issues])

                    # Extract hyperlinks
                    page_links = self.link_checker.extract_links_from_html(norm_url, html_content)
                    all_extracted_links.extend(page_links)

                    # Enqueue internal links for multi-page crawl if depth allows
                    if depth < self.max_depth:
                        for l in page_links:
                            if l.get("is_internal") and not l.get("is_fragment_only"):
                                link_norm = self._normalize_url(l["url"])
                                if link_norm not in visited_urls and link_norm not in [q[0] for q in queue]:
                                    queue.append((link_norm, depth + 1))
                else:
                    # Non-200 page
                    pages_results.append(PageAuditResult(
                        url=norm_url,
                        status_code=status_code,
                        response_time_ms=latency
                    ))

            # 3. Check Hyperlinks (Broken links detection)
            self._notify("checking_links", {
                "total_links": len(all_extracted_links),
                "message": f"Validating {len(all_extracted_links)} discovered links across crawled pages..."
            })

            link_results, link_issues = self.link_checker.check_all_links(
                all_extracted_links,
                check_external=self.check_external_links
            )
            all_issues.extend(link_issues)

        # 4. Filter broken links
        broken_links_list = [l.to_dict() for l in link_results if l.is_broken]

        # 5. Deduplicate identical issues across pages if any
        seen_issue_keys = set()
        deduped_issues = []
        for iss in all_issues:
            key = (iss.id, iss.location)
            if key not in seen_issue_keys:
                seen_issue_keys.add(key)
                deduped_issues.append(iss.to_dict())

        # 6. Scoring & Grading
        health_score, grade, category_scores, severity_counts = AuditReporter.calculate_scores(
            deduped_issues,
            pages_count=len(visited_urls),
            broken_links_count=len(broken_links_list)
        )

        duration = round(time.time() - start_time, 2)
        audit_id = f"audit_{int(time.time() * 1000)}"

        # Aggregate Structured Data & Security Summaries
        structured_summary = []
        for p in pages_results:
            for s in p.structured_data:
                structured_summary.append({
                    "page_url": p.url,
                    "type": s.get("type"),
                    "name": s.get("name")
                })

        avg_sec_score = int(sum([p.security_score for p in pages_results]) / max(1, len(pages_results)))
        sec_grade = "A+" if avg_sec_score >= 90 else ("A" if avg_sec_score >= 80 else ("B" if avg_sec_score >= 65 else ("C" if avg_sec_score >= 50 else "F")))

        report = SiteAuditReport(
            id=audit_id,
            root_url=self.root_url,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=duration,
            pages_crawled=len(visited_urls),
            total_links_checked=len(link_results),
            broken_links_count=len(broken_links_list),
            health_score=health_score,
            grade=grade,
            category_scores=category_scores,
            severity_counts=severity_counts,
            issues=deduped_issues,
            broken_links=broken_links_list,
            pages=[p.to_dict() for p in pages_results],
            crawl_summary={
                "max_depth_configured": self.max_depth,
                "max_pages_configured": self.max_pages,
                "external_links_checked": self.check_external_links,
                "root_domain": self.root_domain
            },
            structured_data_summary=structured_summary,
            security_summary={
                "average_score": avg_sec_score,
                "overall_grade": sec_grade
            }
        )

        self._notify("audit_completed", {
            "health_score": health_score,
            "grade": grade,
            "duration": duration,
            "pages_crawled": len(visited_urls),
            "broken_links": len(broken_links_list),
            "issues_count": len(deduped_issues)
        })

        return report
