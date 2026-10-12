import time
import concurrent.futures
from typing import List, Dict, Set, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import httpx
from .models import LinkCheckResult, AuditIssue, Severity, IssueCategory


class ConcurrentLinkChecker:
    """
    Validates internal and external links concurrently.
    Detects HTTP status codes (404, 500, etc.), network timeouts,
    DNS failures, and dead anchor hash fragments.
    """

    USER_AGENT = "Mozilla/5.0 (compatible; WebsiteAuditBot/2.0; +https://github.com/website-audit)"

    def __init__(self, max_workers: int = 10, timeout_seconds: float = 6.0):
        self.max_workers = max_workers
        self.timeout = timeout_seconds
        self.cache: Dict[str, Tuple[Optional[int], bool, Optional[str], float]] = {}

    def extract_links_from_html(self, base_url: str, html_content: str) -> List[Dict[str, str]]:
        """Extract all hyperlink tags with their anchor text and resolved destination."""
        soup = BeautifulSoup(html_content, "html.parser")
        extracted = []
        base_domain = urlparse(base_url).netloc.lower()

        for a_tag in soup.find_all("a", href=True):
            raw_href = a_tag.get("href", "").strip()
            anchor_text = a_tag.get_text(separator=" ", strip=True) or "[No Anchor Text / Image Link]"
            
            # Skip mailto, tel, javascript, data, etc.
            if not raw_href or raw_href.startswith(("mailto:", "tel:", "javascript:", "sms:", "whatsapp:", "data:")):
                continue

            # Check if this is an anchor on the same page e.g. "#services"
            if raw_href.startswith("#"):
                fragment = raw_href[1:]
                if fragment:  # Non-empty hash
                    # Check if fragment ID exists in this page's HTML
                    has_target = bool(soup.find(id=fragment) or soup.find(attrs={"name": fragment}))
                    extracted.append({
                        "url": base_url + raw_href,
                        "raw_href": raw_href,
                        "anchor_text": anchor_text,
                        "source_url": base_url,
                        "is_internal": True,
                        "is_fragment_only": True,
                        "target_found": has_target,
                        "fragment": fragment
                    })
                continue

            # Absolute or relative link
            resolved_url = urljoin(base_url, raw_href)
            parsed_res = urlparse(resolved_url)
            
            # Only test http and https
            if parsed_res.scheme not in ("http", "https"):
                continue

            is_internal = parsed_res.netloc.lower() == base_domain

            extracted.append({
                "url": resolved_url,
                "raw_href": raw_href,
                "anchor_text": anchor_text,
                "source_url": base_url,
                "is_internal": is_internal,
                "is_fragment_only": False,
                "target_found": True,
                "fragment": parsed_res.fragment
            })

        return extracted

    def check_link_status(self, url: str) -> Tuple[Optional[int], bool, Optional[str], float]:
        """
        Check the status code of a single URL.
        Returns: (status_code, is_broken, error_message, latency_ms)
        """
        # Strip fragment for network request
        clean_url, _ = urldefrag(url)

        if clean_url in self.cache:
            return self.cache[clean_url]

        start_time = time.time()
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "*/*"
        }

        status_code = None
        is_broken = False
        error_msg = None

        # Create client with redirects followed and polite timeout
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                # First try HEAD
                try:
                    resp = client.head(clean_url, headers=headers)
                    if resp.status_code in (405, 403, 400):
                        # Some servers reject HEAD, fallback to GET
                        resp = client.get(clean_url, headers=headers)
                except httpx.HTTPError:
                    # Fallback to GET
                    resp = client.get(clean_url, headers=headers)

                status_code = resp.status_code
                latency_ms = round((time.time() - start_time) * 1000, 2)

                if status_code >= 400:
                    is_broken = True
                    error_msg = f"HTTP {status_code} {resp.reason_phrase if hasattr(resp, 'reason_phrase') else ''}"
                else:
                    is_broken = False

        except httpx.ConnectTimeout:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            is_broken = True
            error_msg = "Connection Timeout"
        except httpx.ReadTimeout:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            is_broken = True
            error_msg = "Read Timeout"
        except httpx.ConnectError as e:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            is_broken = True
            error_msg = f"Connection Refused / DNS Failure"
        except Exception as e:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            is_broken = True
            error_msg = f"Network Error: {str(e)[:60]}"

        result = (status_code, is_broken, error_msg, latency_ms)
        self.cache[clean_url] = result
        return result

    def check_all_links(self, links_data: List[Dict[str, Any]], check_external: bool = True) -> Tuple[List[LinkCheckResult], List[AuditIssue]]:
        """
        Concurrently checks all extracted links and returns detailed LinkCheckResults + AuditIssues.
        """
        results: List[LinkCheckResult] = []
        issues: List[AuditIssue] = []

        # Separate items to probe over network
        unique_urls_to_test: Set[str] = set()
        for item in links_data:
            if item.get("is_fragment_only"):
                continue
            if not check_external and not item.get("is_internal"):
                continue
            clean_u, _ = urldefrag(item["url"])
            unique_urls_to_test.add(clean_u)

        # Run concurrent checks
        if unique_urls_to_test:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_url = {executor.submit(self.check_link_status, url): url for url in unique_urls_to_test}
                for future in concurrent.futures.as_completed(future_to_url):
                    pass  # Results stored in self.cache

        # Compile final results
        broken_count = 0
        for item in links_data:
            url = item["url"]
            source = item["source_url"]
            anchor = item["anchor_text"]
            is_internal = item["is_internal"]

            # Handle fragment-only link test
            if item.get("is_fragment_only"):
                target_found = item.get("target_found", False)
                fragment = item.get("fragment", "")
                if not target_found:
                    broken_count += 1
                    link_res = LinkCheckResult(
                        url=url,
                        anchor_text=anchor,
                        source_url=source,
                        is_internal=True,
                        status_code=None,
                        is_broken=True,
                        error_message=f"Dead hash fragment '#{fragment}' (no id or name matches)",
                        response_time_ms=0.0
                    )
                    results.append(link_res)
                    issues.append(AuditIssue(
                        id=f"dead_anchor_{fragment}",
                        category=IssueCategory.LINKS.value,
                        severity=Severity.CRITICAL.value,
                        title=f"Dead Anchor Hash Link: #{fragment}",
                        description=f"Anchor link '{anchor}' points to #{fragment}, but no element on the page has id=\"{fragment}\" or name=\"{fragment}\".",
                        location=f"<a href=\"#{fragment}\">{anchor}</a>",
                        impact="Clicking this link does nothing, confusing visitors attempting to reach specific page sections.",
                        recommendation=f"Add id=\"{fragment}\" to the targeted section or update href to the correct anchor identifier.",
                        code_fix=f'<section id="{fragment}">\n  <!-- Target content for #{fragment} -->\n</section>'
                    ))
                else:
                    results.append(LinkCheckResult(
                        url=url,
                        anchor_text=anchor,
                        source_url=source,
                        is_internal=True,
                        status_code=200,
                        is_broken=False,
                        error_message=None,
                        response_time_ms=0.0
                    ))
                continue

            # Regular link
            if not check_external and not is_internal:
                # External check skipped
                results.append(LinkCheckResult(
                    url=url,
                    anchor_text=anchor,
                    source_url=source,
                    is_internal=False,
                    status_code=None,
                    is_broken=False,
                    error_message="External check skipped by configuration",
                    response_time_ms=0.0
                ))
                continue

            clean_u, _ = urldefrag(url)
            status_code, is_broken, error_msg, latency_ms = self.cache.get(
                clean_u, (None, True, "Not checked", 0.0)
            )

            link_res = LinkCheckResult(
                url=url,
                anchor_text=anchor,
                source_url=source,
                is_internal=is_internal,
                status_code=status_code,
                is_broken=is_broken,
                error_message=error_msg,
                response_time_ms=latency_ms
            )
            results.append(link_res)

            if is_broken:
                broken_count += 1
                link_type = "Internal" if is_internal else "External"
                issues.append(AuditIssue(
                    id=f"broken_link_{clean_u[:40]}",
                    category=IssueCategory.LINKS.value,
                    severity=Severity.CRITICAL.value,
                    title=f"Broken {link_type} Link ({status_code or error_msg})",
                    description=f"Link to '{url}' with anchor text '{anchor}' failed with status: {error_msg or status_code}.",
                    location=f"Found on {source} -> <a href=\"{url}\">{anchor}</a>",
                    impact="Severely hurts user trust, increases bounce rate, and wastes Google crawler budget.",
                    recommendation=f"Update the destination URL or remove the dead hyperlink from {source}.",
                    code_fix=f'<!-- On {source}: -->\n<a href="/updated-valid-path">{anchor}</a>'
                ))

        if broken_count == 0 and len(results) > 0:
            issues.append(AuditIssue(
                id="all_links_healthy",
                category=IssueCategory.LINKS.value,
                severity=Severity.PASSED.value,
                title=f"All {len(results)} Hyperlinks Verified Active",
                description="Every tested internal and external hyperlink responded with valid HTTP status codes.",
                location=f"{len(results)} links tested",
                impact="Ensures flawless visitor navigation and unimpeded search engine crawl discovery.",
                recommendation="Maintain routine link health monitoring across all published content."
            ))

        return results, issues
