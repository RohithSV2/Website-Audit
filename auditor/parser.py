import re
from typing import List, Dict, Tuple, Any, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .models import AuditIssue, HeadingNode, PageAuditResult, Severity, IssueCategory
from .structured_data import StructuredDataValidator
from .security_audit import SecurityHeadersAuditor
from .performance_metrics import PerformanceMetricsAuditor


class HTMLPageAuditor:
    """
    Parses HTML documents to evaluate SEO signals, structural hierarchy,
    accessibility attributes, and DOM integrity.
    """

    DEPRECATED_TAGS = {"center", "font", "marquee", "blink", "big", "strike", "frame", "frameset", "applet"}

    def __init__(self, url: str, html_content: str, status_code: int = 200, response_time_ms: float = 0.0, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.parsed_url = urlparse(url)
        self.html_content = html_content or ""
        self.status_code = status_code
        self.response_time_ms = round(response_time_ms, 2)
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        
        # Parse with BeautifulSoup
        self.soup = BeautifulSoup(self.html_content, "html.parser")
        self.issues: List[AuditIssue] = []

    def audit(self) -> PageAuditResult:
        """Run all systematic checks on the page and construct the PageAuditResult."""
        parsed_title, title_len = self._audit_title()
        parsed_desc, desc_len = self._audit_description()
        canonical = self._audit_canonical()
        robots_meta = self._audit_robots()
        viewport = self._audit_viewport()
        lang = self._audit_html_lang()
        charset = self._audit_charset()
        og_data = self._audit_open_graph()
        twitter_data = self._audit_twitter_cards()
        self._audit_favicon()
        
        # Headings structure
        heading_counts, headings_tree = self._audit_heading_structure()
        
        # Images & Media
        total_images, missing_alt = self._audit_images()
        
        # Semantic & Structural HTML
        self._audit_semantics_and_deprecated()
        
        # Security & Transport
        ssl_active = self._audit_security_and_transport()
        
        # Content Metrics
        word_count, reading_time = self._compute_content_metrics()

        # Pro Module 1: Structured Data (Schema.org JSON-LD)
        schemas, schema_issues = StructuredDataValidator.validate(self.soup, self.url)
        self.issues.extend(schema_issues)

        # Pro Module 2: Enterprise Security Headers & SSL Grade
        sec_score, sec_grade, sec_headers, sec_issues = SecurityHeadersAuditor.audit(self.headers, ssl_active, self.url)
        self.issues.extend(sec_issues)

        # Pro Module 3: Performance, DOM Size & CWV Signals
        perf_metrics, perf_issues = PerformanceMetricsAuditor.audit(self.soup, self.url)
        self.issues.extend(perf_issues)

        # SERP Snippet Preview Simulation (Google Search Simulator)
        clean_netloc = self.parsed_url.netloc
        clean_path = self.parsed_url.path or "/"
        serp_preview = {
            "url": self.url,
            "display_url": f"https://{clean_netloc}{clean_path}",
            "title": parsed_title or "Untitled Document",
            "truncated_title": (parsed_title[:57] + "...") if parsed_title and len(parsed_title) > 60 else (parsed_title or "Untitled Document"),
            "snippet": (parsed_desc[:155] + "...") if parsed_desc and len(parsed_desc) > 160 else (parsed_desc or "No meta description provided. Google will extract text snippets from page body."),
            "is_truncated_title": bool(parsed_title and len(parsed_title) > 60),
            "is_truncated_snippet": bool(parsed_desc and len(parsed_desc) > 160)
        }

        # Social Card Preview Simulation (X/Twitter & OpenGraph)
        social_preview = {
            "og_title": og_data.get("og:title") or parsed_title or "No Title",
            "og_description": og_data.get("og:description") or parsed_desc or "No description provided.",
            "og_image": og_data.get("og:image"),
            "og_url": og_data.get("og:url") or self.url,
            "twitter_card": twitter_data.get("twitter:card", "summary_large_image"),
            "twitter_title": twitter_data.get("twitter:title") or og_data.get("og:title") or parsed_title or "No Title",
            "twitter_description": twitter_data.get("twitter:description") or og_data.get("og:description") or parsed_desc or ""
        }

        return PageAuditResult(
            url=self.url,
            status_code=self.status_code,
            response_time_ms=self.response_time_ms,
            title=parsed_title,
            title_length=title_len,
            description=parsed_desc,
            description_length=desc_len,
            canonical=canonical,
            robots_meta=robots_meta,
            viewport=viewport,
            lang=lang,
            charset=charset,
            open_graph=og_data,
            twitter_cards=twitter_data,
            heading_counts=heading_counts,
            headings_tree=[h.to_dict() for h in headings_tree],
            images_total=total_images,
            images_missing_alt=missing_alt,
            word_count=word_count,
            content_length_bytes=len(self.html_content.encode("utf-8")),
            ssl_active=ssl_active,
            issues=[issue.to_dict() for issue in self.issues],
            links_found=len(self.soup.find_all("a", href=True)),
            structured_data=schemas,
            security_headers=sec_headers,
            security_score=sec_score,
            security_grade=sec_grade,
            performance_metrics=perf_metrics,
            serp_preview=serp_preview,
            social_preview=social_preview
        )

    # ---------------------------------------------------------
    # 1. META TAGS & HEAD AUDIT
    # ---------------------------------------------------------
    def _audit_title(self) -> Tuple[Optional[str], int]:
        title_tag = self.soup.find("title")
        if not title_tag or not title_tag.string or not title_tag.string.strip():
            self.issues.append(AuditIssue(
                id="missing_title",
                category=IssueCategory.META.value,
                severity=Severity.CRITICAL.value,
                title="Missing or Empty <title> Tag",
                description="The page lacks a <title> tag in the <head> section. Search engines rely on title tags as primary signals.",
                location=self.url,
                impact="Catastrophic for organic search rankings and click-through rates. Browsers cannot name the tab properly.",
                recommendation="Add a descriptive, concise <title> inside <head> containing primary keywords (30-60 chars).",
                code_fix="<head>\n  <title>Your Primary Keyword & Company Name (30-60 chars)</title>\n</head>"
            ))
            return None, 0

        title_text = title_tag.string.strip()
        t_len = len(title_text)

        if t_len < 30:
            self.issues.append(AuditIssue(
                id="short_title",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title=f"Title Tag Is Too Short ({t_len} chars)",
                description=f"The current title '{title_text}' is {t_len} characters. Search engines prefer 30 to 60 characters.",
                location=f"<title>{title_text}</title>",
                impact="Underutilizes SERP display space, missing key topical keywords and brand identifiers.",
                recommendation="Expand the title tag to 30-60 characters with relevant search terms.",
                code_fix=f"<title>{title_text} | Comprehensive Guide & Solutions</title>"
            ))
        elif t_len > 60:
            self.issues.append(AuditIssue(
                id="long_title",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title=f"Title Tag Is Too Long ({t_len} chars)",
                description=f"The current title is {t_len} characters. Google truncates titles over ~60 characters on desktop/mobile.",
                location=f"<title>{title_text[:40]}...</title>",
                impact="Search engines truncate the title with ellipses ('...'), cutting off brand messaging.",
                recommendation="Trim the title to under 60 characters while retaining primary value proposition.",
                code_fix=f"<title>{title_text[:57]}...</title>"
            ))
        else:
            self.issues.append(AuditIssue(
                id="optimal_title",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Optimal Title Tag Length",
                description=f"The title tag is {t_len} characters ('{title_text}'), perfectly within the 30-60 character range.",
                location=f"<title>{title_text}</title>",
                impact="Maximizes CTR and displays completely without truncation on search engine results.",
                recommendation="Maintain this title length and keyword clarity."
            ))

        return title_text, t_len

    def _audit_description(self) -> Tuple[Optional[str], int]:
        desc_tag = self.soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if not desc_tag or not desc_tag.get("content", "").strip():
            self.issues.append(AuditIssue(
                id="missing_meta_description",
                category=IssueCategory.META.value,
                severity=Severity.CRITICAL.value,
                title="Missing Meta Description",
                description="The page lacks a meta description tag. Google will generate arbitrary snippets from random page text.",
                location=self.url,
                impact="Decreases user click-through rate (CTR) on SERP pages by up to 35%.",
                recommendation="Provide an engaging meta description between 70 and 160 characters highlighting page value.",
                code_fix="<meta name=\"description\" content=\"Discover in-depth website audits, SEO health scores, and systematic debugging to boost your search rankings.\">"
            ))
            return None, 0

        desc_text = desc_tag.get("content", "").strip()
        d_len = len(desc_text)

        if d_len < 70:
            self.issues.append(AuditIssue(
                id="short_meta_description",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title=f"Meta Description Too Short ({d_len} chars)",
                description=f"Current description is only {d_len} characters. Recommended length is 70 to 160 characters.",
                location=f"<meta name=\"description\" content=\"{desc_text}\">",
                impact="Wastes SERP snippet real estate and leaves searchers with incomplete context.",
                recommendation="Elaborate on page benefits, target keywords, and a call-to-action.",
                code_fix=f"<meta name=\"description\" content=\"{desc_text} Explore features, real-time insights, and instant reports.\">"
            ))
        elif d_len > 160:
            self.issues.append(AuditIssue(
                id="long_meta_description",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title=f"Meta Description Too Long ({d_len} chars)",
                description=f"Current description is {d_len} characters. Google typically truncates snippets exceeding 160 characters.",
                location=f"<meta name=\"description\" content=\"{desc_text[:40]}...\">",
                impact="Text is cut off midway with '...', potentially hiding your call to action.",
                recommendation="Condense the description to 120-155 characters for optimal snippet presentation.",
                code_fix=f"<meta name=\"description\" content=\"{desc_text[:155]}...\">"
            ))
        else:
            self.issues.append(AuditIssue(
                id="optimal_meta_description",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Optimal Meta Description Length",
                description=f"Meta description is {d_len} characters, well balanced for modern search engine snippet display.",
                location=f"<meta name=\"description\" content=\"{desc_text[:50]}...\">",
                impact="Ensures clean presentation and compelling call-to-action in search engine results.",
                recommendation="Keep this concise and user-focused."
            ))

        return desc_text, d_len

    def _audit_canonical(self) -> Optional[str]:
        canonical_tag = self.soup.find("link", rel=lambda r: r and "canonical" in r)
        if not canonical_tag or not canonical_tag.get("href"):
            self.issues.append(AuditIssue(
                id="missing_canonical",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title="Missing Canonical Tag (<link rel='canonical'>)",
                description="No canonical tag declared. Search engines might index duplicate versions (HTTP vs HTTPS, trailing slash, tracking params).",
                location=self.url,
                impact="Potential duplicate content penalties and split page ranking signals across variants.",
                recommendation="Add a self-referential canonical URL tag in the <head>.",
                code_fix=f"<link rel=\"canonical\" href=\"{self.url}\" />"
            ))
            return None

        href = canonical_tag.get("href", "").strip()
        parsed_canon = urlparse(href)
        if not parsed_canon.scheme or not parsed_canon.netloc:
            self.issues.append(AuditIssue(
                id="relative_canonical",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title="Relative Canonical Tag Detected",
                description=f"The canonical tag href '{href}' is relative. Search engines strongly recommend absolute canonical URLs.",
                location=f"<link rel=\"canonical\" href=\"{href}\">",
                impact="Search bots might misinterpret relative URLs depending on request paths.",
                recommendation="Convert canonical URL to an absolute URL with scheme and host.",
                code_fix=f"<link rel=\"canonical\" href=\"{urljoin(self.url, href)}\" />"
            ))
        else:
            self.issues.append(AuditIssue(
                id="valid_canonical",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Canonical URL Configured",
                description=f"Canonical URL points to '{href}'.",
                location=f"<link rel=\"canonical\" href=\"{href}\">",
                impact="Prevents duplicate content fragmentation in search indexes.",
                recommendation="Verify this represents the authoritative master version."
            ))
        return href

    def _audit_robots(self) -> Optional[str]:
        robots_tag = self.soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
        if not robots_tag:
            self.issues.append(AuditIssue(
                id="default_robots",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Default Robots Directive Active",
                description="No restrictive meta robots tag detected; crawlers will index and follow links by standard default.",
                location="<meta name='robots'>",
                impact="Allows full crawl and indexing unless blocked by robots.txt.",
                recommendation="Add an explicit 'index, follow' tag if you want deterministic indexing policy."
            ))
            return None

        content = robots_tag.get("content", "").lower()
        if "noindex" in content:
            self.issues.append(AuditIssue(
                id="noindex_detected",
                category=IssueCategory.META.value,
                severity=Severity.CRITICAL.value,
                title="Dangerous 'noindex' Directive Present!",
                description=f"The robots meta tag contains 'noindex' ({content}). This explicitly commands Google not to index this page!",
                location=f"<meta name=\"robots\" content=\"{content}\">",
                impact="Page will be completely de-indexed and vanish from organic search rankings.",
                recommendation="Remove 'noindex' immediately if this is a public production page meant to receive search traffic.",
                code_fix="<meta name=\"robots\" content=\"index, follow\">"
            ))
        if "nofollow" in content:
            self.issues.append(AuditIssue(
                id="nofollow_detected",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title="'nofollow' Directive Configured",
                description="The robots meta tag contains 'nofollow', stopping search bots from following outbound internal/external links.",
                location=f"<meta name=\"robots\" content=\"{content}\">",
                impact="Internal link equity (PageRank) will not flow naturally through your site structure.",
                recommendation="Use 'index, follow' on general landing pages unless this is an untrusted user-generated content section."
            ))
        return content

    def _audit_viewport(self) -> Optional[str]:
        viewport_tag = self.soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
        if not viewport_tag or not viewport_tag.get("content"):
            self.issues.append(AuditIssue(
                id="missing_viewport",
                category=IssueCategory.META.value,
                severity=Severity.CRITICAL.value,
                title="Missing Viewport Meta Tag",
                description="No viewport meta tag declared. Mobile devices will render the site in a 980px desktop simulator layout.",
                location="<head>",
                impact="Causes mobile usability failures in Google Mobile-First Indexing and high bounce rates.",
                recommendation="Add a standard responsive viewport tag to the document head.",
                code_fix="<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
            ))
            return None
        
        content = viewport_tag.get("content", "")
        if "width=device-width" not in content:
            self.issues.append(AuditIssue(
                id="invalid_viewport",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title="Suboptimal Viewport Declaration",
                description=f"Viewport content '{content}' does not include 'width=device-width'.",
                location=f"<meta name=\"viewport\" content=\"{content}\">",
                impact="May prevent the layout from auto-adapting to modern smartphone screen sizes.",
                recommendation="Ensure width=device-width, initial-scale=1.0 is specified.",
                code_fix="<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
            ))
        else:
            self.issues.append(AuditIssue(
                id="valid_viewport",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Mobile Viewport Properly Configured",
                description=f"Configured with '{content}'. Ready for responsive mobile viewports.",
                location=f"<meta name=\"viewport\" content=\"{content}\">",
                impact="Supports fluid responsive layouts for Google's Mobile-First indexing.",
                recommendation="Maintain responsive media queries across devices."
            ))
        return content

    def _audit_html_lang(self) -> Optional[str]:
        html_tag = self.soup.find("html")
        lang = html_tag.get("lang") if html_tag else None
        if not lang or not lang.strip():
            self.issues.append(AuditIssue(
                id="missing_lang",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title="Missing HTML 'lang' Attribute",
                description="The root <html> element does not specify a language attribute.",
                location="<html>",
                impact="Screen readers cannot determine appropriate pronunciation; search engines cannot verify targeted locale.",
                recommendation="Add the ISO language code to the <html> opening tag.",
                code_fix="<html lang=\"en\">"
            ))
            return None
        self.issues.append(AuditIssue(
            id="valid_lang",
            category=IssueCategory.META.value,
            severity=Severity.PASSED.value,
            title=f"HTML Language Defined ({lang})",
            description=f"Root document language set to '{lang}'.",
            location=f"<html lang=\"{lang}\">",
            impact="Assists assistive technology accessibility and international SEO ranking.",
            recommendation="Ensure translated subpages adjust this attribute accordingly."
        ))
        return lang.strip()

    def _audit_charset(self) -> Optional[str]:
        charset_tag = self.soup.find("meta", charset=True) or self.soup.find("meta", attrs={"http-equiv": re.compile(r"content-type", re.I)})
        if not charset_tag:
            self.issues.append(AuditIssue(
                id="missing_charset",
                category=IssueCategory.META.value,
                severity=Severity.WARNING.value,
                title="Missing Character Encoding (<meta charset>)",
                description="No character encoding was specified in the HTML document head.",
                location="<head>",
                impact="Browsers may guess encoding, causing mojibake (garbled text or special characters).",
                recommendation="Include UTF-8 encoding as the first child of <head>.",
                code_fix="<meta charset=\"UTF-8\">"
            ))
            return None
        charset_val = charset_tag.get("charset") or charset_tag.get("content", "")
        self.issues.append(AuditIssue(
            id="valid_charset",
            category=IssueCategory.META.value,
            severity=Severity.PASSED.value,
            title="Character Encoding Declared",
            description=f"Charset specified as '{charset_val}'.",
            location=str(charset_tag)[:60],
            impact="Guarantees accurate rendering of unicode characters, emojis, and international text.",
            recommendation="Always keep this at the top of <head>."
        ))
        return str(charset_val)

    def _audit_open_graph(self) -> Dict[str, str]:
        og = {}
        for tag in self.soup.find_all("meta", property=re.compile(r"^og:", re.I)):
            prop = tag.get("property", "").lower()
            val = tag.get("content", "")
            og[prop] = val

        required_og = ["og:title", "og:description", "og:image", "og:url"]
        missing_og = [r for r in required_og if r not in og or not og[r].strip()]

        if missing_og:
            self.issues.append(AuditIssue(
                id="incomplete_open_graph",
                category=IssueCategory.META.value,
                severity=Severity.NOTICE.value,
                title=f"Missing Open Graph Tags ({', '.join(missing_og)})",
                description=f"Social sharing metadata lacks: {', '.join(missing_og)}. Links shared on LinkedIn, WhatsApp, or Slack may look broken or plain.",
                location="<head>",
                impact="Reduces social media CTR and professional brand perception.",
                recommendation="Add standard OpenGraph tags for rich preview cards.",
                code_fix=f'<meta property="og:title" content="Page Title">\n<meta property="og:description" content="Engaging description">\n<meta property="og:image" content="{urljoin(self.url, "/og-preview.png")}">\n<meta property="og:url" content="{self.url}">'
            ))
        else:
            self.issues.append(AuditIssue(
                id="valid_open_graph",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Complete Open Graph Social Tags",
                description="All essential Open Graph attributes (og:title, og:description, og:image, og:url) are present.",
                location="<head>",
                impact="Rich cards with thumbnail images will render automatically when shared across social networks.",
                recommendation="Verify that the og:image is at least 1200x630px for high-DPI displays."
            ))
        return og

    def _audit_twitter_cards(self) -> Dict[str, str]:
        twitter = {}
        for tag in self.soup.find_all("meta", attrs={"name": re.compile(r"^twitter:", re.I)}):
            name = tag.get("name", "").lower()
            val = tag.get("content", "")
            twitter[name] = val

        if "twitter:card" not in twitter:
            self.issues.append(AuditIssue(
                id="missing_twitter_card",
                category=IssueCategory.META.value,
                severity=Severity.NOTICE.value,
                title="Missing Twitter Card Tag",
                description="No 'twitter:card' meta tag found. X/Twitter will fall back to basic text links.",
                location="<head>",
                impact="Missing opportunity for large photo cards on X/Twitter feeds.",
                recommendation="Add 'twitter:card' with value 'summary_large_image'.",
                code_fix="<meta name=\"twitter:card\" content=\"summary_large_image\">"
            ))
        return twitter

    def _audit_favicon(self) -> None:
        icon = self.soup.find("link", rel=lambda r: r and any("icon" in x for x in (r if isinstance(r, list) else [r])))
        if not icon:
            self.issues.append(AuditIssue(
                id="missing_favicon",
                category=IssueCategory.META.value,
                severity=Severity.NOTICE.value,
                title="Missing Favicon Link",
                description="No explicit <link rel='icon'> was found in the HTML head.",
                location="<head>",
                impact="Displays default blank globe icon in browser tabs and mobile bookmarks.",
                recommendation="Provide high-resolution SVG or PNG favicons for brand recognition.",
                code_fix="<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\">"
            ))
        else:
            self.issues.append(AuditIssue(
                id="valid_favicon",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title="Favicon Detected",
                description=f"Favicon configured: {icon.get('href', '')}",
                location=str(icon)[:60],
                impact="Aids brand identity and visual tab discovery in browsers.",
                recommendation="Ensure Apple touch icons and dark-mode variants are supplied."
            ))

    # ---------------------------------------------------------
    # 2. HEADING STRUCTURE & HIERARCHY AUDIT
    # ---------------------------------------------------------
    def _audit_heading_structure(self) -> Tuple[Dict[str, int], List[HeadingNode]]:
        headings_raw = self.soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        counts = {f"h{i}": 0 for i in range(1, 7)}
        heading_nodes: List[HeadingNode] = []

        for h in headings_raw:
            tag_name = h.name.lower()
            counts[tag_name] += 1

        # Check H1 Existence
        if counts["h1"] == 0:
            self.issues.append(AuditIssue(
                id="missing_h1",
                category=IssueCategory.HEADINGS.value,
                severity=Severity.CRITICAL.value,
                title="Missing Main <h1> Heading",
                description="The page contains zero <h1> tags. Every primary web page must have exactly one <h1> identifying its core theme.",
                location=self.url,
                impact="Substantially degrades SEO ranking, semantic indexing, and accessibility for assistive screen readers.",
                recommendation="Insert a single semantic <h1> tag representing the central topic of this page.",
                code_fix="<h1>The Definitive Guide to Website Optimization</h1>"
            ))
        elif counts["h1"] > 1:
            self.issues.append(AuditIssue(
                id="multiple_h1",
                category=IssueCategory.HEADINGS.value,
                severity=Severity.WARNING.value,
                title=f"Multiple <h1> Headings Found ({counts['h1']} tags)",
                description=f"The page contains {counts['h1']} separate <h1> elements. Best practice for search engines and accessibility is a single distinct H1.",
                location=f"Detected {counts['h1']} tags",
                impact="Dilutes topical relevance and confuses screen reader document outlines.",
                recommendation="Retain the most prominent topic heading as <h1>, and demote secondary headers to <h2> or <h3>.",
                code_fix="<!-- Keep primary topic as H1 -->\n<h1>Primary Page Topic</h1>\n\n<!-- Convert secondary topics to H2 -->\n<h2>Secondary Section</h2>"
            ))
        else:
            self.issues.append(AuditIssue(
                id="single_h1_passed",
                category=IssueCategory.HEADINGS.value,
                severity=Severity.PASSED.value,
                title="Single Clear <h1> Heading Present",
                description="The page features exactly one primary <h1> tag, maintaining a clean hierarchical apex.",
                location="<h1>",
                impact="Maximizes topical clarity for search engine crawlers and screen readers.",
                recommendation="Ensure the H1 aligns with your target search intent."
            ))

        # Check Systematic Heading Level Skips (e.g. H1 -> H3, H2 -> H4)
        last_level = 0
        skipped_detected = False

        for h in headings_raw:
            tag_name = h.name.lower()
            current_level = int(tag_name[1])
            text = h.get_text(strip=True)
            node_issue = None
            is_valid = True

            # Empty heading check
            if not text:
                node_issue = "Empty heading text (no content)"
                is_valid = False
                self.issues.append(AuditIssue(
                    id="empty_heading",
                    category=IssueCategory.HEADINGS.value,
                    severity=Severity.WARNING.value,
                    title=f"Empty <{tag_name}> Heading Element",
                    description=f"An empty <{tag_name}> tag with no text was found in the document.",
                    location=f"<{tag_name}>...</{tag_name}>",
                    impact="Creates empty auditory pauses for screen readers and signals poor DOM markup hygiene.",
                    recommendation=f"Add descriptive text inside the <{tag_name}> tag or remove the empty element.",
                    code_fix=f"<{tag_name}>Meaningful Section Title</{tag_name}>"
                ))

            # Hierarchy step check: cannot skip levels downward (e.g. 1 -> 3, 2 -> 4)
            if last_level > 0 and current_level > last_level + 1:
                node_issue = f"Skipped heading level: jumped from <h{last_level}> directly to <h{current_level}>"
                is_valid = False
                skipped_detected = True
                self.issues.append(AuditIssue(
                    id=f"skipped_heading_h{last_level}_to_h{current_level}",
                    category=IssueCategory.HEADINGS.value,
                    severity=Severity.WARNING.value,
                    title=f"Skipped Heading Level: <h{last_level}> to <h{current_level}>",
                    description=f"The document jumped directly from <h{last_level}> to <h{current_level}> ('{text[:30]}...'), skipping level <h{last_level + 1}>.",
                    location=f"<{tag_name}>{text[:40]}</{tag_name}>",
                    impact="Breaks the visual and structural outline, confusing assistive technology navigation modes.",
                    recommendation=f"Restructure heading hierarchy so that <h{current_level}> is reclassified as <h{last_level + 1}>.",
                    code_fix=f"<!-- Instead of <h{current_level}>, use <h{last_level + 1}> -->\n<h{last_level + 1}>{text}</h{last_level + 1}>"
                ))
            
            # First heading isn't H1
            if last_level == 0 and current_level != 1:
                node_issue = f"Document begins with <{tag_name}> instead of <h1>"
                is_valid = False
                self.issues.append(AuditIssue(
                    id="first_heading_not_h1",
                    category=IssueCategory.HEADINGS.value,
                    severity=Severity.WARNING.value,
                    title=f"Document Starts With <{tag_name}> Instead of <h1>",
                    description=f"The first heading encountered is <{tag_name}> ('{text[:30]}'). An outline should begin at <h1>.",
                    location=f"<{tag_name}>{text[:40]}</{tag_name}>",
                    impact="Disrupts document hierarchy from the start.",
                    recommendation="Ensure the topmost heading of the page is an <h1> element.",
                    code_fix=f"<h1>{text}</h1>"
                ))

            heading_nodes.append(HeadingNode(
                level=current_level,
                tag=tag_name,
                text=text or "[Empty Heading]",
                is_valid=is_valid,
                issue=node_issue
            ))
            last_level = current_level

        if not skipped_detected and len(headings_raw) > 1 and counts["h1"] == 1:
            self.issues.append(AuditIssue(
                id="perfect_heading_hierarchy",
                category=IssueCategory.HEADINGS.value,
                severity=Severity.PASSED.value,
                title="Clean Hierarchical Heading Structure",
                description=f"All {len(headings_raw)} headings follow sequential progression without skipped levels.",
                location="Heading Tree",
                impact="Maximizes readability and semantic clarity across all search engines and screen readers.",
                recommendation="Continue maintaining this strict hierarchy."
            ))

        return counts, heading_nodes

    # ---------------------------------------------------------
    # 3. IMAGES & ACCESSIBILITY AUDIT
    # ---------------------------------------------------------
    def _audit_images(self) -> Tuple[int, List[Dict[str, str]]]:
        images = self.soup.find_all("img")
        missing_alt = []

        for idx, img in enumerate(images):
            src = img.get("src", "").strip() or "[inline / missing src]"
            alt = img.get("alt")

            if alt is None:
                missing_alt.append({
                    "src": src,
                    "reason": "Attribute 'alt' is completely missing",
                    "snippet": str(img)[:80]
                })
            elif alt.strip() == "":
                # Empty alt is valid for decorative images ONLY if role="presentation" or aria-hidden="true"
                role = img.get("role", "")
                aria_hidden = img.get("aria-hidden", "")
                if role != "presentation" and aria_hidden != "true":
                    missing_alt.append({
                        "src": src,
                        "reason": "Empty alt attribute on potentially informative image",
                        "snippet": str(img)[:80]
                    })

        total = len(images)
        if missing_alt:
            self.issues.append(AuditIssue(
                id="missing_image_alts",
                category=IssueCategory.IMAGES.value,
                severity=Severity.WARNING.value,
                title=f"{len(missing_alt)} Image(s) Missing 'alt' Attributes",
                description=f"{len(missing_alt)} of {total} images lack descriptive alternative text for search engines and visually impaired users.",
                location=f"{len(missing_alt)} images detected",
                impact="Penalizes Google Image Search visibility and triggers WCAG accessibility non-compliance.",
                recommendation="Add descriptive, keyword-relevant alt text to informative images or role='presentation' for decorative elements.",
                code_fix="<img src=\"chart.png\" alt=\"Quarterly performance growth chart with 25% revenue increase\">"
            ))
        elif total > 0:
            self.issues.append(AuditIssue(
                id="all_images_have_alt",
                category=IssueCategory.IMAGES.value,
                severity=Severity.PASSED.value,
                title="All Images Contain 'alt' Attributes",
                description=f"All {total} images on the page have alternative text properly specified.",
                location="<img> elements",
                impact="Ensures full WCAG 2.1 accessibility and empowers Google Image Search indexing.",
                recommendation="Audit alt text periodically to ensure descriptions remain current and accurate."
            ))

        return total, missing_alt

    # ---------------------------------------------------------
    # 4. STRUCTURAL HTML & SEMANTICS
    # ---------------------------------------------------------
    def _audit_semantics_and_deprecated(self) -> None:
        # Check semantic HTML5 landmarks
        landmarks = {
            "main": self.soup.find("main"),
            "header": self.soup.find("header"),
            "footer": self.soup.find("footer"),
            "nav": self.soup.find("nav")
        }

        missing_landmarks = [name for name, node in landmarks.items() if node is None]
        if "main" in missing_landmarks:
            self.issues.append(AuditIssue(
                id="missing_main_tag",
                category=IssueCategory.STRUCTURE.value,
                severity=Severity.WARNING.value,
                title="Missing Semantic <main> Landmark",
                description="The page lacks a <main> container element. Semantic landmarks allow accessibility clients to navigate directly to primary content.",
                location="<body>",
                impact="Screen readers cannot jump directly to the primary page content.",
                recommendation="Enclose primary page content in a single <main> element.",
                code_fix="<body>\n  <header>...</header>\n  <main>\n    <h1>Main Article</h1>\n  </main>\n  <footer>...</footer>\n</body>"
            ))
        else:
            self.issues.append(AuditIssue(
                id="semantic_main_present",
                category=IssueCategory.STRUCTURE.value,
                severity=Severity.PASSED.value,
                title="Semantic <main> Landmark Present",
                description="Primary content is enclosed within a standard <main> element.",
                location="<main>",
                impact="Enables screen reader users to skip repeated navigation blocks.",
                recommendation="Ensure non-main content (headers, footers, sidebars) remains outside <main>."
            ))

        # Check deprecated HTML tags
        found_deprecated = []
        for tag_name in self.DEPRECATED_TAGS:
            bad_tags = self.soup.find_all(tag_name)
            if bad_tags:
                found_deprecated.append((tag_name, len(bad_tags)))

        if found_deprecated:
            tags_str = ", ".join([f"<{t}> ({count}x)" for t, count in found_deprecated])
            self.issues.append(AuditIssue(
                id="deprecated_html_tags",
                category=IssueCategory.STRUCTURE.value,
                severity=Severity.WARNING.value,
                title=f"Deprecated HTML Elements Detected: {tags_str}",
                description=f"Found obsolete HTML tags ({tags_str}) that are deprecated in HTML5.",
                location="DOM Tree",
                impact="Increases page rendering quirks and signals outdated web engineering practices.",
                recommendation="Replace deprecated tags with modern CSS layout rules (Flexbox/Grid).",
                code_fix="/* Replace <center> or <font> with modern CSS */\n.container {\n  display: flex;\n  justify-content: center;\n  font-family: inherit;\n}"
            ))

    # ---------------------------------------------------------
    # 5. SECURITY & TRANSPORT
    # ---------------------------------------------------------
    def _audit_security_and_transport(self) -> bool:
        is_https = self.parsed_url.scheme.lower() == "https"
        if not is_https and not self.parsed_url.netloc.startswith("localhost") and not self.parsed_url.netloc.startswith("127.0.0.1"):
            self.issues.append(AuditIssue(
                id="insecure_http",
                category=IssueCategory.SECURITY.value,
                severity=Severity.CRITICAL.value,
                title="Insecure HTTP Protocol (Missing SSL/TLS)",
                description=f"Page is loaded via unencrypted 'http://'. Google Chrome flags HTTP sites as 'Not Secure'.",
                location=self.url,
                impact="Major negative ranking signal for Google search, and risks man-in-the-middle data interception.",
                recommendation="Install an SSL/TLS certificate and enforce automatic 301 redirects from HTTP to HTTPS.",
                code_fix="# NGINX Redirect Example:\nserver {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}"
            ))
        else:
            self.issues.append(AuditIssue(
                id="https_secure",
                category=IssueCategory.SECURITY.value,
                severity=Severity.PASSED.value,
                title="Secure HTTPS Protocol Active",
                description="Page is served over encrypted SSL/TLS connection (or local test host).",
                location=self.url,
                impact="Guarantees transport encryption and satisfies Google's core HTTPS ranking signal.",
                recommendation="Ensure HSTS (Strict-Transport-Security) header is active."
            ))

        # Check Security Headers if available
        sec_headers = {
            "strict-transport-security": "HSTS (Strict-Transport-Security)",
            "x-content-type-options": "X-Content-Type-Options: nosniff",
            "x-frame-options": "X-Frame-Options (Clickjacking defense)"
        }
        missing_sec = [name for key, name in sec_headers.items() if key not in self.headers]
        if missing_sec and is_https:
            self.issues.append(AuditIssue(
                id="missing_security_headers",
                category=IssueCategory.SECURITY.value,
                severity=Severity.NOTICE.value,
                title=f"Missing Recommended Security Headers",
                description=f"HTTP response lacks: {', '.join(missing_sec)}.",
                location="HTTP Response Headers",
                impact="Leaves client vulnerable to MIME sniffing, iframe clickjacking, or downgrade attacks.",
                recommendation="Configure your web server (Nginx/Cloudflare) to send standard HTTP security headers.",
                code_fix="Strict-Transport-Security: max-age=31536000; includeSubDomains\nX-Content-Type-Options: nosniff\nX-Frame-Options: SAMEORIGIN"
            ))

        return is_https

    # ---------------------------------------------------------
    # 6. CONTENT METRICS & READABILITY
    # ---------------------------------------------------------
    def _compute_content_metrics(self) -> Tuple[int, float]:
        # Extract meaningful text from body without scripts/styles
        for s in self.soup(["script", "style", "noscript", "svg"]):
            s.decompose()

        text = self.soup.get_text(separator=" ", strip=True)
        words = re.findall(r"\b\w+\b", text)
        word_count = len(words)
        reading_time_mins = round(word_count / 200.0, 1) if word_count > 0 else 0.0

        if word_count < 150:
            self.issues.append(AuditIssue(
                id="thin_content",
                category=IssueCategory.PERFORMANCE.value,
                severity=Severity.WARNING.value,
                title=f"Thin Content Detected ({word_count} words)",
                description=f"The page has only {word_count} words of visible content. Search engines may flag this as thin/low-value content.",
                location=self.url,
                impact="High risk of being ignored or soft-404 classified by search engines.",
                recommendation="Expand valuable textual copy with in-depth analysis, FAQs, and topical coverage.",
                code_fix="<!-- Provide authoritative, original content covering user search intent -->"
            ))
        else:
            self.issues.append(AuditIssue(
                id="healthy_content_length",
                category=IssueCategory.PERFORMANCE.value,
                severity=Severity.PASSED.value,
                title=f"Substantial Content Density ({word_count} words)",
                description=f"The page features {word_count} words (~{reading_time_mins} min read), indicating deep topical substance.",
                location=self.url,
                impact="Boosts semantic keyword relevance and improves dwell time.",
                recommendation="Maintain readability with bulleted lists and concise subheadings."
            ))

        return word_count, reading_time_mins
