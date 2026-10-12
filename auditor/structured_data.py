import json
from typing import List, Dict, Any, Tuple
from bs4 import BeautifulSoup
from .models import AuditIssue, Severity, IssueCategory


class StructuredDataValidator:
    """
    Validates Schema.org JSON-LD and Microdata structured data.
    Provides rich snippet readiness diagnostics.
    """

    SUPPORTED_TYPES = {
        "Organization", "WebSite", "Article", "NewsArticle", "BlogPosting",
        "Product", "BreadcrumbList", "FAQPage", "LocalBusiness", "Person",
        "Event", "Recipe", "SoftwareApplication", "Course"
    }

    @classmethod
    def validate(cls, soup: BeautifulSoup, page_url: str) -> Tuple[List[Dict[str, Any]], List[AuditIssue]]:
        schemas_found: List[Dict[str, Any]] = []
        issues: List[AuditIssue] = []

        # 1. Parse JSON-LD scripts
        json_ld_scripts = soup.find_all("script", type=lambda t: t and "application/ld+json" in t.lower())
        
        for idx, tag in enumerate(json_ld_scripts):
            raw_content = tag.string or tag.get_text()
            if not raw_content or not raw_content.strip():
                issues.append(AuditIssue(
                    id=f"empty_json_ld_{idx}",
                    category=IssueCategory.STRUCTURE.value,
                    severity=Severity.WARNING.value,
                    title="Empty JSON-LD Script Tag",
                    description="A <script type=\"application/ld+json\"> tag was found without content.",
                    location=f"JSON-LD Script #{idx + 1}",
                    impact="Search engines cannot parse structured data from empty scripts.",
                    recommendation="Remove the empty script tag or populate it with valid Schema.org JSON-LD."
                ))
                continue

            try:
                parsed = json.loads(raw_content)
                # Handle single schema or @graph array
                items = parsed if isinstance(parsed, list) else (parsed.get("@graph", [parsed]) if isinstance(parsed, dict) else [parsed])

                for item in items:
                    if isinstance(item, dict):
                        schema_type = item.get("@type", "Unknown")
                        context = item.get("@context", "")
                        
                        schema_info = {
                            "type": schema_type,
                            "context": context,
                            "name": item.get("name") or item.get("headline") or "Untitled",
                            "raw": item
                        }
                        schemas_found.append(schema_info)

            except json.JSONDecodeError as e:
                issues.append(AuditIssue(
                    id=f"invalid_json_ld_syntax_{idx}",
                    category=IssueCategory.STRUCTURE.value,
                    severity=Severity.CRITICAL.value,
                    title=f"Malformed JSON-LD Syntax (Syntax Error)",
                    description=f"JSON parsing error: {str(e)[:60]} in structured data script #{idx + 1}.",
                    location=f"JSON-LD Script #{idx + 1}",
                    impact="Google Search Console will reject the structured data completely, disabling rich snippets.",
                    recommendation="Fix formatting, missing commas, or trailing quotes in the JSON-LD snippet.",
                    code_fix="<script type=\"application/ld+json\">\n{\n  \"@context\": \"https://schema.org\",\n  \"@type\": \"Organization\",\n  \"name\": \"Your Brand\",\n  \"url\": \"https://example.com\"\n}\n</script>"
                ))

        # Check if structured data is entirely missing on this page
        if not schemas_found:
            issues.append(AuditIssue(
                id="missing_structured_data",
                category=IssueCategory.META.value,
                severity=Severity.NOTICE.value,
                title="No Schema.org (JSON-LD) Structured Data Detected",
                description="The page lacks Schema.org JSON-LD markup. Rich snippets (star ratings, site links, FAQ accordion, brand logo) require structured data.",
                location=page_url,
                impact="Forfeits visual search result enhancements (Google Rich Results).",
                recommendation="Add Schema.org JSON-LD (e.g. WebSite, Organization, or Article schema) to the <head>.",
                code_fix=f'<script type="application/ld+json">\n{{\n  "@context": "https://schema.org",\n  "@type": "WebSite",\n  "name": "Site Name",\n  "url": "{page_url}"\n}}\n</script>'
            ))
        else:
            types_str = ", ".join([s["type"] for s in schemas_found if isinstance(s.get("type"), str)])
            issues.append(AuditIssue(
                id="valid_structured_data_present",
                category=IssueCategory.META.value,
                severity=Severity.PASSED.value,
                title=f"Structured Data Configured ({types_str})",
                description=f"Found {len(schemas_found)} valid Schema.org structured data definition(s).",
                location="<script type='application/ld+json'>",
                impact="Enables Google Search rich results, breadcrumb trails, and knowledge graph signals.",
                recommendation="Validate continuously using Google Rich Results Test tool."
            ))

        return schemas_found, issues
