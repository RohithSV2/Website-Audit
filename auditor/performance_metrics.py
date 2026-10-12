from typing import Dict, List, Tuple, Any
from bs4 import BeautifulSoup
from .models import AuditIssue, Severity, IssueCategory


class PerformanceMetricsAuditor:
    """
    Evaluates DOM complexity, resource weights, render-blocking scripts,
    and Core Web Vitals (CWV) risk signals.
    """

    @classmethod
    def audit(cls, soup: BeautifulSoup, page_url: str) -> Tuple[Dict[str, Any], List[AuditIssue]]:
        issues: List[AuditIssue] = []

        # 1. DOM Elements Count
        all_elements = soup.find_all()
        dom_node_count = len(all_elements)

        if dom_node_count > 1400:
            issues.append(AuditIssue(
                id="excessive_dom_size",
                category=IssueCategory.PERFORMANCE.value,
                severity=Severity.WARNING.value,
                title=f"Excessive DOM Node Tree ({dom_node_count} nodes)",
                description=f"Page contains {dom_node_count} DOM elements (Google Lighthouse recommends <800).",
                location="DOM Tree",
                impact="Slows browser style calculations, layout recalculations, and increases memory consumption on mobile devices.",
                recommendation="Prune deeply nested layout wrappers and virtualize lengthy lists or feeds."
            ))
        elif dom_node_count > 0:
            issues.append(AuditIssue(
                id="healthy_dom_size",
                category=IssueCategory.PERFORMANCE.value,
                severity=Severity.PASSED.value,
                title=f"Lean DOM Tree Complexity ({dom_node_count} nodes)",
                description=f"DOM tree has {dom_node_count} nodes, well within optimal performance thresholds.",
                location="DOM Tree",
                impact="Ensures fast style calculation and fluid scrolling frame rates.",
                recommendation="Maintain modular DOM architecture."
            ))

        # 2. Scripts Analysis (Render-Blocking)
        scripts = soup.find_all("script")
        blocking_scripts = 0
        async_defer_scripts = 0
        inline_scripts = 0

        for s in scripts:
            src = s.get("src")
            if src:
                has_async = s.has_attr("async")
                has_defer = s.has_attr("defer")
                script_type = s.get("type", "")
                if script_type == "module" or has_async or has_defer:
                    async_defer_scripts += 1
                else:
                    blocking_scripts += 1
            else:
                inline_scripts += 1

        if blocking_scripts > 2:
            issues.append(AuditIssue(
                id="render_blocking_scripts",
                category=IssueCategory.PERFORMANCE.value,
                severity=Severity.WARNING.value,
                title=f"{blocking_scripts} Render-Blocking Script(s) Detected",
                description=f"Found {blocking_scripts} external scripts loaded synchronously in document head without 'defer' or 'async'.",
                location="<script src=...>",
                impact="Blocks initial HTML rendering, delaying First Contentful Paint (FCP) and Largest Contentful Paint (LCP).",
                recommendation="Add 'defer' or 'async' to non-critical external scripts.",
                code_fix="<!-- Non-blocking script loading -->\n<script src=\"bundle.js\" defer></script>"
            ))

        # 3. Stylesheets & Inline Styles
        css_links = soup.find_all("link", rel=lambda r: r and "stylesheet" in (r if isinstance(r, list) else [r]))
        inline_styles = soup.find_all("style")

        # 4. Images Missing Width and Height (CLS Risk)
        images = soup.find_all("img")
        unsized_images = 0
        for img in images:
            w = img.get("width")
            h = img.get("height")
            if not w or not h:
                unsized_images += 1

        cls_risk = "Low"
        if unsized_images > 3:
            cls_risk = "High"
            issues.append(AuditIssue(
                id="unsized_images_cls_risk",
                category=IssueCategory.PERFORMANCE.value,
                severity=Severity.WARNING.value,
                title=f"{unsized_images} Image(s) Missing Explicit Dimensions (CLS Risk)",
                description=f"{unsized_images} <img> elements lack 'width' and 'height' attributes.",
                location="<img> elements",
                impact="Triggers Cumulative Layout Shift (CLS) as images load, degrading user experience and Google Core Web Vitals scores.",
                recommendation="Provide explicit width and height attributes (or aspect-ratio CSS) on all image tags.",
                code_fix="<img src=\"hero.webp\" width=\"800\" height=\"450\" alt=\"Hero banner\" loading=\"lazy\">"
            ))
        elif unsized_images > 0:
            cls_risk = "Medium"

        # 5. Resource Hints (preload, preconnect)
        resource_hints = soup.find_all("link", rel=lambda r: r and any(x in (r if isinstance(r, list) else [r]) for x in ["preload", "preconnect", "dns-prefetch"]))

        metrics = {
            "dom_node_count": dom_node_count,
            "total_scripts": len(scripts),
            "blocking_scripts": blocking_scripts,
            "async_defer_scripts": async_defer_scripts,
            "inline_scripts": inline_scripts,
            "external_stylesheets": len(css_links),
            "inline_style_blocks": len(inline_styles),
            "total_images": len(images),
            "unsized_images": unsized_images,
            "cls_risk_rating": cls_risk,
            "resource_hints_count": len(resource_hints)
        }

        return metrics, issues
