import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
from .models import SiteAuditReport, Severity, IssueCategory


class AuditReporter:
    """
    Computes weighted health scores, generates executive summaries,
    and produces exportable Markdown and JSON audit reports.
    """

    @staticmethod
    def calculate_scores(issues: List[Dict[str, Any]], pages_count: int, broken_links_count: int) -> Tuple[int, str, Dict[str, int], Dict[str, int]]:
        """
        Calculates overall score, letter grade, and category breakdown.
        """
        # Count issues by severity
        severity_counts = {
            Severity.CRITICAL.value: 0,
            Severity.WARNING.value: 0,
            Severity.NOTICE.value: 0,
            Severity.PASSED.value: 0,
        }

        category_issue_counts = {cat.value: 0 for cat in IssueCategory}

        # Deductions
        critical_deductions = 0
        warning_deductions = 0
        notice_deductions = 0

        # Category deductions mapping
        cat_penalties = {cat.value: 0 for cat in IssueCategory}

        for issue in issues:
            sev = issue.get("severity", Severity.NOTICE.value)
            cat = issue.get("category", IssueCategory.META.value)

            if sev in severity_counts:
                severity_counts[sev] += 1
            if cat in category_issue_counts:
                category_issue_counts[cat] += 1

            if sev == Severity.CRITICAL.value:
                critical_deductions += 12
                cat_penalties[cat] = cat_penalties.get(cat, 0) + 20
            elif sev == Severity.WARNING.value:
                warning_deductions += 4
                cat_penalties[cat] = cat_penalties.get(cat, 0) + 8
            elif sev == Severity.NOTICE.value:
                notice_deductions += 1
                cat_penalties[cat] = cat_penalties.get(cat, 0) + 2

        # Scale deductions if multi-page to avoid 0 scores on massive crawls
        page_scale_factor = max(1.0, pages_count * 0.7)
        total_deduction = (critical_deductions * 1.2 + warning_deductions * 0.9 + notice_deductions * 0.5) / page_scale_factor

        # Overall health score (0-100)
        health_score = max(5, min(100, int(round(100 - total_deduction))))

        # If there are broken links or missing titles, cap at 85
        if broken_links_count > 0 and health_score > 85:
            health_score = 85

        # Letter grade
        if health_score >= 95:
            grade = "A+"
        elif health_score >= 88:
            grade = "A"
        elif health_score >= 75:
            grade = "B"
        elif health_score >= 60:
            grade = "C"
        elif health_score >= 45:
            grade = "D"
        else:
            grade = "F"

        # Category Scores
        category_scores = {}
        for cat in IssueCategory:
            c_val = cat.value
            penalty = cat_penalties.get(c_val, 0) / page_scale_factor
            c_score = max(10, min(100, int(round(100 - penalty * 1.5))))
            category_scores[c_val] = c_score

        return health_score, grade, category_scores, severity_counts

    @staticmethod
    def generate_markdown(report: SiteAuditReport) -> str:
        """Constructs an in-depth, structured Markdown audit document."""
        data = report.to_dict()
        md = []
        md.append(f"# Website Comprehensive Audit Report")
        md.append(f"**Target Host**: `{data['root_url']}`  ")
        md.append(f"**Generated**: {data['timestamp']}  ")
        md.append(f"**Audit Health Score**: **{data['health_score']}/100** (Grade: **{data['grade']}**)  ")
        md.append(f"**Crawl Duration**: {data['duration_seconds']}s  \n")

        md.append("---")
        md.append("## 1. Executive Summary")
        md.append(f"| Metric | Result |")
        md.append(f"|---|---|")
        md.append(f"| **Pages Crawled** | {data['pages_crawled']} |")
        md.append(f"| **Total Links Tested** | {data['total_links_checked']} |")
        md.append(f"| **Broken Links Detected** | {data['broken_links_count']} |")
        md.append(f"| **Critical Issues** | {data['severity_counts'].get('critical', 0)} |")
        md.append(f"| **Warnings** | {data['severity_counts'].get('warning', 0)} |")
        md.append(f"| **Notices** | {data['severity_counts'].get('notice', 0)} |")
        md.append(f"| **Passed Checks** | {data['severity_counts'].get('passed', 0)} |\n")

        md.append("### Category Health Breakdown")
        for cat, score in data.get("category_scores", {}).items():
            status = "🟢 Excellent" if score >= 85 else ("🟡 Fair" if score >= 65 else "🔴 Needs Attention")
            md.append(f"- **{cat.capitalize()}**: `{score}/100` — {status}")
        md.append("")

        # Broken Links Section
        md.append("---")
        md.append("## 2. Broken Links & Dead Anchors Analysis")
        broken = data.get("broken_links", [])
        if not broken:
            md.append("✅ **No broken hyperlinks or dead anchors were found during this audit.**\n")
        else:
            md.append(f"🚨 Found **{len(broken)} broken link(s)** that need immediate remediation:\n")
            md.append("| Target URL | Anchor Text | Source Page | Status / Error |")
            md.append("|---|---|---|---|")
            for b in broken:
                md.append(f"| `{b.get('url')}` | \"{b.get('anchor_text')}\" | `{b.get('source_url')}` | `{b.get('status_code') or b.get('error_message')}` |")
            md.append("")

        # Systematic Issues Breakdown
        md.append("---")
        md.append("## 3. Systematic Debugger & Issue Remediation")
        issues = data.get("issues", [])
        
        # Group by severity
        for sev in ["critical", "warning", "notice"]:
            sev_issues = [i for i in issues if i.get("severity") == sev]
            if not sev_issues:
                continue
            icon = "🚨" if sev == "critical" else ("⚠️" if sev == "warning" else "💡")
            md.append(f"### {icon} {sev.upper()} Issues ({len(sev_issues)})")
            
            for item in sev_issues:
                md.append(f"#### {item.get('title')}")
                md.append(f"- **Category**: `{item.get('category')}`")
                md.append(f"- **Location**: `{item.get('location')}`")
                md.append(f"- **Description**: {item.get('description')}")
                md.append(f"- **SEO & Architectural Impact**: {item.get('impact')}")
                md.append(f"- **Systematic Fix Recipe**: {item.get('recommendation')}")
                if item.get("code_fix"):
                    md.append(f"```html\n{item.get('code_fix')}\n```")
                md.append("")

        # Page Breakdown
        md.append("---")
        md.append("## 4. Crawled Pages Inventory")
        pages = data.get("pages", [])
        for p in pages:
            md.append(f"### Page: `{p.get('url')}`")
            md.append(f"- **Status**: `{p.get('status_code')}` | **Latency**: `{p.get('response_time_ms')}ms` | **Words**: `{p.get('word_count')}`")
            md.append(f"- **Title**: {p.get('title') or '_Missing_'}")
            md.append(f"- **Description**: {p.get('description') or '_Missing_'}")
            md.append(f"- **Headings Count**: {p.get('heading_counts')}")
            
            tree = p.get("headings_tree", [])
            if tree:
                md.append(f"- **Heading Hierarchy Outline**:")
                for h in tree[:12]:
                    indent = "  " * (h.get("level", 1) - 1)
                    flag = "❌ [SKIPPED/EMPTY]" if not h.get("is_valid") else "✓"
                    md.append(f"  {indent}- `{h.get('tag').upper()}`: {h.get('text')} {flag}")
            md.append("")

        md.append("---\n*Audit compiled autonomously by Website Auditing Tool Engine.*")
        return "\n".join(md)
