from auditor.parser import HTMLPageAuditor
from auditor.link_checker import ConcurrentLinkChecker
from auditor.reporter import AuditReporter

# Test HTML with intentional flaws:
# 1. Missing meta description
# 2. Short title (<30 chars)
# 3. Skipped heading level (H1 -> H3)
# 4. Images missing alt
# 5. Deprecated <center>
# 6. Dead anchor link (#faq-anchor)
SAMPLE_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Short Title</title>
</head>
<body>
  <h1>Main Product</h1>
  <h3>Skipped to H3 directly</h3>
  <img src="banner.jpg">
  <center><p>Old centered text</p></center>
  <a href="#missing-faq">Dead Anchor</a>
  <a href="https://example.com/services">Valid Link</a>
</body>
</html>
"""

def test_engine():
    print("Testing HTMLPageAuditor...")
    auditor = HTMLPageAuditor("https://test.local", SAMPLE_HTML)
    res = auditor.audit()

    print(f"Page title: {res.title} ({res.title_length} chars)")
    print(f"Word count: {res.word_count}")
    print(f"Issues detected: {len(res.issues)}")
    
    # Check issue IDs
    issue_ids = [i["id"] for i in res.issues]
    print(f"Issue IDs: {issue_ids}")

    assert "short_title" in issue_ids, "Should detect short title"
    assert "missing_meta_description" in issue_ids, "Should detect missing meta description"
    assert "missing_viewport" in issue_ids, "Should detect missing viewport"
    assert "skipped_heading_h1_to_h3" in issue_ids, "Should detect skipped heading level"
    assert "missing_image_alts" in issue_ids, "Should detect missing image alts"
    assert "deprecated_html_tags" in issue_ids, "Should detect deprecated html tags"
    print("[OK] All structural & SEO parser checks PASSED!")

    print("\nTesting ConcurrentLinkChecker dead anchor detection...")
    checker = ConcurrentLinkChecker()
    extracted = checker.extract_links_from_html("https://test.local", SAMPLE_HTML)
    assert len(extracted) == 2, f"Expected 2 links, got {len(extracted)}"
    
    results, link_issues = checker.check_all_links(extracted, check_external=False)
    broken = [r for r in results if r.is_broken]
    assert len(broken) == 1, f"Expected 1 broken link (dead anchor), got {len(broken)}"
    assert "#missing-faq" in broken[0].url
    print(f"[OK] Dead anchor successfully caught: {broken[0].error_message}")

    print("\nTesting Score & Markdown Generation...")
    all_issues = res.issues + [i.to_dict() for i in link_issues]
    score, grade, cat_scores, sev_counts = AuditReporter.calculate_scores(all_issues, 1, len(broken))
    print(f"[OK] Health Score calculated: {score}/100 (Grade: {grade})")
    print(f"[OK] Category Scores: {cat_scores}")
    print(f"[OK] Severity Counts: {sev_counts}")
    assert score < 85, "Should penalize for critical & warning flaws"
    print("ALL TESTS PASSED WITH 100% SUCCESS!")

if __name__ == "__main__":
    test_engine()
