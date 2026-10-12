/**
 * VECTRA AUDIT ENGINE — PRO CLIENT-SIDE CONTROLLER
 * Real-time SSE streaming, SVG score dial animations,
 * systematic debugger filters, SERP/Social simulators,
 * security header diagnostics, CWV telemetry, and SQLite history drawer.
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const auditForm = document.getElementById("audit-form");
  const targetUrlInput = document.getElementById("target-url");
  const maxPagesSelect = document.getElementById("max-pages-select");
  const maxDepthSelect = document.getElementById("max-depth-select");
  const checkExternalToggle = document.getElementById("check-external-toggle");
  const submitBtn = document.getElementById("submit-btn");
  const tryDemoBtn = document.getElementById("try-demo-btn");

  // History Drawer Elements
  const historyToggleBtn = document.getElementById("history-toggle-btn");
  const closeHistoryBtn = document.getElementById("close-history-btn");
  const historyBackdrop = document.getElementById("history-backdrop");
  const historyDrawer = document.getElementById("history-drawer");
  const historyListContainer = document.getElementById("history-list-container");
  const historyCountBadge = document.getElementById("history-count-badge");

  // Telemetry Panel
  const telemetryPanel = document.getElementById("telemetry-panel");
  const telemetryTargetUrl = document.getElementById("telemetry-target-url");
  const telemetryPhase = document.getElementById("telemetry-phase");
  const telemetryProgressFill = document.getElementById("telemetry-progress-fill");
  const statPages = document.getElementById("stat-pages");
  const statQueue = document.getElementById("stat-queue");
  const statLinks = document.getElementById("stat-links");
  const statTimer = document.getElementById("stat-timer");
  const terminalLogs = document.getElementById("terminal-logs");

  // Results Panel
  const resultsPanel = document.getElementById("results-panel");
  const scoreCircle = document.getElementById("score-circle");
  const reportScore = document.getElementById("report-score");
  const reportGrade = document.getElementById("report-grade");
  const reportDomain = document.getElementById("report-domain");
  const reportTimestamp = document.getElementById("report-timestamp");
  const reportPagesBadge = document.getElementById("report-pages-badge");
  const reportLinksBadge = document.getElementById("report-links-badge");
  const reportDurationBadge = document.getElementById("report-duration-badge");
  const reportSecBadge = document.getElementById("report-sec-badge");

  // Counts & Tallies
  const countCritical = document.getElementById("count-critical");
  const countWarning = document.getElementById("count-warning");
  const countNotice = document.getElementById("count-notice");
  const countPassed = document.getElementById("count-passed");
  const tabIssuesCount = document.getElementById("tab-issues-count");
  const tabBrokenCount = document.getElementById("tab-broken-count");
  const tabPagesCount = document.getElementById("tab-pages-count");

  // Category Breakdown
  const categoryBarsContainer = document.getElementById("category-bars-container");

  // Tabs & Filters
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const filterPills = document.querySelectorAll(".filter-pill");
  const categorySelect = document.getElementById("issue-category-select");
  const issuesListContainer = document.getElementById("issues-list-container");

  // SERP Previews
  const serpPageSelect = document.getElementById("serp-page-select");
  const serpMockUrl = document.getElementById("serp-mock-url");
  const serpMockTitle = document.getElementById("serp-mock-title");
  const serpMockDesc = document.getElementById("serp-mock-desc");
  const serpMockStatus = document.getElementById("serp-mock-status");
  const twitterMockImageWrap = document.getElementById("twitter-mock-image-wrap");
  const twitterMockDomain = document.getElementById("twitter-mock-domain");
  const twitterMockTitle = document.getElementById("twitter-mock-title");
  const twitterMockDesc = document.getElementById("twitter-mock-desc");

  // Security Panel
  const secOverallGrade = document.getElementById("sec-overall-grade");
  const secOverallScore = document.getElementById("sec-overall-score");
  const securityHeadersTableBody = document.getElementById("security-headers-table-body");

  // CWV Panel
  const cwvMetricsContainer = document.getElementById("cwv-metrics-container");

  // Heading Tree & Links & Pages
  const treePageSelect = document.getElementById("tree-page-select");
  const headingTreeDisplay = document.getElementById("heading-tree-display");
  const linksTableBody = document.getElementById("links-table-body");
  const brokenOnlyToggle = document.getElementById("broken-only-toggle");
  const pagesGridContainer = document.getElementById("pages-grid-container");

  // Export Buttons
  const downloadMdBtn = document.getElementById("download-md-btn");
  const downloadJsonBtn = document.getElementById("download-json-btn");
  const printReportBtn = document.getElementById("print-report-btn");

  // State
  let currentJobId = null;
  let activeEventSource = null;
  let currentReportData = null;
  let timerInterval = null;
  let startTime = 0;
  let activeSeverityFilter = "all";
  let activeCategoryFilter = "all";

  // Initial load: fetch history count
  fetchHistoryList(false);

  // -------------------------------------------------------------
  // History Drawer Controls
  // -------------------------------------------------------------
  historyToggleBtn.addEventListener("click", () => {
    fetchHistoryList(true);
    historyDrawer.classList.remove("hidden");
    historyBackdrop.classList.remove("hidden");
  });

  closeHistoryBtn.addEventListener("click", closeDrawer);
  historyBackdrop.addEventListener("click", closeDrawer);

  function closeDrawer() {
    historyDrawer.classList.add("hidden");
    historyBackdrop.classList.add("hidden");
  }

  async function fetchHistoryList(renderOpen = false) {
    try {
      const res = await fetch("/api/history?limit=30");
      if (!res.ok) return;
      const historyItems = await res.json();
      historyCountBadge.textContent = historyItems.length;

      if (renderOpen) {
        renderHistoryList(historyItems);
      }
    } catch (e) {
      console.warn("Could not load history:", e);
    }
  }

  function renderHistoryList(items) {
    historyListContainer.innerHTML = "";
    if (!items || items.length === 0) {
      historyListContainer.innerHTML = `
        <div style="padding: 30px; text-align: center; color: var(--text-muted); font-family: var(--font-mono);">
          No saved audits yet. Run your first audit to populate history!
        </div>
      `;
      return;
    }

    items.forEach(item => {
      const card = document.createElement("div");
      card.className = "history-item-card";

      const scoreColor = item.health_score >= 85 ? "var(--accent-lichen)" : (item.health_score >= 65 ? "var(--sev-warning)" : "var(--sev-critical)");

      card.innerHTML = `
        <div class="history-item-top">
          <span class="history-url">${escapeHtml(item.root_url)}</span>
          <span class="history-score-badge" style="background: ${scoreColor}22; color: ${scoreColor}; border: 1px solid ${scoreColor}55;">
            ${item.health_score}/100 (${item.grade})
          </span>
        </div>
        <div class="history-item-meta">
          <span>${escapeHtml(item.timestamp)}</span>
          <span>${item.pages_crawled} page(s) | ${item.broken_links_count} dead links</span>
        </div>
        <div class="history-actions">
          <button class="history-btn-sm history-btn-load" data-id="${item.id}">⚡ Load Report</button>
          <button class="history-btn-sm history-btn-del" data-id="${item.id}">🗑 Delete</button>
        </div>
      `;
      historyListContainer.appendChild(card);
    });

    // Add action handlers
    historyListContainer.querySelectorAll(".history-btn-load").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-id");
        loadHistoricalAudit(id);
        closeDrawer();
      });
    });

    historyListContainer.querySelectorAll(".history-btn-del").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        if (confirm("Delete this saved audit record?")) {
          await fetch(`/api/history/${id}`, { method: "DELETE" });
          fetchHistoryList(true);
          showToast("Audit record deleted", "info");
        }
      });
    });
  }

  async function loadHistoricalAudit(id) {
    try {
      showToast("Loading saved audit...", "info");
      const res = await fetch(`/api/history/${id}`);
      if (!res.ok) throw new Error("Could not load report");
      const report = await res.json();
      currentJobId = report.id || id;
      currentReportData = report;
      renderDashboard(report);

      telemetryPanel.classList.add("hidden");
      resultsPanel.classList.remove("hidden");
      resultsPanel.scrollIntoView({ behavior: "smooth" });
      showToast("Historical Audit Loaded!", "success");
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  // -------------------------------------------------------------
  // Quick Sandbox Preset
  // -------------------------------------------------------------
  tryDemoBtn.addEventListener("click", () => {
    const demoUrl = window.location.origin + "/demo-target";
    targetUrlInput.value = demoUrl;
    maxPagesSelect.value = "5";
    maxDepthSelect.value = "2";
    checkExternalToggle.checked = true;
    showToast("Loaded built-in flawed test sandbox!", "info");
    startAuditFlow(demoUrl, 2, 5, true);
  });

  // -------------------------------------------------------------
  // Audit Form Submission
  // -------------------------------------------------------------
  auditForm.addEventListener("submit", (e) => {
    e.preventDefault();
    let url = targetUrlInput.value.trim();
    if (!url) return;

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
      targetUrlInput.value = url;
    }

    const depth = parseInt(maxDepthSelect.value, 10);
    const maxPages = parseInt(maxPagesSelect.value, 10);
    const checkExt = checkExternalToggle.checked;

    startAuditFlow(url, depth, maxPages, checkExt);
  });

  // -------------------------------------------------------------
  // Audit Execution & Real-Time SSE Stream
  // -------------------------------------------------------------
  async function startAuditFlow(url, depth, maxPages, checkExternal) {
    if (activeEventSource) {
      activeEventSource.close();
    }
    clearInterval(timerInterval);

    resultsPanel.classList.add("hidden");
    telemetryPanel.classList.remove("hidden");
    submitBtn.disabled = true;
    submitBtn.querySelector(".btn-text").textContent = "CRAWLING...";

    telemetryTargetUrl.textContent = url;
    telemetryPhase.textContent = "INITIALIZING";
    telemetryProgressFill.style.width = "4%";
    statPages.textContent = "0";
    statQueue.textContent = "1";
    statLinks.textContent = "0";
    terminalLogs.innerHTML = "";
    addLog(`[VECTRA] Connecting to backend audit worker for ${url}...`, "system");

    startTime = Date.now();
    timerInterval = setInterval(() => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      statTimer.textContent = `${elapsed}s`;
    }, 100);

    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url,
          max_depth: depth,
          max_pages: maxPages,
          check_external: checkExternal
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to start audit job");
      }

      const jobData = await res.json();
      currentJobId = jobData.job_id;
      initEventStream(currentJobId, maxPages);

    } catch (err) {
      clearInterval(timerInterval);
      submitBtn.disabled = false;
      submitBtn.querySelector(".btn-text").textContent = "INITIALIZE AUDIT";
      telemetryPanel.classList.add("hidden");
      showToast(err.message, "error");
      addLog(`[ERROR] ${err.message}`, "warn");
    }
  }

  function initEventStream(jobId, maxPagesConfig) {
    activeEventSource = new EventSource(`/api/audit/${jobId}/stream`);

    activeEventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleStreamEvent(data, maxPagesConfig);
      } catch (e) {
        console.error("Failed to parse SSE event:", event.data);
      }
    };

    activeEventSource.onerror = (err) => {
      console.warn("EventSource encountered an error or connection ended.", err);
    };
  }

  function handleStreamEvent(data, maxPagesConfig) {
    const type = data.type;

    if (type === "connected") {
      addLog(`[WORKER] Connected. Job ID: ${data.job_id.slice(0, 8)}...`, "system");
      telemetryPhase.textContent = "DISPATCHING BFS";
      telemetryProgressFill.style.width = "10%";
    } 
    else if (type === "crawling_page") {
      telemetryPhase.textContent = `CRAWLING TIER (Depth ${data.depth})`;
      statPages.textContent = data.crawled_count;
      statQueue.textContent = data.queue_length;

      const progressPct = Math.min(80, Math.round((data.crawled_count / maxPagesConfig) * 75) + 10);
      telemetryProgressFill.style.width = `${progressPct}%`;
      addLog(`[FETCH] Parsed ${data.url} (Depth ${data.depth})`, "success");
    }
    else if (type === "status_update") {
      addLog(`[STATUS] ${data.message}`, "system");
    }
    else if (type === "checking_links") {
      telemetryPhase.textContent = "TESTING HYPERLINKS (404/DEAD ANCHORS)";
      telemetryProgressFill.style.width = "85%";
      statLinks.textContent = data.total_links;
      addLog(`[LINKS] Concurrently verifying ${data.total_links} discovered hyperlinks...`, "warn");
    }
    else if (type === "audit_completed" || type === "completed") {
      telemetryPhase.textContent = "COMPLETED";
      telemetryProgressFill.style.width = "100%";
      addLog(`[SUCCESS] Audit complete. Health Score: ${data.health_score || data.report_summary?.health_score}/100.`, "success");
      
      if (activeEventSource) {
        activeEventSource.close();
      }
      clearInterval(timerInterval);

      // Refresh history badge
      fetchHistoryList(false);

      setTimeout(() => {
        fetchAuditReport(currentJobId);
      }, 500);
    }
    else if (type === "error") {
      telemetryPhase.textContent = "EXECUTION FAILED";
      addLog(`[ERROR] ${data.message}`, "warn");
      if (activeEventSource) activeEventSource.close();
      clearInterval(timerInterval);
      submitBtn.disabled = false;
      submitBtn.querySelector(".btn-text").textContent = "INITIALIZE AUDIT";
      showToast(data.message, "error");
    }
  }

  function addLog(msg, type = "normal") {
    const line = document.createElement("div");
    line.className = `log-line ${type}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    terminalLogs.appendChild(line);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
  }

  // -------------------------------------------------------------
  // Fetch & Render Full Audit Report
  // -------------------------------------------------------------
  async function fetchAuditReport(jobId) {
    try {
      const res = await fetch(`/api/audit/${jobId}/report`);
      if (!res.ok) throw new Error("Could not retrieve audit report data");
      
      const report = await res.json();
      currentReportData = report;

      renderDashboard(report);

      telemetryPanel.classList.add("hidden");
      resultsPanel.classList.remove("hidden");
      submitBtn.disabled = false;
      submitBtn.querySelector(".btn-text").textContent = "INITIALIZE AUDIT";

      resultsPanel.scrollIntoView({ behavior: "smooth" });
      showToast("Comprehensive Audit Complete!", "success");

    } catch (err) {
      showToast(err.message, "error");
      submitBtn.disabled = false;
      submitBtn.querySelector(".btn-text").textContent = "INITIALIZE AUDIT";
    }
  }

  function renderDashboard(report) {
    const score = report.health_score || 0;
    reportScore.textContent = score;
    reportGrade.textContent = `Grade ${report.grade}`;
    reportDomain.textContent = report.root_url;
    reportTimestamp.textContent = `Generated: ${report.timestamp}`;
    reportPagesBadge.textContent = `${report.pages_crawled} Page(s) Crawled`;
    reportLinksBadge.textContent = `${report.total_links_checked} Links Tested`;
    reportDurationBadge.textContent = `${report.duration_seconds}s Duration`;

    // Security Badge
    const secSum = report.security_summary || {};
    reportSecBadge.textContent = `Security Grade: ${secSum.overall_grade || 'B'}`;

    // Radial Dial calculation
    const circumference = 440;
    const offset = circumference - (circumference * score) / 100;
    scoreCircle.style.strokeDashoffset = offset;

    if (score >= 85) {
      scoreCircle.style.stroke = "var(--accent-lichen)";
      reportGrade.style.color = "var(--accent-lichen)";
      reportGrade.style.borderColor = "var(--accent-lichen)";
    } else if (score >= 65) {
      scoreCircle.style.stroke = "var(--sev-warning)";
      reportGrade.style.color = "var(--sev-warning)";
      reportGrade.style.borderColor = "var(--sev-warning)";
    } else {
      scoreCircle.style.stroke = "var(--sev-critical)";
      reportGrade.style.color = "var(--sev-critical)";
      reportGrade.style.borderColor = "var(--sev-critical)";
    }

    const counts = report.severity_counts || {};
    countCritical.textContent = counts.critical || 0;
    countWarning.textContent = counts.warning || 0;
    countNotice.textContent = counts.notice || 0;
    countPassed.textContent = counts.passed || 0;

    tabIssuesCount.textContent = report.issues.length;
    tabBrokenCount.textContent = report.broken_links_count || 0;
    tabPagesCount.textContent = report.pages_crawled || 0;

    // Sub-Modules Rendering
    renderCategoryMeters(report.category_scores || {});
    renderIssuesList(report.issues || []);
    setupSerpPreviews(report.pages || []);
    setupHeadingTree(report.pages || []);
    renderSecurityPanel(report.security_summary || {}, report.pages || []);
    renderCwvPanel(report.pages || []);
    renderLinksTable(report.broken_links || [], report.pages || []);
    renderPagesGrid(report.pages || []);
  }

  function renderCategoryMeters(catScores) {
    categoryBarsContainer.innerHTML = "";
    const displayNames = {
      meta: "Meta Tags & Head SEO",
      headings: "Heading Hierarchy Structure",
      links: "Hyperlinks & Dead Anchors",
      images: "Image Media & Alt Tags",
      structure: "DOM & Semantic Landmarks",
      security: "Transport & SSL Security",
      performance: "Content Density & Response"
    };

    Object.entries(catScores).forEach(([cat, val]) => {
      const card = document.createElement("div");
      card.className = "cat-meter-card";

      let color = "var(--accent-lichen)";
      if (val < 60) color = "var(--sev-critical)";
      else if (val < 80) color = "var(--sev-warning)";

      card.innerHTML = `
        <div class="cat-meter-top">
          <span class="cat-name">${displayNames[cat] || cat}</span>
          <span class="cat-score" style="color: ${color}">${val}%</span>
        </div>
        <div class="cat-bar-track">
          <div class="cat-bar-fill" style="width: ${val}%; background: ${color}"></div>
        </div>
      `;
      categoryBarsContainer.appendChild(card);
    });
  }

  // -------------------------------------------------------------
  // Systematic Debugger Cards & Filtering
  // -------------------------------------------------------------
  function renderIssuesList(issues) {
    issuesListContainer.innerHTML = "";

    const filtered = issues.filter(issue => {
      const matchesSev = (activeSeverityFilter === "all" || issue.severity === activeSeverityFilter);
      const matchesCat = (activeCategoryFilter === "all" || issue.category === activeCategoryFilter);
      return matchesSev && matchesCat;
    });

    if (filtered.length === 0) {
      issuesListContainer.innerHTML = `
        <div class="card-surface" style="padding: 30px; text-align: center; color: var(--text-muted);">
          No issues found matching the active severity or category filters.
        </div>
      `;
      return;
    }

    filtered.forEach(issue => {
      const card = document.createElement("div");
      card.className = `issue-card ${issue.severity}`;

      const fixBlock = issue.code_fix ? `
        <div class="issue-recipe-box">
          <div class="recipe-header">
            <span class="recipe-title">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="16 18 22 12 16 6"></polyline>
                <polyline points="8 6 2 12 8 18"></polyline>
              </svg>
              Systematic Remediation Recipe:
            </span>
            <button class="copy-fix-btn" data-code="${encodeURIComponent(issue.code_fix)}">Copy Code</button>
          </div>
          <pre class="recipe-code"><code>${escapeHtml(issue.code_fix)}</code></pre>
        </div>
      ` : "";

      card.innerHTML = `
        <div class="issue-header">
          <div class="issue-title-row">
            <span class="issue-sev-badge ${issue.severity}">${issue.severity}</span>
            <span class="issue-cat-tag">#${issue.category}</span>
            <h4 class="issue-title">${escapeHtml(issue.title)}</h4>
          </div>
          <span class="issue-location" title="${escapeHtml(issue.location)}">${escapeHtml(issue.location)}</span>
        </div>

        <p class="issue-desc">${escapeHtml(issue.description)}</p>

        <div class="issue-impact-box">
          <span class="impact-label">Search & Structural Impact:</span>
          <span>${escapeHtml(issue.impact)}</span>
        </div>

        <div style="font-size: 13px; color: var(--text-primary);">
          <strong>Actionable Recommendation:</strong> ${escapeHtml(issue.recommendation)}
        </div>

        ${fixBlock}
      `;

      issuesListContainer.appendChild(card);
    });

    issuesListContainer.querySelectorAll(".copy-fix-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const rawCode = decodeURIComponent(btn.getAttribute("data-code"));
        navigator.clipboard.writeText(rawCode).then(() => {
          btn.textContent = "Copied!";
          setTimeout(() => btn.textContent = "Copy Code", 1800);
          showToast("Code snippet copied to clipboard!", "success");
        });
      });
    });
  }

  filterPills.forEach(pill => {
    pill.addEventListener("click", () => {
      filterPills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      activeSeverityFilter = pill.getAttribute("data-sev");
      if (currentReportData) renderIssuesList(currentReportData.issues);
    });
  });

  document.querySelectorAll(".tally-card").forEach(card => {
    card.addEventListener("click", () => {
      const sev = card.getAttribute("data-filter");
      filterPills.forEach(p => {
        p.classList.toggle("active", p.getAttribute("data-sev") === sev);
      });
      activeSeverityFilter = sev;
      switchTab("tab-debugger");
      if (currentReportData) renderIssuesList(currentReportData.issues);
    });
  });

  categorySelect.addEventListener("change", () => {
    activeCategoryFilter = categorySelect.value;
    if (currentReportData) renderIssuesList(currentReportData.issues);
  });

  // -------------------------------------------------------------
  // SERP & Social Previews Simulation
  // -------------------------------------------------------------
  function setupSerpPreviews(pages) {
    serpPageSelect.innerHTML = "";
    pages.forEach((p, idx) => {
      const opt = document.createElement("option");
      opt.value = idx;
      opt.textContent = `${p.url} (${p.title || 'Untitled'})`;
      serpPageSelect.appendChild(opt);
    });

    serpPageSelect.onchange = () => {
      const idx = parseInt(serpPageSelect.value, 10);
      renderSerpPagePreview(pages[idx]);
    };

    if (pages.length > 0) {
      renderSerpPagePreview(pages[0]);
    }
  }

  function renderSerpPagePreview(page) {
    if (!page) return;
    const serp = page.serp_preview || {};
    const social = page.social_preview || {};

    // Google SERP
    serpMockUrl.textContent = serp.display_url || page.url;
    serpMockTitle.textContent = serp.truncated_title || page.title || "Untitled Document";
    serpMockDesc.textContent = serp.snippet || "No description provided.";

    let statusNotes = [];
    if (serp.is_truncated_title) statusNotes.push("⚠️ Title exceeds 60 chars (truncated on Google)");
    if (serp.is_truncated_snippet) statusNotes.push("⚠️ Snippet exceeds 160 chars (truncated)");
    if (!serp.is_truncated_title && !serp.is_truncated_snippet) statusNotes.push("✓ Title and Snippet lengths are optimal for Google Desktop & Mobile");

    serpMockStatus.textContent = statusNotes.join(" | ");

    // Twitter / Social Card
    const urlObj = new URL(page.url);
    twitterMockDomain.textContent = urlObj.hostname;
    twitterMockTitle.textContent = social.twitter_title || social.og_title || page.title || "No Title";
    twitterMockDesc.textContent = social.twitter_description || social.og_description || page.description || "No description";

    if (social.og_image) {
      twitterMockImageWrap.innerHTML = `<img src="${escapeHtml(social.og_image)}" alt="Social Preview Thumbnail" onerror="this.parentElement.innerHTML='<span class=\\'social-image-placeholder\\'>Failed to load og:image</span>'">`;
    } else {
      twitterMockImageWrap.innerHTML = `<span class="social-image-placeholder">No og:image / twitter:image specified</span>`;
    }
  }

  // -------------------------------------------------------------
  // Heading Hierarchy Tree Visualizer
  // -------------------------------------------------------------
  function setupHeadingTree(pages) {
    treePageSelect.innerHTML = "";
    pages.forEach((p, idx) => {
      const opt = document.createElement("option");
      opt.value = idx;
      opt.textContent = `${p.url} (${p.headings_tree ? p.headings_tree.length : 0} headings)`;
      treePageSelect.appendChild(opt);
    });

    treePageSelect.onchange = () => {
      const selectedIndex = parseInt(treePageSelect.value, 10);
      renderHeadingNodes(pages[selectedIndex]?.headings_tree || []);
    };

    if (pages.length > 0) {
      renderHeadingNodes(pages[0]?.headings_tree || []);
    }
  }

  function renderHeadingNodes(treeNodes) {
    headingTreeDisplay.innerHTML = "";

    if (!treeNodes || treeNodes.length === 0) {
      headingTreeDisplay.innerHTML = `
        <div style="padding: 24px; text-align: center; color: var(--text-muted); font-family: var(--font-mono);">
          Zero headings (H1-H6) discovered on this page.
        </div>
      `;
      return;
    }

    treeNodes.forEach(node => {
      const row = document.createElement("div");
      row.className = `tree-node-row ${node.is_valid ? "" : "invalid"}`;
      
      const indentPx = (node.level - 1) * 26;
      row.style.marginLeft = `${indentPx}px`;

      const flagHtml = node.issue ? `<span class="tree-flag">⚠️ ${escapeHtml(node.issue)}</span>` : "";

      row.innerHTML = `
        <span class="tree-tag-badge ${node.tag}">${node.tag.toUpperCase()}</span>
        <span class="tree-text">${escapeHtml(node.text)}</span>
        ${flagHtml}
      `;

      headingTreeDisplay.appendChild(row);
    });
  }

  // -------------------------------------------------------------
  // Security Panel & SSL Headers
  // -------------------------------------------------------------
  function renderSecurityPanel(secSummary, pages) {
    const grade = secSummary.overall_grade || "B";
    const score = secSummary.average_score || 70;

    secOverallGrade.textContent = grade;
    secOverallScore.textContent = `Average Transport Score: ${score}/100`;

    if (grade === "A+" || grade === "A") {
      secOverallGrade.style.borderColor = "var(--accent-lichen)";
      secOverallGrade.style.color = "var(--accent-lichen)";
    } else if (grade === "B") {
      secOverallGrade.style.borderColor = "var(--sev-warning)";
      secOverallGrade.style.color = "var(--sev-warning)";
    } else {
      secOverallGrade.style.borderColor = "var(--sev-critical)";
      secOverallGrade.style.color = "var(--sev-critical)";
    }

    securityHeadersTableBody.innerHTML = "";
    const firstPage = pages[0] || {};
    const secHeaders = firstPage.security_headers || [];

    if (secHeaders.length === 0) {
      securityHeadersTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px;">No security headers recorded.</td></tr>`;
      return;
    }

    const recommendedMap = {
      "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'; script-src 'self'",
      "x-frame-options": "SAMEORIGIN / DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=()"
    };

    secHeaders.forEach(h => {
      const tr = document.createElement("tr");
      const statusPill = h.present ? 
        `<span class="status-pill ok">Configured</span>` : 
        `<span class="status-pill broken">Missing</span>`;

      tr.innerHTML = `
        <td><strong>${escapeHtml(h.header)}</strong></td>
        <td>${statusPill}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${escapeHtml(h.value || 'None')}
        </td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--accent-lichen);">
          ${escapeHtml(recommendedMap[h.key] || '-')}
        </td>
      `;
      securityHeadersTableBody.appendChild(tr);
    });
  }

  // -------------------------------------------------------------
  // Core Web Vitals & DOM Performance Panel
  // -------------------------------------------------------------
  function renderCwvPanel(pages) {
    cwvMetricsContainer.innerHTML = "";
    const p = pages[0] || {};
    const m = p.performance_metrics || {};

    const metricsDef = [
      {
        title: "DOM Node Count",
        val: m.dom_node_count || 0,
        tag: (m.dom_node_count || 0) > 1400 ? "Excessive" : "Optimal",
        color: (m.dom_node_count || 0) > 1400 ? "var(--sev-warning)" : "var(--accent-lichen)"
      },
      {
        title: "Render-Blocking Scripts",
        val: m.blocking_scripts || 0,
        tag: (m.blocking_scripts || 0) > 1 ? "Needs Defer/Async" : "Fast",
        color: (m.blocking_scripts || 0) > 1 ? "var(--sev-critical)" : "var(--accent-lichen)"
      },
      {
        title: "CLS Risk Rating",
        val: m.cls_risk_rating || "Low",
        tag: `${m.unsized_images || 0} unsized image(s)`,
        color: m.cls_risk_rating === "High" ? "var(--sev-critical)" : (m.cls_risk_rating === "Medium" ? "var(--sev-warning)" : "var(--accent-lichen)")
      },
      {
        title: "External Stylesheets",
        val: m.external_stylesheets || 0,
        tag: "CSS Network Requests",
        color: "var(--text-primary)"
      },
      {
        title: "Total JavaScript Assets",
        val: m.total_scripts || 0,
        tag: `${m.async_defer_scripts || 0} deferred/async`,
        color: "var(--text-primary)"
      },
      {
        title: "Resource Hints",
        val: m.resource_hints_count || 0,
        tag: "Preload & Preconnect",
        color: (m.resource_hints_count || 0) > 0 ? "var(--accent-lichen)" : "var(--text-muted)"
      }
    ];

    metricsDef.forEach(met => {
      const box = document.createElement("div");
      box.className = "cwv-metric-box";
      box.innerHTML = `
        <span class="cwv-metric-title">${escapeHtml(met.title)}</span>
        <span class="cwv-metric-val" style="color: ${met.color};">${escapeHtml(String(met.val))}</span>
        <span class="cwv-metric-tag" style="background: ${met.color}22; color: ${met.color};">${escapeHtml(met.tag)}</span>
      `;
      cwvMetricsContainer.appendChild(box);
    });
  }

  // -------------------------------------------------------------
  // Broken Links & Hyperlinks Table
  // -------------------------------------------------------------
  function renderLinksTable(brokenLinks, pages) {
    linksTableBody.innerHTML = "";

    const allLinks = [];
    brokenLinks.forEach(b => {
      allLinks.push({ ...b, is_broken: true });
    });

    const isBrokenOnly = brokenOnlyToggle.checked;
    const displayList = isBrokenOnly ? brokenLinks : allLinks;

    if (displayList.length === 0) {
      linksTableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 28px; color: var(--accent-lichen); font-family: var(--font-mono);">
            ✓ Zero broken links detected! All hyperlinks are healthy and functional.
          </td>
        </tr>
      `;
      return;
    }

    displayList.forEach(link => {
      const tr = document.createElement("tr");
      const statusClass = link.is_broken ? "broken" : "ok";
      const statusText = link.is_broken ? (link.status_code || link.error_message || "BROKEN") : (link.status_code || "200 OK");
      const linkType = link.is_fragment_only ? "Dead Anchor (#)" : (link.is_internal ? "Internal" : "External");

      tr.innerHTML = `
        <td><span class="status-pill ${statusClass}">${statusText}</span></td>
        <td style="font-family: var(--font-mono); color: var(--text-primary); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(link.url)}">
          ${escapeHtml(link.url)}
        </td>
        <td>"${escapeHtml(link.anchor_text || "No Anchor Text")}"</td>
        <td>${linkType}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(link.source_url)}">
          ${escapeHtml(link.source_url)}
        </td>
        <td style="font-family: var(--font-mono);">${link.response_time_ms ? link.response_time_ms + "ms" : "-"}</td>
      `;
      linksTableBody.appendChild(tr);
    });
  }

  brokenOnlyToggle.addEventListener("change", () => {
    if (currentReportData) {
      renderLinksTable(currentReportData.broken_links || [], currentReportData.pages || []);
    }
  });

  // -------------------------------------------------------------
  // Crawled Pages Grid
  // -------------------------------------------------------------
  function renderPagesGrid(pages) {
    pagesGridContainer.innerHTML = "";

    pages.forEach(p => {
      const card = document.createElement("div");
      card.className = "page-card";

      const hCountSummary = p.heading_counts ? 
        Object.entries(p.heading_counts).filter(([_, c]) => c > 0).map(([k, c]) => `${k.toUpperCase()}:${c}`).join(" | ") 
        : "None";

      card.innerHTML = `
        <div class="page-card-header">
          <span class="page-url-title">${escapeHtml(p.url)}</span>
          <span class="status-pill ${p.status_code === 200 ? 'ok' : 'broken'}">${p.status_code || 'ERR'}</span>
        </div>
        <div class="page-details-list">
          <div class="page-detail-row">
            <span>Title:</span>
            <strong style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(p.title || "Missing")}</strong>
          </div>
          <div class="page-detail-row">
            <span>Title Length:</span>
            <span>${p.title_length || 0} chars</span>
          </div>
          <div class="page-detail-row">
            <span>Description:</span>
            <strong style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(p.description || "Missing")}</strong>
          </div>
          <div class="page-detail-row">
            <span>Headings:</span>
            <span style="font-family: var(--font-mono);">${hCountSummary}</span>
          </div>
          <div class="page-detail-row">
            <span>Word Count:</span>
            <span>${p.word_count || 0} words</span>
          </div>
          <div class="page-detail-row">
            <span>Security Grade:</span>
            <span style="font-weight: 700; color: var(--accent-lichen);">${p.security_grade || 'B'} (${p.security_score || 0}%)</span>
          </div>
          <div class="page-detail-row">
            <span>Images Total:</span>
            <span>${p.images_total || 0} (${p.images_missing_alt?.length || 0} missing alt)</span>
          </div>
        </div>
      `;
      pagesGridContainer.appendChild(card);
    });
  }

  // -------------------------------------------------------------
  // Tab Switching
  // -------------------------------------------------------------
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      switchTab(targetId);
    });
  });

  function switchTab(tabId) {
    tabBtns.forEach(b => b.classList.toggle("active", b.getAttribute("data-tab") === tabId));
    tabContents.forEach(c => c.classList.toggle("active", c.id === tabId));
  }

  // -------------------------------------------------------------
  // Exports: Markdown, JSON, Print PDF
  // -------------------------------------------------------------
  downloadMdBtn.addEventListener("click", () => {
    if (!currentJobId) return;
    window.location.href = `/api/audit/${currentJobId}/export/markdown`;
    showToast("Downloading Markdown report...", "info");
  });

  downloadJsonBtn.addEventListener("click", () => {
    if (!currentJobId) return;
    window.location.href = `/api/audit/${currentJobId}/export/json`;
    showToast("Downloading JSON audit report...", "info");
  });

  printReportBtn.addEventListener("click", () => {
    window.print();
  });

  // -------------------------------------------------------------
  // Toast Notifications
  // -------------------------------------------------------------
  function showToast(msg, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = "toast";
    
    let icon = "ℹ️";
    if (type === "success") icon = "✓";
    if (type === "error") icon = "⚠️";

    toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
