import os
import uuid
import time
import json
import queue
import threading
from typing import Dict, Any
from flask import Flask, render_template, request, jsonify, Response, send_file, make_response
from flask_cors import CORS

from auditor import WebsiteCrawler, AuditReporter, SiteAuditReport
from auditor.db import init_db, save_audit, list_audits, get_audit_by_id, delete_audit_by_id
from demo.mock_site import demo_bp

# Initialize persistent SQLite audit store
init_db()

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Register intentional sandbox target
app.register_blueprint(demo_bp)

# In-memory storage for audit jobs
# job_id -> {"status": str, "events": Queue, "report": SiteAuditReport or None, "error": str or None, "created_at": float}
JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


def run_audit_worker(job_id: str, url: str, max_depth: int, max_pages: int, check_external: bool):
    def on_progress(event_data: Dict[str, Any]):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job and "events" in job:
                job["events"].put(event_data)

    try:
        crawler = WebsiteCrawler(
            root_url=url,
            max_depth=max_depth,
            max_pages=max_pages,
            check_external_links=check_external,
            progress_callback=on_progress
        )
        report = crawler.run_audit()
        
        # Persist to local SQLite history
        try:
            save_audit(report.to_dict())
        except Exception as save_err:
            print(f"Warning: could not save audit to SQLite: {save_err}")

        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["status"] = "completed"
                JOBS[job_id]["report"] = report
                JOBS[job_id]["events"].put({
                    "type": "completed",
                    "report_summary": {
                        "health_score": report.health_score,
                        "grade": report.grade,
                        "pages_crawled": report.pages_crawled,
                        "broken_links_count": report.broken_links_count,
                        "issues_count": len(report.issues)
                    }
                })
    except Exception as e:
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["status"] = "failed"
                JOBS[job_id]["error"] = str(e)
                JOBS[job_id]["events"].put({
                    "type": "error",
                    "message": f"Audit execution failed: {str(e)}"
                })


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    svg_icon = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FF5E36" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
    </svg>"""
    return Response(svg_icon, mimetype="image/svg+xml")


@app.route("/api/audit", methods=["POST"])
def start_audit():
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    max_depth = int(data.get("max_depth", 2))
    max_pages = int(data.get("max_pages", 10))
    check_external = bool(data.get("check_external", True))

    job_id = str(uuid.uuid4())
    event_q = queue.Queue()

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",
            "events": event_q,
            "report": None,
            "error": None,
            "created_at": time.time(),
            "target_url": target_url
        }

    thread = threading.Thread(
        target=run_audit_worker,
        args=(job_id, target_url, max_depth, max_pages, check_external),
        daemon=True
    )
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "running",
        "target_url": target_url,
        "stream_url": f"/api/audit/{job_id}/stream",
        "report_url": f"/api/audit/{job_id}/report"
    })


@app.route("/api/audit/<job_id>/stream")
def stream_audit_progress(job_id: str):
    """Server-Sent Events (SSE) streaming live progress for the given audit job."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        event_q = job["events"]

    def event_stream():
        yield f"data: {json.dumps({'type': 'connected', 'job_id': job_id})}\n\n"
        while True:
            try:
                event = event_q.get(timeout=25.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("completed", "error"):
                    break
            except queue.Empty:
                # Keep-alive heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


@app.route("/api/audit/<job_id>/report", methods=["GET"])
def get_audit_report(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        status = job["status"]
        if status == "running":
            return jsonify({"status": "running", "message": "Audit is currently processing"}), 202
        if status == "failed":
            return jsonify({"status": "failed", "error": job.get("error", "Unknown error")}), 500

        report: SiteAuditReport = job["report"]
        return jsonify(report.to_dict())


@app.route("/api/audit/<job_id>/export/markdown")
def export_markdown(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or not job.get("report"):
            return jsonify({"error": "Report not found or incomplete"}), 404
        report: SiteAuditReport = job["report"]

    md_content = AuditReporter.generate_markdown(report)
    response = make_response(md_content)
    domain_slug = report.root_url.replace("https://", "").replace("http://", "").replace("/", "_")
    response.headers["Content-Disposition"] = f"attachment; filename=audit_{domain_slug}_{int(time.time())}.md"
    response.headers["Content-Type"] = "text/markdown; charset=utf-8"
    return response


@app.route("/api/audit/<job_id>/export/json")
def export_json(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or not job.get("report"):
            return jsonify({"error": "Report not found or incomplete"}), 404
        report: SiteAuditReport = job["report"]

    json_str = json.dumps(report.to_dict(), indent=2)
    response = make_response(json_str)
    domain_slug = report.root_url.replace("https://", "").replace("http://", "").replace("/", "_")
    response.headers["Content-Disposition"] = f"attachment; filename=audit_{domain_slug}_{int(time.time())}.json"
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response


@app.route("/api/history", methods=["GET"])
def get_audit_history():
    """Lists recent audits stored in SQLite database."""
    limit = int(request.args.get("limit", 25))
    history = list_audits(limit=limit)
    return jsonify(history)


@app.route("/api/history/<audit_id>", methods=["GET"])
def get_historical_audit(audit_id: str):
    """Loads a specific full audit report from database."""
    report_data = get_audit_by_id(audit_id)
    if not report_data:
        return jsonify({"error": "Audit not found"}), 404
    return jsonify(report_data)


@app.route("/api/history/<audit_id>", methods=["DELETE"])
def delete_historical_audit(audit_id: str):
    """Deletes an audit from database."""
    success = delete_audit_by_id(audit_id)
    if not success:
        return jsonify({"error": "Audit not found"}), 404
    return jsonify({"success": True, "deleted_id": audit_id})


@app.route("/api/compare", methods=["GET"])
def compare_audits():
    """Compares two historical audits to show score evolution, fixed issues, and regressions."""
    id1 = request.args.get("id1")
    id2 = request.args.get("id2")
    if not id1 or not id2:
        return jsonify({"error": "Both id1 and id2 parameters required"}), 400

    report1 = get_audit_by_id(id1)
    report2 = get_audit_by_id(id2)
    if not report1 or not report2:
        return jsonify({"error": "One or both audit reports not found"}), 404

    score_delta = report2.get("health_score", 0) - report1.get("health_score", 0)
    
    issues1_keys = { (i.get("id"), i.get("location")): i for i in report1.get("issues", []) }
    issues2_keys = { (i.get("id"), i.get("location")): i for i in report2.get("issues", []) }

    fixed_issues = [i for k, i in issues1_keys.items() if k not in issues2_keys and i.get("severity") in ("critical", "warning")]
    new_issues = [i for k, i in issues2_keys.items() if k not in issues1_keys and i.get("severity") in ("critical", "warning")]

    return jsonify({
        "audit_before": {
            "id": id1,
            "timestamp": report1.get("timestamp"),
            "health_score": report1.get("health_score"),
            "grade": report1.get("grade")
        },
        "audit_after": {
            "id": id2,
            "timestamp": report2.get("timestamp"),
            "health_score": report2.get("health_score"),
            "grade": report2.get("grade")
        },
        "score_delta": score_delta,
        "improved": score_delta > 0,
        "fixed_issues_count": len(fixed_issues),
        "new_issues_count": len(new_issues),
        "fixed_issues": fixed_issues,
        "new_issues": new_issues
    })


@app.route("/api/health")
def health_check():
    return jsonify({
        "status": "online",
        "service": "Website Auditing Tool",
        "version": "2.5.0 Pro",
        "active_jobs": len(JOBS)
    })


if __name__ == "__main__":
    # Run server
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f">> Website Auditing Engine running on http://127.0.0.1:{port}")
    print(f">> Built-in Playground Target: http://127.0.0.1:{port}/demo-target")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
