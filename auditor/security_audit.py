from typing import Dict, List, Tuple, Any
from .models import AuditIssue, Severity, IssueCategory


class SecurityHeadersAuditor:
    """
    Evaluates enterprise-grade HTTP transport and response security headers.
    Calculates an authoritative security grade (A+ to F).
    """

    HEADERS_CONFIG = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "weight": 25,
            "recommended": "max-age=31536000; includeSubDomains; preload",
            "critical": True
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "weight": 25,
            "recommended": "default-src 'self'; script-src 'self'; img-src 'self' data: https:;",
            "critical": True
        },
        "x-frame-options": {
            "name": "X-Frame-Options (Clickjacking Protection)",
            "weight": 15,
            "recommended": "DENY or SAMEORIGIN",
            "critical": False
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options (MIME Sniffing)",
            "weight": 15,
            "recommended": "nosniff",
            "critical": False
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "weight": 10,
            "recommended": "strict-origin-when-cross-origin",
            "critical": False
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "weight": 10,
            "recommended": "camera=(), microphone=(), geolocation=()",
            "critical": False
        }
    }

    @classmethod
    def audit(cls, headers: Dict[str, str], is_https: bool, page_url: str) -> Tuple[int, str, List[Dict[str, Any]], List[AuditIssue]]:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        score = 0
        max_possible = 100
        headers_status = []
        issues: List[AuditIssue] = []

        if not is_https and not page_url.startswith(("http://localhost", "http://127.0.0.1")):
            return 20, "F", [], [
                AuditIssue(
                    id="transport_unencrypted",
                    category=IssueCategory.SECURITY.value,
                    severity=Severity.CRITICAL.value,
                    title="Transport Encryption Disabled (Insecure HTTP)",
                    description="The page is served via plain HTTP. Encryption headers cannot function securely over unencrypted transport.",
                    location=page_url,
                    impact="Exposes credentials, tokens, and data to network eavesdropping and man-in-the-middle tampering.",
                    recommendation="Enable SSL/TLS certificate and configure HTTP-to-HTTPS redirect."
                )
            ]

        for key, conf in cls.HEADERS_CONFIG.items():
            val = headers_lower.get(key)
            present = bool(val)
            weight = conf["weight"]

            if present:
                score += weight
                headers_status.append({
                    "header": conf["name"],
                    "key": key,
                    "present": True,
                    "value": val,
                    "status": "Configured"
                })
            else:
                headers_status.append({
                    "header": conf["name"],
                    "key": key,
                    "present": False,
                    "value": None,
                    "status": "Missing"
                })

                sev = Severity.WARNING.value if conf["critical"] else Severity.NOTICE.value
                issues.append(AuditIssue(
                    id=f"missing_header_{key.replace('-', '_')}",
                    category=IssueCategory.SECURITY.value,
                    severity=sev,
                    title=f"Missing Security Header: {conf['name']}",
                    description=f"HTTP response lacks the '{key}' header.",
                    location="HTTP Response Headers",
                    impact="Leaves users and web clients vulnerable to security exploits (XSS, clickjacking, MIME injection).",
                    recommendation=f"Add `{key}: {conf['recommended']}` to your web server or CDN configuration.",
                    code_fix=f"/* NGINX Header Directive */\nadd_header {key} \"{conf['recommended']}\" always;"
                ))

        # Check for server information leakage (Server or X-Powered-By)
        leaked = []
        if "server" in headers_lower:
            leaked.append(f"Server: {headers_lower['server']}")
        if "x-powered-by" in headers_lower:
            leaked.append(f"X-Powered-By: {headers_lower['x-powered-by']}")

        if leaked:
            issues.append(AuditIssue(
                id="server_banner_leak",
                category=IssueCategory.SECURITY.value,
                severity=Severity.NOTICE.value,
                title="Server Version Information Disclosure",
                description=f"Response headers expose internal software stack signatures ({', '.join(leaked)}).",
                location="HTTP Headers",
                impact="Allows automated scanners to fingerprint server versions and target known CVE vulnerabilities.",
                recommendation="Suppress Server and X-Powered-By banners in server configs.",
                code_fix="# NGINX:\nserver_tokens off;\n\n# Express / Node:\napp.disable('x-powered-by');"
            ))

        # Grade calculation
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        return score, grade, headers_status, issues
