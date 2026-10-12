from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    NOTICE = "notice"
    PASSED = "passed"


class IssueCategory(str, Enum):
    META = "meta"
    HEADINGS = "headings"
    LINKS = "links"
    IMAGES = "images"
    STRUCTURE = "structure"
    SECURITY = "security"
    PERFORMANCE = "performance"


@dataclass
class AuditIssue:
    id: str
    category: str
    severity: str
    title: str
    description: str
    location: str
    impact: str
    recommendation: str
    code_fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HeadingNode:
    level: int
    tag: str
    text: str
    is_valid: bool
    issue: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LinkCheckResult:
    url: str
    anchor_text: str
    source_url: str
    is_internal: bool
    status_code: Optional[int] = None
    is_broken: bool = False
    error_message: Optional[str] = None
    response_time_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PageAuditResult:
    url: str
    status_code: int
    response_time_ms: float
    title: Optional[str] = None
    title_length: int = 0
    description: Optional[str] = None
    description_length: int = 0
    canonical: Optional[str] = None
    robots_meta: Optional[str] = None
    viewport: Optional[str] = None
    lang: Optional[str] = None
    charset: Optional[str] = None
    open_graph: Dict[str, str] = field(default_factory=dict)
    twitter_cards: Dict[str, str] = field(default_factory=dict)
    heading_counts: Dict[str, int] = field(default_factory=dict)
    headings_tree: List[Dict[str, Any]] = field(default_factory=list)
    images_total: int = 0
    images_missing_alt: List[Dict[str, str]] = field(default_factory=list)
    word_count: int = 0
    content_length_bytes: int = 0
    ssl_active: bool = False
    issues: List[Dict[str, Any]] = field(default_factory=list)
    links_found: int = 0
    structured_data: List[Dict[str, Any]] = field(default_factory=list)
    security_headers: List[Dict[str, Any]] = field(default_factory=list)
    security_score: int = 0
    security_grade: str = "F"
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    serp_preview: Dict[str, Any] = field(default_factory=dict)
    social_preview: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SiteAuditReport:
    root_url: str
    timestamp: str
    duration_seconds: float
    pages_crawled: int
    total_links_checked: int
    broken_links_count: int
    health_score: int
    grade: str
    id: Optional[str] = None
    category_scores: Dict[str, int] = field(default_factory=dict)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    category_issue_counts: Dict[str, int] = field(default_factory=dict)
    issues: List[Dict[str, Any]] = field(default_factory=list)
    broken_links: List[Dict[str, Any]] = field(default_factory=list)
    pages: List[Dict[str, Any]] = field(default_factory=list)
    crawl_summary: Dict[str, Any] = field(default_factory=dict)
    structured_data_summary: List[Dict[str, Any]] = field(default_factory=list)
    security_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
