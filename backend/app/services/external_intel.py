"""
Sentinel AI — External Intelligence Service
Single module for all outbound intel calls: VirusTotal, Shodan, NVD, MITRE ATT&CK, GitHub.
Agents NEVER call httpx directly — they go through this service.

Key features:
- Per-source rate limiting (token bucket / sliding window)
- Per-source SQLite caching (IOC 24h, CVE 7d)
- Graceful degradation on unavailability (never fails the whole pipeline)
- Secret behind interface for easy replacement (NVD -> VulnCheck, etc.)
"""
import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.exceptions import ExternalAPIError, RateLimitError

log = structlog.get_logger(__name__)


# ============================================================
# Rate Limiters (per-source token buckets)
# ============================================================

class AsyncTokenBucket:
    """Simple token bucket rate limiter for per-source throttling."""

    def __init__(self, rate_per_second: float, burst: int = 1) -> None:
        self._rate = rate_per_second
        self._burst = burst
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# Per-source rate limiters
_vt_limiter = AsyncTokenBucket(rate_per_second=settings.VIRUSTOTAL_REQUESTS_PER_MINUTE / 60.0, burst=2)
_shodan_limiter = AsyncTokenBucket(rate_per_second=float(settings.SHODAN_REQUESTS_PER_SECOND), burst=1)
_nvd_limiter = AsyncTokenBucket(rate_per_second=settings.NVD_REQUESTS_PER_30S / 30.0, burst=5)


# ============================================================
# Shared async HTTP client
# ============================================================

_http_client: Optional[httpx.AsyncClient] = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
    return _http_client


# ============================================================
# SQLite Cache Helpers (direct SQL to avoid circular imports)
# ============================================================

async def _get_ioc_from_cache(ioc_key: str) -> Optional[Dict[str, Any]]:
    """Return cached IOC enrichment if not expired, else None."""
    from sqlalchemy import select, text
    from app.db.database import AsyncSessionLocal
    from app.db.models.ioc_cache import IOCEnrichmentCache

    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(IOCEnrichmentCache).where(
                IOCEnrichmentCache.ioc_key == ioc_key,
                IOCEnrichmentCache.expires_at > now,
            )
        )
        cached = result.scalar_one_or_none()
        if cached:
            return {"data": cached.enrichment_data, "status": cached.enrichment_status}
    return None


async def _set_ioc_cache(ioc_key: str, ioc_value: str, ioc_type: str,
                          enrichment_data: dict, status: str) -> None:
    from app.db.database import AsyncSessionLocal
    from app.db.models.ioc_cache import IOCEnrichmentCache
    from sqlalchemy import select

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.IOC_CACHE_TTL_SECONDS)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IOCEnrichmentCache).where(IOCEnrichmentCache.ioc_key == ioc_key)
        )
        cached = result.scalar_one_or_none()
        if cached:
            cached.enrichment_data = enrichment_data
            cached.enrichment_status = status
            cached.cached_at = now
            cached.expires_at = expires_at
        else:
            db.add(IOCEnrichmentCache(
                ioc_key=ioc_key, ioc_value=ioc_value, ioc_type=ioc_type,
                enrichment_data=enrichment_data, enrichment_status=status,
                cached_at=now, expires_at=expires_at,
            ))
        await db.commit()


async def _get_cve_from_cache(cve_id: str) -> Optional[Dict[str, Any]]:
    from sqlalchemy import select
    from app.db.database import AsyncSessionLocal
    from app.db.models.cve_cache import CVECache

    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(CVECache).where(
                CVECache.cve_id == cve_id.upper(),
                CVECache.expires_at > now,
            )
        )
        cached = result.scalar_one_or_none()
        if cached:
            return cached.nvd_data
    return None


async def _set_cve_cache(cve_id: str, nvd_data: dict, cvss_score: Optional[float],
                          cvss_severity: Optional[str], cvss_vector: Optional[str]) -> None:
    from app.db.database import AsyncSessionLocal
    from app.db.models.cve_cache import CVECache
    from sqlalchemy import select

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.CVE_CACHE_TTL_SECONDS)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CVECache).where(CVECache.cve_id == cve_id.upper())
        )
        cached = result.scalar_one_or_none()
        if cached:
            cached.nvd_data = nvd_data
            cached.cvss_v3_score = cvss_score
            cached.cvss_v3_severity = cvss_severity
            cached.cvss_v3_vector = cvss_vector
            cached.cached_at = now
            cached.expires_at = expires_at
        else:
            db.add(CVECache(
                cve_id=cve_id.upper(), nvd_data=nvd_data, cvss_v3_score=cvss_score,
                cvss_v3_severity=cvss_severity, cvss_v3_vector=cvss_vector,
                cached_at=now, expires_at=expires_at,
            ))
        await db.commit()


# ============================================================
# VirusTotal Client
# ============================================================

async def enrich_ioc_virustotal(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Query VirusTotal for IOC reputation. Caches results for 24h.
    Degrades gracefully if API is unreachable or key is missing.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        log.warning("virustotal_key_missing", ioc=value)
        return {"source": "virustotal", "status": "unavailable", "reason": "API key not configured"}

    ioc_key = f"{value}::{ioc_type}"
    cached = await _get_ioc_from_cache(ioc_key)
    if cached:
        log.debug("virustotal_cache_hit", ioc=value)
        return cached["data"]

    await _vt_limiter.acquire()

    try:
        client = _get_http_client()
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        type_to_endpoint = {
            "IP": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            "Domain": f"https://www.virustotal.com/api/v3/domains/{value}",
            "Hash": f"https://www.virustotal.com/api/v3/files/{value}",
        }
        url = type_to_endpoint.get(ioc_type, f"https://www.virustotal.com/api/v3/ip_addresses/{value}")
        response = await client.get(url, headers=headers)

        if response.status_code == 429:
            log.warning("virustotal_rate_limited", ioc=value)
            result = {"source": "virustotal", "status": "unavailable", "reason": "rate_limited"}
            await _set_ioc_cache(ioc_key, value, ioc_type, result, "unavailable")
            return result

        if response.status_code == 404:
            result = {"source": "virustotal", "status": "not_found", "reputation": "unknown"}
            await _set_ioc_cache(ioc_key, value, ioc_type, result, "ok")
            return result

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        result = {
            "source": "virustotal",
            "status": "ok",
            "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
            "reputation": attributes.get("reputation", 0),
            "country": attributes.get("country", "Unknown"),
            "tags": attributes.get("tags", []),
        }
        await _set_ioc_cache(ioc_key, value, ioc_type, result, "ok")
        log.info("virustotal_enriched", ioc=value, malicious=result["malicious"])
        return result

    except Exception as e:
        log.error("virustotal_error", ioc=value, error=str(e))
        result = {"source": "virustotal", "status": "unavailable", "reason": str(e)[:200]}
        await _set_ioc_cache(ioc_key, value, ioc_type, result, "unavailable")
        return result


# ============================================================
# Shodan Client
# ============================================================

async def enrich_ip_shodan(ip: str) -> Dict[str, Any]:
    """
    Query Shodan for exposed ports and banners. 24h cache.
    Degrades gracefully if unavailable.
    """
    if not settings.SHODAN_API_KEY:
        log.warning("shodan_key_missing", ip=ip)
        return {"source": "shodan", "status": "unavailable", "reason": "API key not configured"}

    ioc_key = f"{ip}::IP::shodan"
    cached = await _get_ioc_from_cache(ioc_key)
    if cached:
        log.debug("shodan_cache_hit", ip=ip)
        return cached["data"]

    await _shodan_limiter.acquire()

    try:
        client = _get_http_client()
        response = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": settings.SHODAN_API_KEY},
        )
        if response.status_code == 404:
            result = {"source": "shodan", "status": "not_found"}
        elif response.status_code == 401:
            result = {"source": "shodan", "status": "unavailable", "reason": "Invalid API key"}
        else:
            response.raise_for_status()
            data = response.json()
            result = {
                "source": "shodan",
                "status": "ok",
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org", "Unknown"),
                "country": data.get("country_name", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "last_update": data.get("last_update"),
                "vulns": list(data.get("vulns", {}).keys()),
            }

        await _set_ioc_cache(ioc_key, ip, "IP", result, result.get("status", "ok"))
        log.info("shodan_enriched", ip=ip, ports=result.get("open_ports", []))
        return result

    except Exception as e:
        log.error("shodan_error", ip=ip, error=str(e))
        result = {"source": "shodan", "status": "unavailable", "reason": str(e)[:200]}
        await _set_ioc_cache(ioc_key, ip, "IP", result, "unavailable")
        return result


# ============================================================
# NVD CVE Client (behind interface for easy swap)
# ============================================================

class CVEDataSource(ABC):
    """Interface for CVE data providers. Swap NVD for VulnCheck by implementing this."""

    @abstractmethod
    async def get_cve(self, cve_id: str) -> Dict[str, Any]:
        pass


class NVDCVESource(CVEDataSource):
    """NVD CVE API 2.0 implementation with caching and backoff."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @retry(
        retry=retry_if_exception_type(ExternalAPIError),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        reraise=True,
    )
    async def get_cve(self, cve_id: str) -> Dict[str, Any]:
        # Check cache first
        cached = await _get_cve_from_cache(cve_id)
        if cached:
            log.debug("nvd_cache_hit", cve_id=cve_id)
            return cached

        await _nvd_limiter.acquire()

        headers = {"Accept": "application/json"}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            client = _get_http_client()
            response = await client.get(
                self.BASE_URL,
                params={"cveId": cve_id.upper()},
                headers=headers,
            )

            if response.status_code in (403, 503):
                log.warning("nvd_rate_limited_or_unavailable", status=response.status_code, cve_id=cve_id)
                raise ExternalAPIError("NVD", f"HTTP {response.status_code}", response.status_code)

            if response.status_code == 404:
                return {"cve_id": cve_id, "status": "not_found"}

            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                return {"cve_id": cve_id, "status": "not_found"}

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            # Parse CVSS v3.1 or v3.0
            cvss_score = None
            cvss_severity = None
            cvss_vector = None

            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    cvss_score = m.get("baseScore")
                    cvss_severity = m.get("baseSeverity")
                    cvss_vector = m.get("vectorString")
                    break

            result = {
                "cve_id": cve_id.upper(),
                "status": "found",
                "description": next(
                    (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                    "No description available",
                ),
                "cvss_v3_score": cvss_score,
                "cvss_v3_severity": cvss_severity,
                "cvss_v3_vector": cvss_vector,
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "references": [r["url"] for r in cve_data.get("references", [])[:5]],
                "cwe_ids": [
                    w.get("description", [{}])[0].get("value", "")
                    for w in cve_data.get("weaknesses", [])
                ],
            }

            await _set_cve_cache(cve_id, result, cvss_score, cvss_severity, cvss_vector)
            log.info("nvd_fetched", cve_id=cve_id, score=cvss_score, severity=cvss_severity)
            return result

        except ExternalAPIError:
            raise
        except Exception as e:
            log.error("nvd_error", cve_id=cve_id, error=str(e))
            return {"cve_id": cve_id, "status": "unavailable", "reason": str(e)[:200]}


# Singleton source — swap this to use VulnCheck or another mirror
_cve_source: CVEDataSource = NVDCVESource()


async def get_cve(cve_id: str) -> Dict[str, Any]:
    return await _cve_source.get_cve(cve_id)


# ============================================================
# MITRE ATT&CK (local STIX dataset)
# ============================================================

_mitre_data: Optional[Dict[str, Any]] = None
_mitre_techniques: Optional[Dict[str, Any]] = None  # technique_id -> technique


def _load_mitre_data() -> Dict[str, Any]:
    global _mitre_data, _mitre_techniques

    if _mitre_data is not None:
        return _mitre_data

    path = settings.MITRE_DATA_PATH
    if not os.path.exists(path):
        log.warning("mitre_data_not_found", path=path)
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            _mitre_data = json.load(f)

        # Index techniques by ID for fast lookup
        _mitre_techniques = {}
        for obj in _mitre_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id", "")
                        if tid:
                            _mitre_techniques[tid] = obj
                            break

        log.info("mitre_data_loaded", technique_count=len(_mitre_techniques or {}))
        return _mitre_data
    except Exception as e:
        log.error("mitre_data_load_error", error=str(e))
        return {}


def get_mitre_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Look up a MITRE ATT&CK technique by ID (e.g., T1566.001)."""
    _load_mitre_data()
    if _mitre_techniques is None:
        return None
    return _mitre_techniques.get(technique_id.upper())


def search_mitre_techniques(keywords: List[str]) -> List[Dict[str, Any]]:
    """Find MITRE techniques matching any of the given keywords (in name or description)."""
    _load_mitre_data()
    if not _mitre_techniques:
        return []

    results = []
    kws_lower = [k.lower() for k in keywords]
    for tid, tech in _mitre_techniques.items():
        name = tech.get("name", "").lower()
        desc = tech.get("description", "").lower()
        if any(kw in name or kw in desc for kw in kws_lower):
            ext_refs = tech.get("external_references", [])
            mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
            results.append({
                "id": tid,
                "name": tech.get("name"),
                "description": tech.get("description", "")[:300],
                "url": mitre_ref.get("url"),
                "tactics": [p.get("phase_name") for p in tech.get("kill_chain_phases", [])],
            })
    return results[:10]  # Return top 10 matches


# ============================================================
# GitHub Repo Cloner (shallow, ephemeral)
# ============================================================

async def clone_github_repo(repo_url: str, github_token: Optional[str] = None) -> str:
    """
    Shallow-clone a GitHub repo into an ephemeral temp directory.
    Returns the path to the cloned directory.
    The CALLER is responsible for deleting it after use.
    """
    temp_dir = tempfile.mkdtemp(prefix="sentinel_scan_", dir="./data/scan_tmp")

    # Inject token into URL if provided
    if github_token and "github.com" in repo_url:
        repo_url = repo_url.replace("https://", f"https://{github_token}@")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ExternalAPIError("GitHub", f"Clone failed: {result.stderr[:500]}")

        log.info("github_repo_cloned", url=repo_url.split("@")[-1], temp_dir=temp_dir)
        return temp_dir
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ExternalAPIError("GitHub", "Clone timed out after 120s")


def cleanup_temp_dir(temp_dir: str) -> None:
    """Delete a temp directory created by clone_github_repo."""
    if temp_dir and os.path.exists(temp_dir) and "sentinel_scan_" in temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)
        log.info("temp_dir_cleaned", temp_dir=temp_dir)
