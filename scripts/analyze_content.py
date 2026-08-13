#!/usr/bin/env python3
"""Analyze Liuli shadow candidates and return versioned evidence to the app."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image, ImageFilter, ImageStat


SCHEMA_VERSION = "liuli-analysis-report-v1"
ANALYZER_VERSION = "liuli-pixel-analysis-v1"
MAX_IMAGE_BYTES = 15 * 1024 * 1024
MAX_IMAGE_PIXELS = 80_000_000
ALLOWED_IMAGE_HOSTS = {"www.artic.edu", "openaccess-cdn.clevelandart.org"}
HEX_64 = re.compile(r"^[a-f0-9]{64}$")

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


@dataclass(frozen=True)
class Candidate:
    source_name: str
    source_item_id: str
    image_url: str
    source_url: str
    asset_sha256: str


def main() -> int:
    args = parse_args()
    origin = require_https_origin(args.origin)
    token = args.token.strip()
    if len(token) < 32:
        raise SystemExit("LIULI_AUTOMATION_TOKEN must be at least 32 characters")
    sites_bypass_token = require_sites_bypass_token(origin, args.sites_bypass_token)

    ingestion_summary: dict[str, Any] | None = None
    if args.trigger_ingestion:
        ingestion_response = trigger_ingestion(origin, token, sites_bypass_token, args.ingestion_page)
        raw_summary = ingestion_response.get("result", {})
        if isinstance(raw_summary, dict):
            ingestion_summary = {
                key: raw_summary.get(key)
                for key in ("status", "discovered", "scheduled", "exception", "rejected", "rejectionReasons", "errorCode")
            }

    endpoint = f"{origin}/api/automation/content-analysis"
    candidates = fetch_candidates(endpoint, token, sites_bypass_token)
    if not candidates:
        print(json.dumps({
            "ingestion": ingestion_summary,
            "candidates": 0,
            "submitted": 0,
        }, ensure_ascii=False))
        return 0

    clam_version = read_clamav_version()
    reports: list[dict[str, Any]] = []
    for candidate in candidates:
        image_bytes = download_candidate(candidate)
        digest = hashlib.sha256(image_bytes).hexdigest()
        if digest != candidate.asset_sha256:
            raise RuntimeError(f"asset_changed:{candidate.source_name}:{candidate.source_item_id}")
        with tempfile.TemporaryDirectory(prefix="liuli-analysis-") as temp_dir:
            image_path = Path(temp_dir) / "candidate.jpg"
            image_path.write_bytes(image_bytes)
            scan_with_clamav(image_path)
            evidence = analyze_image_bytes(image_bytes)
        reports.append({
            "sourceName": candidate.source_name,
            "sourceItemId": candidate.source_item_id,
            "assetSha256": digest,
            "perceptualHash": evidence["perceptualHash"],
            "width": evidence["width"],
            "height": evidence["height"],
            "bytes": len(image_bytes),
            "palette": evidence["palette"],
            "metrics": evidence["metrics"],
            "malware": {
                "provider": "ClamAV",
                "engineVersion": clam_version,
                "result": "clean",
            },
        })

    response = submit_reports(endpoint, token, sites_bypass_token, {
        "schemaVersion": SCHEMA_VERSION,
        "analyzerVersion": ANALYZER_VERSION,
        "runId": args.run_id,
        "runUrl": args.run_url,
        "reports": reports,
    })
    print(json.dumps({
        "candidates": len(candidates),
        "submitted": len(reports),
        "results": response.get("results", []),
    }, ensure_ascii=False))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default=os.environ.get("LIULI_AUTOMATION_ORIGIN", ""))
    parser.add_argument("--token", default=os.environ.get("LIULI_AUTOMATION_TOKEN", ""))
    parser.add_argument(
        "--sites-bypass-token",
        default=os.environ.get("LIULI_SITES_BYPASS_TOKEN", ""),
    )
    parser.add_argument("--run-id", default=os.environ.get("LIULI_ANALYSIS_RUN_ID", ""))
    parser.add_argument("--run-url", default=os.environ.get("LIULI_ANALYSIS_RUN_URL", ""))
    parser.add_argument("--trigger-ingestion", action="store_true")
    parser.add_argument(
        "--ingestion-page",
        type=int,
        default=int(os.environ.get("LIULI_INGESTION_PAGE", "0") or "0"),
    )
    args = parser.parse_args()
    if not args.run_id or len(args.run_id) > 120:
        parser.error("--run-id must be 1–120 controlled characters")
    require_https_url(args.run_url)
    if args.ingestion_page < 0 or args.ingestion_page > 1000:
        parser.error("--ingestion-page must be from 1 to 1000 when provided")
    return args


def trigger_ingestion(
    origin: str,
    token: str,
    sites_bypass_token: str,
    page: int,
) -> dict[str, Any]:
    payload = {"page": page} if page else {}
    response = json_request(
        f"{origin}/api/automation/ingestion",
        token,
        sites_bypass_token,
        method="POST",
        payload=payload,
    )
    if response.get("schemaVersion") != "liuli-ingestion-run-v1":
        raise RuntimeError("ingestion_schema_mismatch")
    return response


def fetch_candidates(endpoint: str, token: str, sites_bypass_token: str) -> list[Candidate]:
    payload = json_request(endpoint, token, sites_bypass_token, method="GET")
    if payload.get("schemaVersion") != "liuli-analysis-candidates-v1":
        raise RuntimeError("candidate_schema_mismatch")
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list) or len(raw_candidates) > 24:
        raise RuntimeError("candidate_list_invalid")
    candidates = []
    for value in raw_candidates:
        if not isinstance(value, dict) or set(value) != {
            "sourceName", "sourceItemId", "imageUrl", "sourceUrl", "assetSha256"
        }:
            raise RuntimeError("candidate_shape_invalid")
        if value["sourceName"] not in {"art-institute-chicago", "cleveland-museum-art"} or not HEX_64.fullmatch(value["assetSha256"]):
            raise RuntimeError("candidate_identity_invalid")
        require_allowed_image_url(value["imageUrl"])
        require_https_url(value["sourceUrl"])
        candidates.append(Candidate(
            source_name=value["sourceName"],
            source_item_id=str(value["sourceItemId"]),
            image_url=value["imageUrl"],
            source_url=value["sourceUrl"],
            asset_sha256=value["assetSha256"],
        ))
    return candidates


def download_candidate(candidate: Candidate) -> bytes:
    request = urllib.request.Request(candidate.image_url, headers={
        "Accept": "image/jpeg",
        "User-Agent": "LiuliWallpaperAnalyzer/0.19",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        require_allowed_image_url(response.geturl())
        content_type = response.headers.get_content_type()
        if content_type not in {"image/jpeg", "image/jpg"}:
            raise RuntimeError("image_mime_invalid")
        data = response.read(MAX_IMAGE_BYTES + 1)
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise RuntimeError("image_size_invalid")
    return data


def analyze_image_bytes(image_bytes: bytes) -> dict[str, Any]:
    from io import BytesIO

    with Image.open(BytesIO(image_bytes)) as image:
        image.load()
        if image.format != "JPEG":
            raise RuntimeError("image_format_invalid")
        width, height = image.size
        if min(width, height) < 640 or max(width, height) > 12_000 or width * height > MAX_IMAGE_PIXELS:
            raise RuntimeError("image_dimensions_invalid")
        rgb = image.convert("RGB")
        gray = rgb.convert("L")
        metrics = image_metrics(gray)
        return {
            "width": width,
            "height": height,
            "perceptualHash": difference_hash(gray),
            "palette": dominant_palette(rgb),
            "metrics": metrics,
        }


def difference_hash(gray: Image.Image) -> str:
    sampled = gray.resize((9, 8), Image.Resampling.LANCZOS)
    pixels = sampled.tobytes()
    value = 0
    for row in range(8):
        for column in range(8):
            value = (value << 1) | int(pixels[row * 9 + column] > pixels[row * 9 + column + 1])
    return f"{value:016x}"


def dominant_palette(rgb: Image.Image) -> list[str]:
    sample = rgb.copy()
    sample.thumbnail((256, 256), Image.Resampling.LANCZOS)
    quantized = sample.quantize(colors=5, method=Image.Quantize.MEDIANCUT)
    colors = quantized.getcolors(maxcolors=256) or []
    palette_values = quantized.getpalette() or []
    result = []
    for _, index in sorted(colors, reverse=True):
        offset = index * 3
        if offset + 2 >= len(palette_values):
            continue
        red, green, blue = palette_values[offset:offset + 3]
        color = f"#{red:02x}{green:02x}{blue:02x}"
        if color not in result:
            result.append(color)
    return result[:5] or ["#000000"]


def image_metrics(gray: Image.Image) -> dict[str, int]:
    sample = gray.copy()
    sample.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
    stats = ImageStat.Stat(sample)
    contrast = clamp(round(stats.stddev[0] / 64 * 100))
    edges = sample.filter(ImageFilter.FIND_EDGES)
    edge_stats = ImageStat.Stat(edges)
    sharpness = clamp(round(edge_stats.stddev[0] / 48 * 100))
    histogram = sample.histogram()
    total = max(1, sample.width * sample.height)
    clipped = sum(histogram[:6]) + sum(histogram[250:])
    clipping = clamp(round(clipped / total * 100))

    band_height = max(1, sample.height // 7)
    band_width = max(1, sample.width // 10)
    bands = [
        sample.crop((0, 0, sample.width, band_height)),
        sample.crop((0, sample.height - band_height, sample.width, sample.height)),
        sample.crop((0, 0, band_width, sample.height)),
        sample.crop((sample.width - band_width, 0, sample.width, sample.height)),
    ]
    band_activity = sum(ImageStat.Stat(band).stddev[0] for band in bands) / len(bands)
    safe_area = clamp(round(100 - band_activity / 64 * 100))

    corner = edges.crop((int(edges.width * 0.68), int(edges.height * 0.72), edges.width, edges.height))
    corner_histogram = corner.histogram()
    corner_total = max(1, corner.width * corner.height)
    high_edges = sum(corner_histogram[64:])
    watermark_risk = clamp(round(high_edges / corner_total * 180))
    return {
        "sharpness": sharpness,
        "contrast": contrast,
        "clipping": clipping,
        "safeArea": safe_area,
        "watermarkRisk": watermark_risk,
    }


def read_clamav_version() -> str:
    result = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, check=True)
    version = result.stdout.strip().splitlines()[0][:80]
    if not version:
        raise RuntimeError("clamav_version_missing")
    return version


def scan_with_clamav(path: Path) -> None:
    result = subprocess.run(
        ["clamscan", "--no-summary", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 1:
        raise RuntimeError("malware_detected")
    if result.returncode != 0 or " OK" not in result.stdout:
        raise RuntimeError("malware_scan_failed")


def submit_reports(
    endpoint: str,
    token: str,
    sites_bypass_token: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return json_request(endpoint, token, sites_bypass_token, method="POST", payload=payload)


def json_request(
    url: str,
    token: str,
    sites_bypass_token: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers=automation_headers(token, sites_bypass_token),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(256 * 1024)
    except urllib.error.HTTPError as error:
        detail = error.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"automation_http_{error.code}:{detail[:500]}") from error
    value = json.loads(data)
    if not isinstance(value, dict):
        raise RuntimeError("automation_response_invalid")
    return value


def automation_headers(token: str, sites_bypass_token: str = "") -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "LiuliWallpaperAnalyzer/0.19",
    }
    if sites_bypass_token:
        headers["OAI-Sites-Authorization"] = f"Bearer {sites_bypass_token}"
    return headers


def require_sites_bypass_token(origin: str, value: str) -> str:
    token = value.strip()
    if token and len(token) < 32:
        raise SystemExit(
            "LIULI_SITES_BYPASS_TOKEN must be at least 32 characters when provided"
        )
    return token


def require_https_origin(value: str) -> str:
    parsed = require_https_url(value)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise SystemExit("LIULI_AUTOMATION_ORIGIN must be an HTTPS origin without a path")
    return f"{parsed.scheme}://{parsed.netloc}"


def require_https_url(value: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise SystemExit("Expected a credential-free HTTPS URL")
    return parsed


def require_allowed_image_url(value: str) -> None:
    parsed = require_https_url(value)
    if parsed.hostname not in ALLOWED_IMAGE_HOSTS:
        raise RuntimeError("image_host_not_allowed")


def clamp(value: int) -> int:
    return min(100, max(0, value))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"liuli_analyzer_error:{type(error).__name__}:{error}", file=sys.stderr)
        raise
