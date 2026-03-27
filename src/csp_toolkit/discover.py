"""Auto-discover resources on a website and generate a tailored CSP."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .generator import CSPBuilder


@dataclass
class DiscoveredResources:
    url: str
    pages_crawled: int = 0
    script_origins: set[str] = field(default_factory=set)
    style_origins: set[str] = field(default_factory=set)
    img_origins: set[str] = field(default_factory=set)
    font_origins: set[str] = field(default_factory=set)
    connect_origins: set[str] = field(default_factory=set)
    media_origins: set[str] = field(default_factory=set)
    frame_origins: set[str] = field(default_factory=set)
    form_origins: set[str] = field(default_factory=set)
    manifest_origins: set[str] = field(default_factory=set)
    object_origins: set[str] = field(default_factory=set)
    has_inline_scripts: bool = False
    has_inline_styles: bool = False
    has_inline_style_attrs: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "pages_crawled": self.pages_crawled,
            "script_origins": sorted(self.script_origins),
            "style_origins": sorted(self.style_origins),
            "img_origins": sorted(self.img_origins),
            "font_origins": sorted(self.font_origins),
            "connect_origins": sorted(self.connect_origins),
            "media_origins": sorted(self.media_origins),
            "frame_origins": sorted(self.frame_origins),
            "form_origins": sorted(self.form_origins),
            "manifest_origins": sorted(self.manifest_origins),
            "object_origins": sorted(self.object_origins),
            "has_inline_scripts": self.has_inline_scripts,
            "has_inline_styles": self.has_inline_styles,
            "has_inline_style_attrs": self.has_inline_style_attrs,
        }


def _extract_origin(resource_url: str, page_url: str) -> str | None:
    """Extract the origin from a resource URL. Returns None for same-origin."""
    if not resource_url:
        return None

    # Handle data: and blob: URIs
    if resource_url.startswith("data:"):
        return "data:"
    if resource_url.startswith("blob:"):
        return "blob:"

    # Handle protocol-relative URLs
    if resource_url.startswith("//"):
        resource_url = "https:" + resource_url

    # Resolve relative URLs
    resolved = urljoin(page_url, resource_url)
    parsed = urlparse(resolved)
    page_parsed = urlparse(page_url)

    if not parsed.scheme or not parsed.hostname:
        return None

    # Same origin check
    if (parsed.scheme == page_parsed.scheme and
            parsed.hostname == page_parsed.hostname and
            (parsed.port or 443) == (page_parsed.port or 443)):
        return None  # Same origin, covered by 'self'

    # Build origin
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        origin += f":{parsed.port}"

    return origin


def _add_origin(origins: set[str], resource_url: str, page_url: str) -> None:
    """Extract origin from a resource URL and add it to the set."""
    origin = _extract_origin(resource_url, page_url)
    if origin:
        origins.add(origin)


def _extract_resources_from_html(
    html: str,
    page_url: str,
    resources: DiscoveredResources,
) -> list[str]:
    """Parse HTML and extract resource origins. Returns same-origin links for crawling."""
    soup = BeautifulSoup(html, "html.parser")
    same_origin_links: list[str] = []
    page_parsed = urlparse(page_url)

    # Scripts
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            _add_origin(resources.script_origins, src, page_url)
        elif tag.string and tag.string.strip():
            resources.has_inline_scripts = True

    # Stylesheets
    for tag in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
        href = tag.get("href")
        if href:
            _add_origin(resources.style_origins, href, page_url)

    # Inline styles
    if soup.find_all("style"):
        resources.has_inline_styles = True

    # Inline style attributes
    if soup.find(attrs={"style": True}):
        resources.has_inline_style_attrs = True

    # Images
    for tag in soup.find_all("img"):
        src = tag.get("src")
        if src:
            _add_origin(resources.img_origins, src, page_url)
        srcset = tag.get("srcset")
        if srcset:
            for entry in srcset.split(","):
                src_part = entry.strip().split()[0] if entry.strip() else ""
                if src_part:
                    _add_origin(resources.img_origins, src_part, page_url)

    # Pictures
    for tag in soup.find_all("source"):
        src = tag.get("src") or tag.get("srcset", "").split(",")[0].strip().split()[0]
        parent = tag.parent
        if src and parent:
            if parent.name == "picture":
                _add_origin(resources.img_origins, src, page_url)
            elif parent.name in ("video", "audio"):
                _add_origin(resources.media_origins, src, page_url)

    # Video and audio
    for tag in soup.find_all(["video", "audio"]):
        src = tag.get("src")
        if src:
            _add_origin(resources.media_origins, src, page_url)

    # Fonts (preload)
    for tag in soup.find_all("link", rel=lambda r: r and "preload" in r):
        if tag.get("as") == "font":
            href = tag.get("href")
            if href:
                _add_origin(resources.font_origins, href, page_url)

    # Font stylesheets (e.g., Google Fonts)
    for tag in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
        href = tag.get("href", "")
        if "fonts.googleapis.com" in href:
            _add_origin(resources.style_origins, href, page_url)
            # Google Fonts also serves the actual font files from fonts.gstatic.com
            resources.font_origins.add("https://fonts.gstatic.com")

    # Preconnect hints → connect-src
    for tag in soup.find_all("link", rel=lambda r: r and "preconnect" in r):
        href = tag.get("href")
        if href:
            _add_origin(resources.connect_origins, href, page_url)

    # Iframes and frames
    for tag in soup.find_all(["iframe", "frame"]):
        src = tag.get("src")
        if src:
            _add_origin(resources.frame_origins, src, page_url)

    # Objects and embeds
    for tag in soup.find_all("object"):
        data = tag.get("data")
        if data:
            _add_origin(resources.object_origins, data, page_url)
    for tag in soup.find_all("embed"):
        src = tag.get("src")
        if src:
            _add_origin(resources.object_origins, src, page_url)

    # Forms
    for tag in soup.find_all("form"):
        action = tag.get("action")
        if action:
            _add_origin(resources.form_origins, action, page_url)

    # Manifest
    for tag in soup.find_all("link", rel=lambda r: r and "manifest" in r):
        href = tag.get("href")
        if href:
            _add_origin(resources.manifest_origins, href, page_url)

    # Collect same-origin links for crawling
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        resolved = urljoin(page_url, href)
        link_parsed = urlparse(resolved)
        if (link_parsed.hostname == page_parsed.hostname and
                link_parsed.scheme in ("http", "https")):
            # Normalize: strip fragment, keep path
            clean = f"{link_parsed.scheme}://{link_parsed.hostname}{link_parsed.path}"
            same_origin_links.append(clean)

    return same_origin_links


def discover_resources(
    url: str,
    *,
    depth: int = 0,
    max_pages: int = 50,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> DiscoveredResources:
    """Crawl a website and discover all external resource origins.

    Args:
        url: Starting URL to crawl.
        depth: How many levels of same-origin links to follow (0 = just this page).
        max_pages: Maximum number of pages to crawl.
        timeout: HTTP timeout per request.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        DiscoveredResources with all found origins grouped by CSP directive.
    """
    resources = DiscoveredResources(url=url)
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(url, 0)])

    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        verify=verify_ssl,
        headers={"User-Agent": "csp-toolkit/0.1.0"},
    ) as client:
        while queue and len(visited) < max_pages:
            current_url, current_depth = queue.popleft()

            # Normalize URL for dedup
            normalized = urlparse(current_url)
            norm_key = f"{normalized.scheme}://{normalized.hostname}{normalized.path}"
            if norm_key in visited:
                continue
            visited.add(norm_key)

            try:
                resp = client.get(current_url)
            except (httpx.HTTPError, httpx.TimeoutException):
                continue

            content_type = resp.headers.get("content-type", "")
            if "html" not in content_type.lower():
                continue

            resources.pages_crawled += 1
            page_url = str(resp.url)

            links = _extract_resources_from_html(resp.text, page_url, resources)

            # Queue same-origin links if depth allows
            if current_depth < depth:
                for link in links:
                    queue.append((link, current_depth + 1))

    return resources


def generate_csp(
    resources: DiscoveredResources,
    *,
    nonce: str | None = None,
) -> CSPBuilder:
    """Generate a CSP policy based on discovered resources.

    Returns a CSPBuilder that can output header/nginx/apache/meta formats.
    """
    builder = CSPBuilder()

    # default-src 'none' — restrictive base
    builder.add_directive("default-src", "'none'")

    # script-src
    script_sources = ["'self'"]
    if resources.has_inline_scripts:
        if nonce:
            script_sources.append(f"'nonce-{nonce}'")
        else:
            script_sources.append("'unsafe-inline'")
    script_sources.extend(sorted(resources.script_origins))
    builder.add_directive("script-src", *script_sources)

    # style-src
    style_sources = ["'self'"]
    if resources.has_inline_styles or resources.has_inline_style_attrs:
        if nonce:
            style_sources.append(f"'nonce-{nonce}'")
        else:
            style_sources.append("'unsafe-inline'")
    style_sources.extend(sorted(resources.style_origins))
    builder.add_directive("style-src", *style_sources)

    # img-src
    img_sources = ["'self'"]
    img_sources.extend(sorted(resources.img_origins))
    builder.add_directive("img-src", *img_sources)

    # font-src
    font_sources = ["'self'"]
    font_sources.extend(sorted(resources.font_origins))
    builder.add_directive("font-src", *font_sources)

    # connect-src
    connect_sources = ["'self'"]
    connect_sources.extend(sorted(resources.connect_origins))
    builder.add_directive("connect-src", *connect_sources)

    # media-src (only if media found)
    if resources.media_origins:
        media_sources = ["'self'"]
        media_sources.extend(sorted(resources.media_origins))
        builder.add_directive("media-src", *media_sources)

    # frame-src (only if frames found)
    if resources.frame_origins:
        frame_sources = ["'self'"]
        frame_sources.extend(sorted(resources.frame_origins))
        builder.add_directive("frame-src", *frame_sources)

    # manifest-src (only if manifest found)
    if resources.manifest_origins:
        manifest_sources = ["'self'"]
        manifest_sources.extend(sorted(resources.manifest_origins))
        builder.add_directive("manifest-src", *manifest_sources)

    # object-src — 'none' unless objects were found
    if resources.object_origins:
        obj_sources = ["'self'"]
        obj_sources.extend(sorted(resources.object_origins))
        builder.add_directive("object-src", *obj_sources)
    else:
        builder.add_directive("object-src", "'none'")

    # Security directives
    builder.add_directive("base-uri", "'self'")

    form_sources = ["'self'"]
    form_sources.extend(sorted(resources.form_origins))
    builder.add_directive("form-action", *form_sources)

    builder.add_directive("frame-ancestors", "'none'")

    return builder
