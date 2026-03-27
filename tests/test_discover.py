"""Tests for resource discovery and CSP auto-generation."""

from csp_toolkit.discover import (
    DiscoveredResources,
    _extract_origin,
    _extract_resources_from_html,
    discover_resources,
    generate_csp,
)
from csp_toolkit.parser import parse


SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <link rel="stylesheet" href="https://cdn.example.com/style.css">
    <link rel="stylesheet" href="/local.css">
    <link rel="preconnect" href="https://api.example.com">
    <link rel="preload" as="font" href="https://fonts.gstatic.com/s/roboto/v30/font.woff2">
    <link rel="manifest" href="/manifest.json">
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://analytics.example.com/track.js"></script>
    <script>console.log("inline");</script>
    <style>.body { color: red; }</style>
</head>
<body>
    <div style="color: blue;">
        <img src="https://images.example.com/photo.jpg">
        <img src="/local-image.png">
        <img srcset="https://images.example.com/small.jpg 300w, https://images.example.com/large.jpg 600w">
        <video src="https://media.example.com/video.mp4"></video>
        <iframe src="https://embed.example.com/widget"></iframe>
        <form action="https://api.example.com/submit">
            <input type="text">
        </form>
        <a href="/about">About</a>
        <a href="https://other.com/page">External</a>
    </div>
</body>
</html>
"""

MINIMAL_HTML = """
<!DOCTYPE html>
<html>
<head><title>Minimal</title></head>
<body><p>Hello</p></body>
</html>
"""

HTML_WITH_DATA_URIS = """
<html>
<body>
    <img src="data:image/png;base64,iVBOR...">
    <script src="data:text/javascript,alert(1)"></script>
</body>
</html>
"""


class TestExtractOrigin:
    def test_external_url(self):
        assert _extract_origin("https://cdn.example.com/app.js", "https://example.com/") == "https://cdn.example.com"

    def test_same_origin_returns_none(self):
        assert _extract_origin("https://example.com/app.js", "https://example.com/") is None

    def test_relative_url_same_origin(self):
        assert _extract_origin("/app.js", "https://example.com/") is None

    def test_protocol_relative(self):
        assert _extract_origin("//cdn.example.com/app.js", "https://example.com/") == "https://cdn.example.com"

    def test_data_uri(self):
        assert _extract_origin("data:image/png;base64,abc", "https://example.com/") == "data:"

    def test_blob_uri(self):
        assert _extract_origin("blob:https://example.com/uuid", "https://example.com/") == "blob:"

    def test_empty_returns_none(self):
        assert _extract_origin("", "https://example.com/") is None

    def test_port_in_origin(self):
        assert _extract_origin("https://api.example.com:8080/path", "https://example.com/") == "https://api.example.com:8080"

    def test_standard_port_omitted(self):
        assert _extract_origin("https://cdn.example.com:443/path", "https://example.com/") == "https://cdn.example.com"


class TestExtractResourcesFromHtml:
    def test_scripts(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://cdn.example.com" in resources.script_origins
        assert "https://analytics.example.com" in resources.script_origins

    def test_inline_scripts_detected(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert resources.has_inline_scripts is True

    def test_stylesheets(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://cdn.example.com" in resources.style_origins

    def test_inline_styles_detected(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert resources.has_inline_styles is True
        assert resources.has_inline_style_attrs is True

    def test_images(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://images.example.com" in resources.img_origins

    def test_srcset(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://images.example.com" in resources.img_origins

    def test_media(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://media.example.com" in resources.media_origins

    def test_fonts(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://fonts.gstatic.com" in resources.font_origins

    def test_frames(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://embed.example.com" in resources.frame_origins

    def test_forms(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://api.example.com" in resources.form_origins

    def test_preconnect(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert "https://api.example.com" in resources.connect_origins

    def test_same_origin_links_returned(self):
        resources = DiscoveredResources(url="https://example.com/")
        links = _extract_resources_from_html(SAMPLE_HTML, "https://example.com/", resources)
        assert any("/about" in link for link in links)
        # External links should NOT be in same-origin list
        assert not any("other.com" in link for link in links)

    def test_minimal_html_no_externals(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(MINIMAL_HTML, "https://example.com/", resources)
        assert resources.script_origins == set()
        assert resources.style_origins == set()
        assert resources.has_inline_scripts is False

    def test_data_uris(self):
        resources = DiscoveredResources(url="https://example.com/")
        _extract_resources_from_html(HTML_WITH_DATA_URIS, "https://example.com/", resources)
        assert "data:" in resources.img_origins
        assert "data:" in resources.script_origins


class TestGenerateCsp:
    def test_basic_generation(self):
        resources = DiscoveredResources(
            url="https://example.com/",
            pages_crawled=1,
            script_origins={"https://cdn.example.com"},
            style_origins={"https://cdn.example.com"},
            img_origins={"https://images.example.com"},
        )
        builder = generate_csp(resources)
        csp = builder.build()
        policy = parse(csp)

        assert policy.has_directive("default-src")
        assert policy.get_directive("default-src").has_source("'none'")
        assert policy.has_directive("script-src")
        assert policy.get_directive("script-src").has_source("'self'")
        assert policy.get_directive("script-src").has_source("https://cdn.example.com")
        assert policy.has_directive("object-src")
        assert policy.get_directive("object-src").has_source("'none'")

    def test_inline_scripts_add_unsafe_inline(self):
        resources = DiscoveredResources(
            url="https://example.com/",
            pages_crawled=1,
            has_inline_scripts=True,
        )
        builder = generate_csp(resources)
        csp = builder.build()
        assert "'unsafe-inline'" in csp

    def test_nonce_instead_of_unsafe_inline(self):
        resources = DiscoveredResources(
            url="https://example.com/",
            pages_crawled=1,
            has_inline_scripts=True,
        )
        builder = generate_csp(resources, nonce="abc123")
        csp = builder.build()
        assert "'nonce-abc123'" in csp
        assert "'unsafe-inline'" not in csp

    def test_media_only_added_if_found(self):
        resources = DiscoveredResources(url="https://example.com/", pages_crawled=1)
        builder = generate_csp(resources)
        csp = builder.build()
        assert "media-src" not in csp

        resources.media_origins.add("https://media.example.com")
        builder = generate_csp(resources)
        csp = builder.build()
        assert "media-src" in csp

    def test_nginx_output(self):
        resources = DiscoveredResources(url="https://example.com/", pages_crawled=1)
        builder = generate_csp(resources)
        nginx = builder.build_nginx()
        assert "add_header Content-Security-Policy" in nginx
        assert "always;" in nginx

    def test_apache_output(self):
        resources = DiscoveredResources(url="https://example.com/", pages_crawled=1)
        builder = generate_csp(resources)
        apache = builder.build_apache()
        assert "Header always set Content-Security-Policy" in apache

    def test_frame_ancestors_set(self):
        resources = DiscoveredResources(url="https://example.com/", pages_crawled=1)
        builder = generate_csp(resources)
        csp = builder.build()
        assert "frame-ancestors 'none'" in csp

    def test_base_uri_set(self):
        resources = DiscoveredResources(url="https://example.com/", pages_crawled=1)
        builder = generate_csp(resources)
        csp = builder.build()
        assert "base-uri 'self'" in csp


class TestDiscoverResources:
    def test_unreachable_url(self):
        resources = discover_resources(
            "https://this-does-not-exist-99999.com",
            timeout=2.0,
        )
        assert resources.pages_crawled == 0

    def test_to_dict(self):
        resources = DiscoveredResources(
            url="https://example.com/",
            pages_crawled=1,
            script_origins={"https://cdn.example.com", "https://analytics.example.com"},
        )
        d = resources.to_dict()
        assert d["url"] == "https://example.com/"
        assert d["pages_crawled"] == 1
        assert "https://analytics.example.com" in d["script_origins"]
        assert "https://cdn.example.com" in d["script_origins"]
