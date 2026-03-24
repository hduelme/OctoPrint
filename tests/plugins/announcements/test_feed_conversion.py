import pytest

from octoprint.plugins.announcements import PLACEHOLDER_IMAGE

SAFE_FEED = """
<rss version="2.0">
    <channel>
        <title>Safe Test Feed</title>
        <description>A safe test feed</description>
        <link>https://example.com/</link>
        <atom:link href="https://example.com/feed.xml" rel="self" type="application/rss+xml"/>
        <pubDate>Tue, 24 Mar 2026 11:46:26 +0000</pubDate>
        <lastBuildDate>Tue, 24 Mar 2026 11:46:26 +0000</lastBuildDate>
        <generator>Something 1.0.0</generator>
        <item>
            <title>Title <strong>with</strong> <em>tags</em>!</title>
            <description>
                <p>Summary with some HTML, e.g. <a href="https://example.com">a link</a>, some <strong>strong</strong> and some <em>em</em> markup and also an image: <img src="image.png" /></p>
            </description>
            <pubDate> Fri, 20 Feb 2026 00:00:00 +0000</pubDate>
            <link>
                https://example.com/link
            </link>
            <guid isPermaLink="true">
                https://example.com/link
            </guid>
            <category>cat1</category>
            <category>cat2</category>
        </item>
    </channel>
</rss>
"""

FEED_TEMPLATE = """
<rss version="2.0">
    <channel>
        <title>Malicious Test Feed</title>
        <description>A malicious test feed</description>
        <link>https://example.com/</link>
        <atom:link href="https://example.com/feed.xml" rel="self" type="application/rss+xml"/>
        <pubDate>Tue, 24 Mar 2026 11:46:26 +0000</pubDate>
        <lastBuildDate>Tue, 24 Mar 2026 11:46:26 +0000</lastBuildDate>
        <generator>Something 1.0.0</generator>
        <item>
            <title>Title</title>
            <description>{description}</description>
            <pubDate> Fri, 20 Feb 2026 00:00:00 +0000</pubDate>
            <link>
                https://example.com/link
            </link>
            <guid isPermaLink="true">
                https://example.com/link
            </guid>
            <category>cat1</category>
            <category>cat2</category>
        </item>
    </channel>
</rss>
"""


def test_to_internal_feed_basic(plugin):
    import feedparser

    feed = feedparser.parse(SAFE_FEED)

    internal = plugin._to_internal_feed(feed)

    assert len(internal) == 1

    entry = internal[0]
    assert entry["title"] == "Title <strong>with</strong> <em>tags</em>!"
    assert entry["title_without_tags"] == "Title with tags!"
    assert (
        entry["summary"]
        == f"""<p>Summary with some HTML, e.g. <a href="https://example.com">a link</a>, some <strong>strong</strong> and some <em>em</em> markup and also an image: <img src="{PLACEHOLDER_IMAGE}" data-src="image.png" /></p>"""
    )
    assert (
        entry["summary_without_images"]
        == """<p>Summary with some HTML, e.g. <a href="https://example.com">a link</a>, some <strong>strong</strong> and some <em>em</em> markup and also an image: </p>"""
    )
    assert entry["link"].startswith(
        "https://example.com/link?utm_source=octoprint&utm_medium=announcements&utm_content="
    )
    assert "published" in entry
    assert entry["read"]


@pytest.mark.parametrize(
    "malicious,expected",
    [
        ("""Test <script>alert(1)</script> 123""", "Test  123"),
        (
            """Test <iframe onload="alert(1)" style="display:none"></iframe> 123""",
            "Test  123",
        ),
        (
            """Test <img src="x" onerror=alert(1)> 123""",
            f"""Test <img src="{PLACEHOLDER_IMAGE}" data-src="x" /> 123""",
        ),
        (
            """Test <img src=x onerror=alert(1)> 123""",
            f"""Test <img src="{PLACEHOLDER_IMAGE}" data-src="x" /> 123""",
        ),
    ],
)
def test_to_internal_feed_sanitization(plugin, malicious, expected):
    import feedparser

    feed = feedparser.parse(FEED_TEMPLATE.format(description=malicious))

    internal = plugin._to_internal_feed(feed)

    assert len(internal) == 1

    entry = internal[0]
    assert entry["summary"] == expected
