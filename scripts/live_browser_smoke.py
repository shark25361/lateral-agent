"""Read-only browser check for the locally running FourCore agent."""

import os
from pathlib import Path
from playwright.sync_api import sync_playwright


base = os.environ.get("LIVE_BROWSER_BASE", "http://127.0.0.1:8080")
assert base in ("http://127.0.0.1:8080", "http://127.0.0.1:8081")
token = os.environ["APP_TOKEN"]
suffix = base.rsplit(":", 1)[-1]
output = Path(os.environ["TEMP"]) / f"fourcore-prodtest-browser-{suffix}.png"
graph_output = Path(os.environ["TEMP"]) / f"fourcore-prodtest-graph-{suffix}.png"

with sync_playwright() as playwright:
    options = {"headless": True}
    for candidate in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if os.path.exists(candidate):
            options["executable_path"] = candidate
            break
    browser = playwright.chromium.launch(**options)
    page = browser.new_page(viewport={"width": 1440, "height": 1080})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(base)
    page.get_by_label("Application access token").fill(token)
    page.get_by_role("button", name="Connect", exact=True).click()
    page.get_by_label("Your request").wait_for(timeout=15000)
    page.get_by_text("Conversation history", exact=True).click()
    page.locator("#chat-history button").first.wait_for(timeout=15000)
    history_count = page.locator("#chat-history button").count()
    page.locator("#chat-history button").first.click()
    page.locator(".message").first.wait_for(timeout=10000)
    page.get_by_role("button", name="View AD evidence graph").first.click()
    page.locator("#graph-panel:not([hidden])").wait_for(timeout=15000)
    graph_nodes = page.locator("#ad-graph .graph-node").count()
    graph_edges = page.locator("#ad-graph .graph-edge").count()
    page.screenshot(path=str(output), full_page=False)
    page.locator("#graph-panel").screenshot(path=str(graph_output))
    assert not errors, errors
    browser.close()
    print(f"PASS: history={history_count} graph_nodes={graph_nodes} graph_edges={graph_edges} screenshot={output} graph_screenshot={graph_output}")
