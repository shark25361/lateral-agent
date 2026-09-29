"""Browser verification against the Go test fixture only; no real provider calls."""
import os
from pathlib import Path
import sys
import time
from playwright.sync_api import expect, sync_playwright

base = sys.argv[1]
assert base.startswith("http://127.0.0.1:"), "Only the local fixture is permitted"
with sync_playwright() as p:
    options = {"headless": True}
    for candidate in [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"]:
        if os.path.exists(candidate):
            options["executable_path"] = candidate
            break
    browser = p.chromium.launch(**options)
    page = browser.new_page(viewport={"width": 1440, "height": 1080})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base)
    page.get_by_label("Application access token").fill("x" * 32)
    page.get_by_role("button", name="Connect", exact=True).click()
    page.get_by_label("Your request").wait_for()
    page.get_by_role("button", name="View AD evidence graph", exact=True).first.click()
    page.locator("#graph-route strong").filter(has_text="Selected route").wait_for()
    page.get_by_text("member of domain", exact=True).first.wait_for()
    page.get_by_text("Lateral simulation executed", exact=True).wait_for()
    assert page.locator("#ad-graph .graph-node").count() >= 2
    assert page.locator("#ad-graph .graph-edge.selected").count() == 1
    assert page.locator("#ad-graph .graph-edge.status-simulated").count() == 1
    graph_output = Path(__file__).resolve().parent.parent / "data" / "ad-graph-smoke.png"
    graph_output.parent.mkdir(exist_ok=True)
    page.locator("#graph-panel").screenshot(path=str(graph_output))
    page.get_by_role("button", name="Close", exact=True).click()
    page.get_by_label("Your request").fill("Validate T1059 on lab-win")
    page.get_by_role("button", name="Send request").click()
    approve = page.get_by_role("button", name="Authorize and run", exact=True)
    approve.wait_for(timeout=30000)
    assert page.locator("img").count() == 0, "Model text rendered as HTML"
    page.get_by_role("button", name="Run authorization preflight", exact=True).click()
    expect(approve).to_be_enabled(timeout=10000)
    page.on("dialog", lambda d: d.accept())
    approve.click()
    headers = {"Authorization": "Bearer " + "x" * 32}
    deadline = time.monotonic() + 20
    executed_plan = None
    while time.monotonic() < deadline:
        plans = page.request.get(base + "/api/plans", headers=headers).json()
        executed_plan = next((plan for plan in plans if any(item.get("execution_id") == "execution-1" for item in plan.get("items", []))), None)
        if executed_plan and executed_plan["status"] == "completed":
            break
        time.sleep(0.1)
    else:
        raise AssertionError("Mock execution did not complete")
    assert executed_plan["items"][0]["execution_id"] == "execution-1"
    page.get_by_role("button", name="Refresh", exact=True).click()
    page.get_by_text("completed", exact=True).first.wait_for()
    output = Path(__file__).resolve().parent.parent / "data" / "browser-smoke.png"
    output.parent.mkdir(exist_ok=True)
    page.screenshot(path=str(output), full_page=True)
    page.reload()
    page.get_by_label("Application access token").fill("x" * 32)
    page.get_by_role("button", name="Connect", exact=True).click()
    page.locator('.message.user').filter(has_text="Validate T1059 on lab-win").wait_for()
    assert not errors, errors
    browser.close()
    print("PASS: login, AD graph viewer, ADK plan, text rendering, authorization, mock execution, report, session reload")
