"""Click through every tab and button of the UI with the fake backend (web/mock.js); fails on any JS error.

    pip install playwright && playwright install chromium
    python -m http.server 8765 --directory web      (in another terminal)
    python tests/test_ui.py
"""
import asyncio
import sys
from playwright.async_api import async_playwright

import os
BASE = os.environ.get("PCSHIELD_UI", "http://localhost:8765/index.html") + "?mock"
CHROME = os.environ.get("CHROME_PATH")  # optional: use an installed Chrome instead of Playwright's
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(("PASS" if cond else "FAIL", name, detail))


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(**({"executable_path": CHROME} if CHROME else {}), args=["--no-sandbox"])
        pg = await b.new_page(viewport={"width": 1400, "height": 900})
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.on("console", lambda m: errs.append("console: " + m.text) if m.type == "error" and "fonts.g" not in m.text and "404" not in m.text else None)

        # --- first launch: welcome theme picker; Done must save a theme
        await pg.goto(BASE); await pg.wait_for_timeout(1300)
        check("welcome shows on first launch", await pg.is_visible("#modal.show"))
        await pg.click("#modal .acts .btn"); await pg.wait_for_timeout(400)
        check("Done saves default theme", await pg.evaluate("window.__savedTheme") == "kara")

        # --- every tab renders with no errors
        for tab in ["Dashboard", "Scanner", "Startup", "Bloatware", "Performance", "Privacy", "Identity", "Shredder", "VPN", "Settings"]:
            await pg.goto(BASE + "&theme=kara"); await pg.wait_for_timeout(500)
            await pg.click(f".tab:has-text('{tab}')"); await pg.wait_for_timeout(1700)
            txt = await pg.inner_text("#main")
            check(f"tab {tab} renders", len(txt) > 40 and "Couldn't" not in txt, txt[:80])

        # --- scanner sub tabs
        await pg.goto(BASE + "&theme=kara"); await pg.wait_for_timeout(500)
        await pg.click(".tab:has-text('Scanner')")
        for sub in ["Results", "Reports", "Scan Scheduler", "Exclusions", "Scan"]:
            await pg.click(f".subtab:has-text('{sub}')"); await pg.wait_for_timeout(700)
            check(f"scanner/{sub} renders", len(await pg.inner_text("#sb")) > 20)

        # --- scheduler shows saved weekday (deep: Days=64 -> Saturday)
        await pg.click(".subtab:has-text('Scan Scheduler')"); await pg.wait_for_timeout(700)
        check("scheduler shows saved day", await pg.eval_on_selector("#dy_deep", "e => e.value") == "SAT")
        check("scheduler daily selected for quick", await pg.eval_on_selector("#fq_quick", "e => e.value") == "daily")
        await pg.click("#sv_deep"); await pg.wait_for_timeout(700)

        # --- results: actions, bulk, apply
        await pg.click(".subtab:has-text('Results')"); await pg.wait_for_timeout(700)
        await pg.select_option("#bulk", "skip"); await pg.wait_for_timeout(200)
        n = await pg.eval_on_selector_all("select.act", "els => els.filter(e => e.value === 'skip').length")
        check("bulk sets waiting items", n >= 3, str(n))
        await pg.click("#apply"); await pg.wait_for_timeout(900)
        check("apply updates statuses", "skipped" in (await pg.inner_text("#sb")).lower())

        # --- apply failure must not leave the button stuck
        await pg.goto(BASE + "&theme=kara&fail"); await pg.wait_for_timeout(500)
        await pg.click(".tab:has-text('Scanner')"); await pg.click(".subtab:has-text('Results')"); await pg.wait_for_timeout(700)
        sels = await pg.query_selector_all("select.act")
        for s in sels:
            opts = await s.eval_on_selector_all("option", "o => o.map(x => x.value)")
            if "skip" in opts:
                await s.select_option("skip"); break
        await pg.click("#apply"); await pg.wait_for_timeout(900)
        check("apply button recovers after error", (await pg.inner_text("#apply")).strip() == "Apply actions"
              and not await pg.eval_on_selector("#apply", "e => e.disabled"))

        # --- scan start shows progress, then results
        await pg.goto(BASE + "&theme=kara"); await pg.wait_for_timeout(500)
        await pg.click(".tab:has-text('Scanner')"); await pg.wait_for_timeout(700)
        await pg.click("#sQuick"); await pg.wait_for_timeout(2500)
        live = await pg.inner_text("#scanLive")
        check("progress shows step/drive/eta", "Step 2 of 3" in live and "left" in live, live[:120])
        check("top chip shows scanning", "Scanning" in await pg.inner_text("#topScan"))
        await pg.wait_for_timeout(9000)
        check("finished scan jumps to results", await pg.is_visible(".subtab.on:has-text('Results')"))

        # --- background (scheduled) scan chip
        await pg.goto(BASE + "&theme=kara&bg"); await pg.wait_for_timeout(1500)
        check("background scan chip", "Scheduled deep scan" in await pg.inner_text("#topScan"))

        # --- privacy protect all
        await pg.click(".tab:has-text('Privacy')"); await pg.wait_for_timeout(700)
        await pg.click("#dall"); await pg.wait_for_timeout(900)
        vals = await pg.eval_on_selector_all("input[data-t]", "els => els.map(e => e.checked)")
        check("protect all turns every switch on", all(vals), str(vals))

        # --- bloatware sequential uninstall
        await pg.click(".tab:has-text('Bloatware')"); await pg.wait_for_timeout(900)
        await pg.click("input[data-i='0']"); await pg.click("input[data-i='2']")
        await pg.click("#un"); await pg.wait_for_timeout(300); await pg.click("#modal .btn.no"); await pg.wait_for_timeout(300)
        check("uninstall shows progress", "1/2" in await pg.inner_text("#un"))
        await pg.wait_for_timeout(2500)

        # --- startup suspicious tooltip
        await pg.click(".tab:has-text('Startup')"); await pg.wait_for_timeout(900)
        title = await pg.get_attribute(".tag.bad[title]", "title")
        check("suspicious tag explains why", bool(title and "Unsigned" in title), str(title))

        # --- shredder add + vpn toggle + identity scan + settings theme change
        await pg.click(".tab:has-text('Shredder')"); await pg.wait_for_timeout(700)
        await pg.click("#af"); await pg.wait_for_timeout(700)
        check("shredder queue", "taxes-2025.pdf" in await pg.inner_text("#q"))
        await pg.click(".tab:has-text('VPN')"); await pg.wait_for_timeout(900)
        await pg.click("#pw"); await pg.wait_for_timeout(2500)
        await pg.click(".tab:has-text('Identity')"); await pg.wait_for_timeout(500)
        await pg.fill("#em", "kara@example.com"); await pg.click("#go"); await pg.wait_for_timeout(1500)
        check("identity results", "Canva" in await pg.inner_text("#res"))
        await pg.fill("#pw", "password"); await pg.click("#pgo"); await pg.wait_for_timeout(600)
        check("password check", "times in leaks" in await pg.inner_text("#pres"))
        await pg.click(".tab:has-text('Settings')"); await pg.wait_for_timeout(900)
        await pg.click("[data-th=dnarte]"); await pg.wait_for_timeout(400)
        check("theme switches", await pg.evaluate("document.documentElement.dataset.theme") == "dnarte")
        await pg.click("#trAdd"); await pg.wait_for_timeout(300)

        check("no JavaScript errors", not errs, "\n".join(errs[:10]))
        await b.close()

asyncio.run(main())
for s, n, d in RESULTS:
    print(f"{s}  {n}" + (f"   [{d}]" if s == "FAIL" and d else ""))
print(f"\n{sum(r[0] == 'PASS' for r in RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(r[0] == "PASS" for r in RESULTS) else 1)
