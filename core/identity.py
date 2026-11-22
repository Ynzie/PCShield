"""Digital footprint: email breach lookup (XposedOrNot, free) and password
check (Have I Been Pwned 'Pwned Passwords' k-anonymity - the password never leaves the PC)."""
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .util import save_setting, load_settings, now_iso

UA = {"User-Agent": "PCShield/1.0 (home security app)"}


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace") if e.fp else ""


def check_email(email):
    email = email.strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return {"ok": False, "message": "That doesn't look like an email address."}
    q = urllib.parse.quote(email, safe="")
    try:
        code, body = _get(f"https://api.xposedornot.com/v1/breach-analytics?email={q}")
    except (urllib.error.URLError, TimeoutError) as e:
        return {"ok": False, "message": f"Couldn't reach the breach database: {e}"}
    breaches = []
    if code == 200:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}
        details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
        for b in details:
            breaches.append({
                "name": b.get("breach"), "domain": b.get("domain"), "date": b.get("xposed_date"),
                "records": b.get("xposed_records"), "data": b.get("xposed_data", ""),
                "password_risk": b.get("password_risk"), "industry": b.get("industry"),
                "details": b.get("details", ""), "logo": b.get("logo"),
            })
        risk = ((data.get("BreachMetrics") or {}).get("risk") or [{}])[0]
    elif code == 404:
        risk = {}
    else:
        return {"ok": False, "message": f"Breach database returned an error ({code}). Try again in a minute."}

    exposed = set()
    for b in breaches:
        for item in (b["data"] or "").split(";"):
            if item.strip():
                exposed.add(item.strip())
    result = {"ok": True, "email": email, "checked": now_iso(), "count": len(breaches),
              "breaches": sorted(breaches, key=lambda b: str(b.get("date") or ""), reverse=True),
              "exposed_types": sorted(exposed), "risk_label": risk.get("risk_label"), "risk_score": risk.get("risk_score")}
    save_setting("footprint", {"email": email, "checked": result["checked"], "count": result["count"],
                               "risk_label": result["risk_label"]})
    return result


def last_footprint():
    return load_settings().get("footprint")


def check_password(password):
    if not password:
        return {"ok": False, "message": "Enter a password."}
    h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    try:
        code, body = _get(f"https://api.pwnedpasswords.com/range/{h[:5]}")
    except (urllib.error.URLError, TimeoutError) as e:
        return {"ok": False, "message": f"Couldn't reach the password database: {e}"}
    if code != 200:
        return {"ok": False, "message": f"Password database error ({code})."}
    count = 0
    for line in body.splitlines():
        suffix, _, n = line.partition(":")
        if suffix.strip() == h[5:]:
            count = int(n.strip() or 0)
            break
    return {"ok": True, "count": count}
