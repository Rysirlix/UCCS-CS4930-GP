"""
Core cookie and web storage extraction + basic privacy analysis.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

import undetected_chromedriver as uc


# ----------------- URL & domain helpers -----------------


def _ensure_url_schema(url: str) -> str:
    """
    Normalize a user-provided URL.

    - Strips whitespace
    - Ensures it is not empty
    - Adds "https://" if no scheme is present
    """
    url = url.strip()
    if not url:
        raise ValueError("Empty URL provided.")
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _simple_registrable_domain(hostname: str) -> str:
    """
    Very simple approximation of the 'registrable' domain (eTLD+1).

    For 'www.example.com' -> 'example.com'
    For 'cdn.tracker.example.org' -> 'example.org'

    NOTE: This does NOT handle special TLDs like .co.uk correctly,
    but it's good enough for a classroom tool.
    """
    if not hostname:
        return ""
    host = hostname.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # naive: join last 2 components
    return ".".join(parts[-2:])


# ----------------- Cookie classification helpers -----------------


# Simple pattern-based hints for cookie purpose.
COOKIE_NAME_PATTERNS = [
    # Security / CSRF
    {"substrings": ["csrf", "xsrf"], "category": "security",
     "reason": "Name suggests protection against cross-site request forgery (CSRF)."},

    # Session / auth
    {"substrings": ["sessionid", "sessid", "phpsessid", "jsessionid", "sid", "auth", "token"],
     "category": "essential",
     "reason": "Name suggests a session or authentication identifier to keep you logged in or maintain your session."},

    # Analytics (Google Analytics, Hotjar, etc.)
    {"substrings": ["_ga", "_gid", "_gat", "_gcl", "_ga_", "_hj", "hotjar"],
     "category": "analytics",
     "reason": "Pattern matches common analytics cookies (e.g. Google Analytics, Hotjar)."},

    # Facebook / ads / ad-tech
    {"substrings": ["_fbp", "fr", "adid", "ad_"],
     "category": "advertising",
     "reason": "Pattern matches common advertising or tracking cookies (e.g. Facebook, ad networks)."},

    # Preferences
    {"substrings": ["lang", "locale", "pref", "theme", "consent"],
     "category": "preferences",
     "reason": "Name suggests storing language, theme, consent, or other user preferences."},
]



CATEGORY_DESCRIPTIONS = {
    "essential": "Likely needed for the basic operation of the site (for example, keeping you logged in or remembering your cart).",
    "analytics": "Likely used to measure how people use the site (pages visited, clicks, etc.) so the owner can improve it.",
    "advertising": "Likely used to show personalized ads or track you across sites for marketing purposes.",
    "preferences": "Likely used to remember choices you make, such as language, layout, or other settings.",
    "security": "Likely used to improve security, for example by preventing malicious requests.",
    "unknown": "The exact purpose is not clear from the name alone.",
}

def _try_click_consent(driver, timeout=6):
    tried = []
    clicked = False
    clicked_selector = None
    clicked_xpath = None
    error = None

    start = time.time()
    deadline = start + max(timeout, 1)

    text_patterns = [
        "accept all cookies",
        "accept all",
        "accept",
        "i agree",
        "i accept",
        "agree",
        "allow all",
        "allow cookies",
        "ok",
        "got it",
    ]

    xpaths = []

    for t in text_patterns:
        xpaths.append(
            (
                f"//button[contains(translate(normalize-space(.),"
                f" 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{t}')]"
            )
        )
        xpaths.append(
            (
                f"//a[contains(translate(normalize-space(.),"
                f" 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{t}')]"
            )
        )

    def find_click_target_in_context(context):
        for xp in xpaths:
            tried.append(f"{context}:xpath:{xp}")
            try:
                elems = driver.find_elements(By.XPATH, xp)
            except Exception:
                continue

            for i in elems:
                try:
                    if i.is_displayed() and i.is_enabled():
                        return i, xp
                except Exception:
                    continue
        return None

    try:
        while time.time() < deadline and not clicked:
            try:
                driver.switch_to.default_content()
            except Exception:
                pass

            if time.time() >= deadline:
                break

            target = find_click_target_in_context("main")
            if target is not None:
                i, xp = target
                try:
                    i.click()
                    clicked = True
                    clicked_xpath = xp
                    break
                except Exception:
                    pass

            try:
                iframes = driver.find_elements(By.TAG_NAME, "iframe")
            except Exception:
                iframes = []

            for idx, frame in enumerate(iframes):
                if time.time() >= deadline or clicked:
                    break
                try:
                    driver.switch_to.default_content()
                    driver.switch_to.frame(frame)
                except Exception:
                    continue

                target = find_click_target_in_context(f"iframe[{idx}]")
                if target is not None:
                    i, xp = target
                    try:
                        i.click()
                        clicked = True
                        clicked_xpath = xp
                        break
                    except Exception:
                        continue

            if not clicked:
                time.sleep(0.5)

        try:
            driver.switch_to.default_content()
        except Exception:
            pass

    except Exception as e:
        error = str(e)

    return {
        "attempted": True,
        "clicked": clicked,
        "clicked_css": clicked_selector,
        "clicked_xpath": clicked_xpath,
        "methods_tried": tried,
        "error": error,
    }

def _classify_cookie(
    cookie: Dict[str, Any],
    site_domain: str,
    is_https: bool,
    now_ts: float,
) -> Dict[str, Any]:
    name = str(cookie.get("name", "")).lower()
    cookie_domain = str(cookie.get("domain", "")).lstrip(".").lower()
    cookie_reg_domain = _simple_registrable_domain(cookie_domain)
    site_reg_domain = _simple_registrable_domain(site_domain)

    first_party = cookie_reg_domain and site_reg_domain and (cookie_reg_domain == site_reg_domain)

    # Expiry & session-ness
    expiry_ts = cookie.get("expiry")
    if isinstance(expiry_ts, (int, float)):
        expires_in_seconds = expiry_ts - now_ts
        expires_in_days = expires_in_seconds / 86400.0
        is_session_cookie = False
    else:
        expires_in_days = None
        is_session_cookie = True

    # --- 1) Try name-based classification first ---
    category = "unknown"
    reason = None
    for pattern in COOKIE_NAME_PATTERNS:
        if any(sub in name for sub in pattern["substrings"]):
            category = pattern["category"]
            reason = pattern["reason"]
            break

    # --- 2) If still unknown, use behavioral heuristics ---
    # Use first/third-party + lifetime to guess.
    # This is where most cookies will get a useful category.
    if category == "unknown":
        if not first_party:
            # Third-party cookie
            if expires_in_days is not None and expires_in_days > 30:
                category = "advertising"
                reason = (
                    "Third-party cookie that lasts a long time; "
                    "these are often used for cross-site tracking or advertising."
                )
            else:
                category = "analytics"
                reason = (
                    "Third-party cookie used during your visit; "
                    "these are often used for analytics or embedded third-party services."
                )
        else:
            # First-party cookie
            if is_session_cookie:
                category = "essential"
                reason = (
                    "First-party session cookie; "
                    "likely needed to keep you logged in or keep the site working during your visit."
                )
            else:
                if expires_in_days is not None and expires_in_days > 60:
                    category = "preferences"
                    reason = (
                        "First-party long-lived cookie; "
                        "often used to remember settings or personalization between visits."
                    )
                else:
                    category = "analytics"
                    reason = (
                        "First-party cookie with a limited lifetime; "
                        "often used to understand how the site is used or to measure basic usage."
                    )

    if reason is None:
        reason = (
            "No strong hints from the name; this is an educated guess "
            "based on who sets it and how long it lasts."
        )

    secure_flag = bool(cookie.get("secure"))
    http_only = bool(cookie.get("httpOnly"))
    same_site = cookie.get("sameSite")

    non_secure_on_https = bool(is_https and not secure_flag)
    javascript_accessible = not http_only
    long_lived = bool(expires_in_days is not None and expires_in_days > 180)

    security_flags = {
        "secure": secure_flag,
        "httpOnly": http_only,
        "sameSite": same_site,
    }
    risk_flags = {
        "non_secure_on_https": non_secure_on_https,
        "javascript_accessible": javascript_accessible,
        "long_lived": long_lived,
    }

    return {
        "first_party": first_party,
        "category": category,
        "reason": reason,
        "is_session_cookie": is_session_cookie,
        "expires_in_days": expires_in_days,
        "security_flags": security_flags,
        "risk_flags": risk_flags,
    }

def _cookie_human_summary(
    cookie: Dict[str, Any],
    meta: Dict[str, Any],
) -> str:
    """
    Produce a short human-readable explanation of what the cookie likely does,
    using simple language.
    """
    name = cookie.get("name", "<unnamed>")
    category = meta.get("category", "unknown")
    cat_desc = CATEGORY_DESCRIPTIONS.get(category, CATEGORY_DESCRIPTIONS["unknown"])

    first_party = meta.get("first_party")
    is_session_cookie = meta.get("is_session_cookie")
    expires_in_days = meta.get("expires_in_days")
    security_flags = meta.get("security_flags", {})
    risk_flags = meta.get("risk_flags", {})

    # Who sets it?
    if first_party is True:
        party = "set by this site (first-party)."
    elif first_party is False:
        party = "set by a different site (third-party)."
    else:
        party = "source is unclear."

    # Lifetime
    if is_session_cookie:
        lifetime = "It only lasts until you close your browser."
    elif isinstance(expires_in_days, (int, float)):
        if expires_in_days <= 1:
            lifetime = "It expires in about a day."
        elif expires_in_days <= 30:
            lifetime = f"It expires in about {int(expires_in_days)} days."
        elif expires_in_days <= 365:
            lifetime = f"It expires in about {int(expires_in_days / 30)} months."
        else:
            lifetime = "It expires in more than a year."
    else:
        lifetime = "Its lifetime is not clearly specified."

    # Security flags (simplified)
    parts = []
    if security_flags.get("secure"):
        parts.append("is only sent over secure (HTTPS) connections")
    else:
        parts.append("can be sent over non-secure connections")
    if security_flags.get("httpOnly"):
        parts.append("cannot be read by JavaScript on the page")
    else:
        parts.append("can be read by JavaScript on the page")

    security_sentence = "It " + " and ".join(parts) + "."

    # Risk hints
    risk_notes = []
    if risk_flags.get("long_lived"):
        risk_notes.append("It is long-lived, which can make tracking easier over time.")
    if risk_flags.get("non_secure_on_https"):
        risk_notes.append("It is not marked as 'secure' even though the site uses HTTPS.")
    if risk_flags.get("javascript_accessible"):
        risk_notes.append("Because it is readable by JavaScript, it could be accessed by scripts running on the page.")

    risk_sentence = " ".join(risk_notes) if risk_notes else ""

    return (
        f"Cookie '{name}' is {party} "
        f"It appears to be used for: {cat_desc} "
        f"{lifetime} {security_sentence} {risk_sentence}"
    ).strip()

def _compute_privacy_score(totals, categories_count):
    score = 100
    reasons = []

    third_party = totals.get("third_party", 0)
    long_lived = totals.get("long_lived", 0)
    non_secure = totals.get("non_secure_on_https", 0)
    js_readable = totals.get("javascript_accessible", 0)
    advertising = categories_count.get("advertising", 0)

    if third_party > 0:
        penalty = min(30, 3 * third_party)
        score -= penalty
        reasons.append(
            f"{third_party} cookie/s are third-party"
            f"(−{penalty} points)."
        )

    if long_lived > 0:
        penalty = min(24, 4 * long_lived)
        score -= penalty
        reasons.append(
            f"{long_lived} cookie/s last longer than 6 months"
            f"(−{penalty} points)."
        )

    if non_secure > 0:
        penalty = min(25, 5 * non_secure)
        score -= penalty
        reasons.append(
            f"{non_secure} cookie/s not marked 'Secure' even though site uses HTTPS"
            f"(−{penalty} points)."
        )

    if js_readable > 0:
        penalty = min(10, 1 * js_readable)
        score -= penalty
        reasons.append(
            f"{js_readable} cookie/s can be read by JavaScript"
            f"(−{penalty} points)."
        )

    if advertising > 0:
        score -= 10
        reasons.append("cookie/s categorized as advertising (−10 points).")

    if score < 0:
        score = 0
    if score > 100:
        score = 100
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    if not reasons:
        reasons.append("No cookie-related risk factors detected.")

    return {
        "privacy_score": score,
        "max_score": 100,
        "grade": grade,
        "reasons": reasons,
    }

def _analyze_cookies(
    cookies: List[Dict[str, Any]],
    final_url: str,
) -> Dict[str, Any]:
    """
    Build a privacy-oriented analysis section for the list of cookies.
    """
    parsed = urlparse(final_url)
    site_domain = parsed.hostname or ""
    is_https = parsed.scheme.lower() == "https"
    now_ts = time.time()

    per_cookie = []
    totals = {
        "count": len(cookies),
        "first_party": 0,
        "third_party": 0,
        "session": 0,
        "persistent": 0,
        "long_lived": 0,
        "non_secure_on_https": 0,
        "javascript_accessible": 0,
    }
    categories_count = {
        "essential": 0,
        "analytics": 0,
        "advertising": 0,
        "preferences": 0,
        "security": 0,
        "unknown": 0,
    }

    for c in cookies:
        meta = _classify_cookie(c, site_domain=site_domain, is_https=is_https, now_ts=now_ts)
        summary = _cookie_human_summary(c, meta)

        # Update totals
        if meta["first_party"]:
            totals["first_party"] += 1
        else:
            totals["third_party"] += 1

        if meta["is_session_cookie"]:
            totals["session"] += 1
        else:
            totals["persistent"] += 1

        if meta["risk_flags"]["long_lived"]:
            totals["long_lived"] += 1
        if meta["risk_flags"]["non_secure_on_https"]:
            totals["non_secure_on_https"] += 1
        if meta["risk_flags"]["javascript_accessible"]:
            totals["javascript_accessible"] += 1

        cat = meta["category"]
        if cat not in categories_count:
            categories_count[cat] = 0
        categories_count[cat] += 1

        per_cookie.append({
            "name": c.get("name"),
            "domain": c.get("domain"),
            "analysis": meta,
            "summary": summary,
        })

    score_block = _compute_privacy_score(totals, categories_count)

    return {
        "site_domain": site_domain,
        "is_https": is_https,
        "totals": totals,
        "categories": categories_count,
        "score": score_block,
        "cookies": per_cookie,
    }


# ----------------- Main extraction function -----------------


def extract_cookies_and_storage(
    url: str,
    headless: bool = True,
    wait_time: int = 8,
    include_analysis: bool = True,
    try_consent: bool = False,
) -> Dict[str, Any]:
    """
    Navigate to a URL using undetected-chromedriver and extract:

    - HTTP cookies (via Selenium's ``get_cookies``)
    - ``window.localStorage``
    - ``window.sessionStorage``
    - (optionally) a privacy-oriented analysis section

    Returns a dict with keys:
      - success, url, http_cookies, local_storage, session_storage, counts
      - analysis (if include_analysis=True)
    """
    url = _ensure_url_schema(url)
    driver = None

    options = uc.ChromeOptions()
    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
    else:
        options.add_argument("--window-position=-2400,-2400")

    try:
        driver = uc.Chrome(options=options)
        if not headless:
            try:
                driver.minimize_window()
            except Exception:
                pass

        driver.get(url)
        time.sleep(max(1, int(wait_time)))

        final_url = driver.current_url or url

        pre_cookies = driver.get_cookies() or []

        consent_info = {
            "attempted": False,
            "clicked": False,
            "clicked_css": None,
            "clicked_xpath": None,
            "methods_tried": [],
            "error": None,
        }

        if try_consent:
            try:
                driver.execute_script(
                    "window.scrollTo(0, document.body.scrollHeight / 3);"
                )
            except Exception:
                pass

            consent_info = _try_click_consent(driver)
            time.sleep(3)

        post_cookies = driver.get_cookies() or []
        if not post_cookies:
            post_cookies = pre_cookies

        http_cookies = post_cookies

        # localStorage
        try:
            raw_local = driver.execute_script("return JSON.stringify(window.localStorage);")
            local_storage = json.loads(raw_local) if raw_local else {}
        except Exception:
            try:
                local_storage = driver.execute_script(
                    """
                    var items = {};
                    for (var i = 0; i < localStorage.length; i++) {
                        var k = localStorage.key(i);
                        items[k] = localStorage.getItem(k);
                    }
                    return items;
                    """
                ) or {}
            except Exception:
                local_storage = {}

        # sessionStorage
        try:
            raw_session = driver.execute_script("return JSON.stringify(window.sessionStorage);")
            session_storage = json.loads(raw_session) if raw_session else {}
        except Exception:
            try:
                session_storage = driver.execute_script(
                    """
                    var items = {};
                    for (var i = 0; i < sessionStorage.length; i++) {
                        var k = sessionStorage.key(i);
                        items[k] = sessionStorage.getItem(k);
                    }
                    return items;
                    """
                ) or {}
            except Exception:
                session_storage = {}

        result: Dict[str, Any] = {
            "success": True,
            "url": final_url,
            "http_cookies": http_cookies,
            "local_storage": local_storage,
            "session_storage": session_storage,
            "counts": {
                "http_cookies": len(http_cookies),
                "local_storage": len(local_storage),
                "session_storage": len(session_storage),
                "total": len(http_cookies) + len(local_storage) + len(session_storage),
            },
        }

        if include_analysis:
            pre_analysis = _analyze_cookies(pre_cookies, final_url)
            post_analysis = _analyze_cookies(http_cookies, final_url)

            result["analysis"] = {
                "cookies": _analyze_cookies(http_cookies, final_url),
                "pre_consent": pre_analysis,
                "post_consent": post_analysis,
                "consent_action": consent_info,
                # In the future you could also add storage-specific analysis here.
            }

        return result
    except Exception as e:
        return {"success": False, "error": str(e), "error_type": type(e).__name__}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
