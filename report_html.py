# report_html.py

from datetime import datetime


def generate_html_report(result, output_path):
    url = result.get("url", "")
    analysis = result.get("analysis", {})
    cookie = analysis.get("cookies", {})
    pre_analysis = analysis.get("pre_consent", {})
    post_analysis = analysis.get("post_consent", {})
    consent_info = analysis.get("consent_action", {})

    site_domain = cookie.get("site_domain", "")
    is_https = cookie.get("is_https", False)
    totals = cookie.get("totals", {})
    categories = cookie.get("categories", {})
    score = cookie.get("score", {})
    per_cookie = cookie.get("cookies", [])

    pre_totals = pre_analysis.get("totals", {})
    post_totals = post_analysis.get("totals", {})

    pre_count = pre_totals.get("count", 0)
    pre_third = pre_totals.get("third_party", 0)
    post_count = post_totals.get("count", 0)
    post_third = post_totals.get("third_party", 0)

    try_consent = consent_info.get("attempted")
    c_clicked = consent_info.get("clicked")

    if try_consent:
        clicked_text = "Yes" if c_clicked else "No"
        c_html = (
            "<p><strong>Consent simulation:</strong> Selected</p>"
            f"<p>Clicked: {clicked_text}</p>"
            f"<p>Pre-consent cookies: {pre_count} total, {pre_third} third-party.<br/>"
            f"Post-consent cookies: {post_count} total, {post_third} third-party.</p>"
        )
    else:
        c_html = "<p><strong>Consent:</strong> Not Selected</p>"

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    title = f"Cookie & Storage Report - {site_domain or url}"

    score_val = score.get("privacy_score")
    grade = score.get("grade", "")
    score_reasons = score.get("reasons", [])

    rows = []
    for entry in per_cookie:
        c_name = entry.get("name", "")
        c_domain = entry.get("domain", "")
        meta = entry.get("analysis", {})
        summary = entry.get("summary", "")

        category = meta.get("category", "unknown")
        first_party = meta.get("first_party")
        is_session = meta.get("is_session_cookie")
        expires_in_days = meta.get("expires_in_days")
        security_flags = meta.get("security_flags", {})
        risk_flags = meta.get("risk_flags", {})

        party_label = "First-party" if first_party else "Third-party"

        if is_session:
            lifetime_label = "Session"
        elif isinstance(expires_in_days, (int, float)):
            lifetime_label = f"{int(expires_in_days)} day(s)"
        else:
            lifetime_label = "Unknown"

        sec_flags_str = (
            f"Secure={security_flags.get('secure')}, "
            f"HttpOnly={security_flags.get('httpOnly')}, "
            f"SameSite={security_flags.get('sameSite')}"
        )

        risk_str = []
        if risk_flags.get("long_lived"):
            risk_str.append("Long-lived")
        if risk_flags.get("non_secure_on_https"):
            risk_str.append("Non-secure on HTTPS")
        if risk_flags.get("javascript_accessible"):
            risk_str.append("Javascript readable")
        risk_label = ", ".join(risk_str) if risk_str else ""

        rows.append(
            "<tr>"
            f"<td>{c_name}</td>"
            f"<td>{c_domain or ''}</td>"
            f"<td>{party_label}</td>"
            f"<td>{category.capitalize()}</td>"
            f"<td>{lifetime_label}</td>"
            f"<td>{sec_flags_str}</td>"
            f"<td>{risk_label}</td>"
            f"<td>{summary}</td>"
            "</tr>"
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='8'>(No cookies found)</td></tr>"

    if score_val is not None:
        score_block = (
            f"<strong>{score_val} /{score.get('max_score', 100)}</strong> "
            f"(grade: {grade})"
        )
    else:
        score_block = "<em>Score not found</em>"

    reasons_html = (
        "<ul>\n" + "\n".join(f"<li>{r}</li>" for r in score_reasons) + "\n</ul>"
        if score_reasons
        else "<p>Recorded reason not found</p>"
    )

    totals_html = (
        "<ul>"
        f"<li>Total cookies: {totals.get('count', 0)}</li>"
        f"<li>First-party: {totals.get('first_party', 0)}</li>"
        f"<li>Third-party: {totals.get('third_party', 0)}</li>"
        f"<li>Session: {totals.get('session', 0)}</li>"
        f"<li>Persistent: {totals.get('persistent', 0)}</li>"
        f"<li>Long-lived [> 180 days]: {totals.get('long_lived', 0)}</li>"
        f"<li>Non-secure with HTTPS: {totals.get('non_secure_on_https', 0)}</li>"
        f"<li>JavaScript readable: {totals.get('javascript_accessible', 0)}</li>"
        "</ul>"
    )

    if categories:
        categories_list = (
            "<ul>"
            + "".join(
                f"<li>{cat.capitalize()}: {count}</li>"
                for cat, count in categories.items()
            )
            + "</ul>"
        )
    else:
        categories_list = "<p>Category breakdown not found</p>"

    with open("templates/cookie_report.html", encoding="utf-8") as f:
        template_text = f.read()

    html_doc = template_text.format(
        TITLE=title,
        URL=url,
        SITE_DOMAIN=site_domain or "(unknown)",
        IS_HTTPS=is_https,
        TIMESTAMP=timestamp,
        SCORE_BLOCK=score_block,
        REASONS_HTML=reasons_html,
        CONSENT_HTML=c_html,
        TOTALS_HTML=totals_html,
        CATEGORIES_LIST=categories_list,
        ROWS_HTML=rows_html,
    )


    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
