import ipaddress
import re
from urllib.parse import urlparse

import streamlit as st


st.set_page_config(
    page_title="Phishguard",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>
    /* Global App Background & Font Styling */
    .stApp {
        background: radial-gradient(circle at 50% 10%, #1e1b4b 0%, #0f172a 50%, #05050a 100%);
        color: #f8fafc;
        font-family: 'Inter', sans-serif;
    }

    /* Enhanced Vibrant Glassmorphism Container */
    .glass-card {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.04) 0%, rgba(255, 255, 255, 0.01) 100%);
        backdrop-filter: blur(24px);
        -webkit-backdrop-filter: blur(24px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 20px;
        padding: 30px;
        box-shadow: 0 16px 48px 0 rgba(0, 0, 0, 0.5), inset 0 1px 0 0 rgba(255, 255, 255, 0.1);
        margin-bottom: 24px;
        transition: all 0.3s ease;
    }

    .glass-card:hover {
        border-color: rgba(99, 102, 241, 0.3);
        box-shadow: 0 16px 48px 0 rgba(99, 102, 241, 0.15), inset 0 1px 0 0 rgba(255, 255, 255, 0.15);
    }

    /* Title Styling with Neon Glow */
    .title-glow {
        text-shadow: 0 0 25px rgba(99, 102, 241, 0.7);
    }

    /* Input Field Customization */
    .stTextInput input {
        background: rgba(15, 23, 42, 0.7) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        color: #f8fafc !important;
        border-radius: 14px !important;
        padding: 14px 18px !important;
        font-size: 1.05rem !important;
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    .stTextInput input:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 20px rgba(99, 102, 241, 0.4), inset 0 2px 4px rgba(0, 0, 0, 0.2) !important;
    }

    /* Metrics Styling */
    [data-testid="stMetricValue"] {
        font-size: 2.4rem !important;
        font-weight: 800 !important;
        background: linear-gradient(90deg, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    /* Progress bar custom styling wrapper */
    [data-testid="stProgressBar"] > div > div > div {
        background-image: linear-gradient(90deg, #6366f1, #a855f7, #ec4899);
        border-radius: 12px;
        height: 10px !important;
    }

    /* Custom Glass Badges for Verdicts */
    .badge-safe {
        background: rgba(16, 185, 129, 0.12);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 10px 20px;
        border-radius: 30px;
        font-weight: 600;
        display: inline-block;
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.1);
    }
    
    .badge-warning {
        background: rgba(245, 158, 11, 0.12);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.3);
        padding: 10px 20px;
        border-radius: 30px;
        font-weight: 600;
        display: inline-block;
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.1);
    }
    
    .badge-danger {
        background: rgba(239, 68, 68, 0.12);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 10px 20px;
        border-radius: 30px;
        font-weight: 600;
        display: inline-block;
        box-shadow: 0 4px 12px rgba(239, 68, 68, 0.1);
    }

    /* Micro Warning Cards */
    .warning-card {
        background: rgba(255, 255, 255, 0.02);
        border-left: 4px solid #f43f5e;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        border-right: 1px solid rgba(255, 255, 255, 0.05);
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        padding: 12px 16px;
        border-radius: 0 12px 12px 0;
        margin-bottom: 12px;
        color: #cbd5e1;
        font-size: 0.95rem;
    }

    /* Hide standard header anchor links */
    .css-1544g2n {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# Header Title Component
# --------------------------------------------------

st.markdown("""
<div class="glass-card" style="text-align: center;">
    <h1 class="title-glow" style="font-weight: 800; letter-spacing: -0.5px; margin-bottom: 10px; font-size: 2.5rem;">🛡️ Phishguard</h1>
    <p style="color: #94a3b8; font-size: 1.15rem; margin-bottom: 0; font-weight: 400;">
        Advanced heuristic intelligence engine to scan web addresses for hidden phishing indicators.
    </p>
</div>
""", unsafe_allow_html=True)


suspicious_words = [
    "login",
    "verify",
    "banking",
    "update",
    "secure",
    "free",
    "gift",
    "bonus",
    "account",
    "pay"
]


# --------------------------------------------------
# Input Component
# --------------------------------------------------

url = st.text_input(
    "Enter the URL of the site",
    placeholder="https://example.com/login"
)


# --------------------------------------------------
# Analysis Engine
# --------------------------------------------------

if url:
    url_clean = url.strip()

    if not url_clean.lower().startswith(("http://", "https://")):
        target_url = "https://" + url_clean
    else:
        target_url = url_clean

    parsed_url = urlparse(target_url)
    domain = (parsed_url.hostname or "").lower()
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    url_lower = target_url.lower()

    risk_score = 0
    warnings = []

    if not domain:
        st.error("Invalid URL. Please enter a valid web address.")
        st.stop()

    # 1. Suspicious keywords
    searchable_url = domain + path + query
    found_words = [w for w in suspicious_words if w in searchable_url]
    if found_words:
        risk_score += min(len(found_words) * 10, 30)
        warnings.append(f"Contains suspicious keywords: **{', '.join(found_words)}**")

    # 2. IP address instead of domain
    try:
        ipaddress.ip_address(domain)
        risk_score += 40
        warnings.append("Uses a raw IP address instead of a standard domain name.")
    except ValueError:
        pass

    # 3. @ symbol
    if "@" in target_url:
        risk_score += 35
        warnings.append("Contains an '@' symbol, which can mask the true destination.")

    # 4. Too many subdomains
    if domain.count(".") > 3:
        risk_score += 20
        warnings.append("URL contains an unusually high number of subdomains.")

    # 5. Multiple HTTP occurrences
    if url_lower.count("http") > 1:
        risk_score += 30
        warnings.append("Multiple 'http' occurrences detected in structure.")

    # 6. Suspicious TLD
    high_risk_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]
    if any(domain.endswith(tld) for tld in high_risk_tlds):
        risk_score += 20
        warnings.append("Uses a TLD frequently associated with spam or phishing.")

    # 7. URL length
    if len(url_clean) > 75:
        risk_score += 15
        warnings.append("URL length exceeds normal structural parameters (> 75 chars).")

    # 8. Punycode / IDN
    if "xn--" in domain:
        risk_score += 25
        warnings.append("Domain utilizes Punycode (xn--), a vector for look-alike attacks.")

    # 9. Excessive hyphens
    if domain.count("-") >= 3:
        risk_score += 10
        warnings.append("Domain contains an excessive number of hyphens.")

    # 10. Non-HTTPS
    if parsed_url.scheme == "http":
        risk_score += 10
        warnings.append("Connection uses unencrypted HTTP instead of secure HTTPS.")

    final_score = min(risk_score, 100)

    # --------------------------------------------------
    # Results Presentation Card
    # --------------------------------------------------

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown("### 🔎 Threat Assessment Results")
    st.markdown("<div style='margin-bottom: 15px;'></div>", unsafe_allow_html=True)

    st.progress(final_score / 100)
    st.markdown("<div style='margin-bottom: 10px;'></div>", unsafe_allow_html=True)

    col1, col2 = st.columns([1.1, 1.9])

    with col1:
        st.metric(
            label="Calculated Risk Score",
            value=f"{final_score} / 100"
        )

    with col2:
        st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)
        if final_score == 0:
            st.markdown('<div class="badge-safe">🟢 Low Risk / Likely Safe</div>', unsafe_allow_html=True)
        elif final_score < 50:
            st.markdown('<div class="badge-warning">🟡 Moderate Risk Detected</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="badge-danger">🔴 High Risk / Phishing Suspect</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # --------------------------------------------------
    # Warnings Card
    # --------------------------------------------------

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    if warnings:
        st.markdown("### 🚨 Detected Anomalies & Red Flags")
        st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)
        for warning in warnings:
            st.markdown(f'<div class="warning-card">⚠️ &nbsp; {warning}</div>', unsafe_allow_html=True)
    else:
        st.markdown("### ✨ Security Status")
        st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)
        st.info("No structural threat indicators or common phishing fingerprints were identified.")

    st.markdown('</div>', unsafe_allow_html=True)

    st.caption(
        "💡 **Disclaimer:** This tool relies on heuristic matching models. "
        "Always exercise manual caution when interacting with unfamiliar links."
    )