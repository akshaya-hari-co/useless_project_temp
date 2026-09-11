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
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.01) 100%);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 20px;
        padding: 28px;
        box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.45), inset 0 1px 0 0 rgba(255, 255, 255, 0.1);
        margin-bottom: 24px;
        transition: transform 0.3s ease;
    }

    .glass-card:hover {
        border-color: rgba(99, 102, 241, 0.3);
        box-shadow: 0 12px 40px 0 rgba(99, 102, 241, 0.15), inset 0 1px 0 0 rgba(255, 255, 255, 0.2);
    }

    /* Title Styling with Neon Glow */
    .title-glow {
        text-shadow: 0 0 20px rgba(99, 102, 241, 0.6);
    }

    /* Input Field Customization */
    .stTextInput input {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        color: #f8fafc !important;
        border-radius: 12px !important;
        padding: 12px 16px !important;
        font-size: 1rem !important;
    }
    
    .stTextInput input:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 15px rgba(99, 102, 241, 0.4) !important;
    }

    /* Metrics Styling */
    [data-testid="stMetricValue"] {
        font-size: 2.2rem !important;
        font-weight: 700 !important;
        background: linear-gradient(90deg, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    /* Progress bar custom styling wrapper */
    [data-testid="stProgressBar"] > div > div > div {
        background-image: linear-gradient(90deg, #6366f1, #a855f7, #ec4899);
        border-radius: 10px;
    }

    /* Hide standard header anchor links */
    .css-1544g2n {visibility: hidden;}
</style>
""", unsafe_allow_html=True)



st.markdown("""
<div class="glass-card" style="text-align: center;">
    <h1 class="title-glow" style="font-weight: 800; letter-spacing: -0.5px; margin-bottom: 8px;">🛡️ Phishguard</h1>
    <p style="color: #94a3b8; font-size: 1.15rem; margin-bottom: 0;">
        Advanced heuristic engine to scan web addresses for hidden phishing threats.
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




url = st.text_input(
    "Enter the URL of the site",
    placeholder="https://example.com/login"
)




if url:

    url_clean = url.strip()

 
    if not url_clean.lower().startswith(("http://", "https://")):
        target_url = "https://" + url_clean
    else:
        target_url = url_clean

    parsed_url = urlparse(target_url)

    domain = parsed_url.hostname or ""
    domain = domain.lower()

    path = parsed_url.path.lower()
    query = parsed_url.query.lower()

    url_lower = target_url.lower()

    risk_score = 0
    warnings = []


    
    if not domain:
        st.error("Invalid URL. Please enter a valid web address.")
        st.stop()


   
    searchable_url = domain + path + query

    found_words = [
        word
        for word in suspicious_words
        if word in searchable_url
    ]

    if found_words:
        risk_score += min(len(found_words) * 10, 30)

        warnings.append(
            "Contains suspicious keywords: **"
            + ", ".join(found_words) + "**"
        )


    
    try:
        ipaddress.ip_address(domain)

        risk_score += 40

        warnings.append(
            "Uses a raw IP address instead of a normal domain name."
        )

    except ValueError:
        pass


    
    if "@" in target_url:
        risk_score += 35

        warnings.append(
            "Contains an '@' symbol, which can hide the real destination."
        )


    

    dot_count = domain.count(".")

    if dot_count > 3:
        risk_score += 20

        warnings.append(
            "URL has an unusually high number of subdomains."
        )


    
    if url_lower.count("http") > 1:
        risk_score += 30

        warnings.append(
            "Multiple 'http' occurrences found in the URL structure."
        )


    
    high_risk_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".work"
    ]

    if any(domain.endswith(tld) for tld in high_risk_tlds):
        risk_score += 20

        warnings.append(
            "Uses a TLD commonly associated with spam or phishing."
        )


    
    if len(url_clean) > 75:
        risk_score += 15

        warnings.append(
            "URL is unusually long (> 75 characters)."
        )


    
    if "xn--" in domain:
        risk_score += 25

        warnings.append(
            "Domain contains Punycode (xn--), which can sometimes "
            "be used in look-alike domains."
        )


   

    if domain.count("-") >= 3:
        risk_score += 10

        warnings.append(
            "Domain contains an unusually high number of hyphens."
        )


   

    if parsed_url.scheme == "http":
        risk_score += 10

        warnings.append(
            "Website uses unencrypted HTTP instead of HTTPS."
        )


    

    final_score = min(risk_score, 100)


   

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown("### 🔎 Analysis Results")

    st.progress(final_score / 100)

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            label="Threat Risk Score",
            value=f"{final_score} / 100"
        )

    with col2:
        st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
        if final_score == 0:
            st.success("🟢 **Verdict: Low Risk / Safe**")
        elif final_score < 50:
            st.warning("🟡 **Verdict: Moderate Risk**")
        else:
            st.error("🔴 **Verdict: High Risk / Phishing Suspect**")

    st.markdown('</div>', unsafe_allow_html=True)


    

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    if warnings:
        st.markdown("### 🚨 Detected Red Flags")
        for warning in warnings:
            st.markdown(f"<p style='margin: 8px 0; color: #cbd5e1;'>⚠️ &nbsp; {warning}</p>", unsafe_allow_html=True)
    else:
        st.markdown("### ✨ Security Status")
        st.info("No common structural phishing patterns or anomalies were identified.")

    st.markdown('</div>', unsafe_allow_html=True)



    st.caption(
        "💡 **Note:** This tool uses heuristic checks and pattern analysis. "
        "It cannot guarantee 100% accuracy on absolute safety status."
    )