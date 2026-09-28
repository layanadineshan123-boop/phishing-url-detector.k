
import streamlit as st
from urllib.parse import urlparse
import ipaddress
import re

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔗"
)

st.title("🔗 Phishing / Malicious Link Detector")
st.write("Check a URL for common phishing indicators.")

url = st.text_input(
    "Enter URL",
    placeholder="https://example.com"
)


def analyze_url(url):
    indicators = []
    score = 0

    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        return ["Invalid URL"], 100

    # 1. HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        indicators.append("Uses HTTP instead of HTTPS")
        score += 20

    # 2. Suspicious words
    suspicious_words = [
        "login", "verify", "secure", "update",
        "account", "password", "signin", "confirm"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        indicators.append(
            "Suspicious words: " + ", ".join(found_words)
        )
        score += 15

    # 3. IP address instead of domain
    try:
        ipaddress.ip_address(domain)
        indicators.append("IP address used instead of a domain name")
        score += 30
    except ValueError:
        pass

    # 4. Too many subdomains
    if len(domain.split(".")) > 3:
        indicators.append("Too many subdomains")
        score += 15

    # 5. @ character
    if "@" in url:
        indicators.append("Suspicious '@' character found")
        score += 25

    # 6. Very long URL
    if len(url) > 100:
        indicators.append("Very long URL")
        score += 15

    score = min(score, 100)

    return indicators, score


if st.button("🔍 Check URL"):

    if not url.strip():
        st.warning("Please enter a URL.")

    else:
        indicators, score = analyze_url(url)

        st.subheader("Analysis Result")

        if score >= 50:
            st.error("🚨 Potentially Suspicious URL")

        elif score >= 25:
            st.warning("⚠️ URL Needs Attention")

        else:
            st.success("✅ No Common Phishing Indicators Detected")

        st.write(f"### Risk Score: {score}/100")

        if indicators:
            st.subheader("Detected Indicators")

            for item in indicators:
                st.write("• " + item)

        else:
            st.info("No common phishing indicators detected.")

        st.caption(
            "This tool checks common URL indicators only. "
            "It does not guarantee that a URL is safe."
        )