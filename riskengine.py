def calculate_risk(score):

score = max(
    0,
    min(score, 100)
)

if score >= 75:
    return "Critical"

if score >= 50:
    return "High"

if score >= 25:
    return "Medium"

return "Low"
10. analyzers/url_analyzer.py
analyzers/url_analyzer.py


import ipaddress

from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
"login",
"signin",
"verify",
"verification",
"password",
"account",
"secure",
"update",
"confirm",
"wallet",
"bank"
}

SHORTENERS = {
"bit.ly",
"tinyurl.com",
"t.co",
"goo.gl",
"is.gd"
}

def is_ip(host):

try:

    ipaddress.ip_address(host)

    return True

except ValueError:

    return False
def analyze_url(url):

findings = []

score = 0

url = url.strip()

if not url.startswith(
    ("http://", "https://")
):

    url = "http://" + url

parsed = urlparse(url)

hostname = parsed.hostname or ""

if not hostname:

    return {
        "url": url,
        "hostname": "",
        "score": 100,
        "findings": [
            "Invalid URL."
        ]
    }

if parsed.scheme == "http":

    findings.append(
        "URL does not use HTTPS."
    )

    score += 15

if is_ip(hostname):

    findings.append(
        "URL uses an IP address."
    )

    score += 25

combined = (
    hostname
    + " "
    + parsed.path
    + " "
    + parsed.query
).lower()

matched = []

for word in SUSPICIOUS_WORDS:

    if word in combined:
        matched.append(word)

if matched:

    findings.append(
        "Potentially sensitive keywords: "
        + ", ".join(matched)
    )

    score += min(
        len(matched) * 7,
        30
    )

if "@" in url:

    findings.append(
        "URL contains @ character."
    )

    score += 25

if len(url) > 150:

    findings.append(
        "URL is unusually long."
    )

    score += 10

if hostname.count(".") >= 4:

    findings.append(
        "Hostname contains many subdomains."
    )

    score += 15

if hostname.lower() in SHORTENERS:

    findings.append(
        "URL uses a shortening service."
    )

    score += 10

if not findings:

    findings.append(
        "No basic suspicious indicators detected."
    )

return {
    "url": url,
    "hostname": hostname,
    "score": min(score, 100),
    "findings": findings
}
