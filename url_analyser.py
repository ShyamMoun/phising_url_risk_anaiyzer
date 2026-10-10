
import ipaddress
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "account",
    "secure", "update", "password"
}

def analyze_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        return "Invalid", 0, ["URL is empty."]

    candidate = (
        raw_url if "://" in raw_url
        else "https://" + raw_url
    )

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        return "Invalid", 0, ["Malformed URL."]

    if parsed.scheme not in {"http", "https"} or not host:
        return "Invalid", 0, ["Unsupported or malformed URL."]

    host = host.lower()
    score = 0
    findings = []

    if parsed.username or parsed.password:
        score += 3
        findings.append("Credentials embedded in URL.")

    try:
        ipaddress.ip_address(host)
        score += 3
        findings.append("Host is an IP address.")
    except ValueError:
        pass

    if host in SHORTENERS:
        score += 2
        findings.append("URL shortener detected.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        findings.append("Internationalized domain needs review.")

    if host.count(".") >= 3:
        score += 1
        findings.append("Many subdomain levels.")

    if len(raw_url) > 100:
        score += 1
        findings.append("Unusually long URL.")

    if "@" in parsed.netloc:
        score += 2
        findings.append("Authority contains an @ symbol.")

    words_found = SUSPICIOUS_WORDS.intersection(
        set(parsed.path.lower().replace("-", "/").split("/"))
    )

    if words_found:
        score += 1
        findings.append(
            "Sensitive-looking URL path terms: "
            + ", ".join(sorted(words_found))
        )

    if score >= 5:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append("No configured warning indicators found.")

    return risk, score, findings

def main():
    url = input("Enter a URL to analyze: ")
    risk, score, findings = analyze_url(url)

    print("\n--- URL Risk Report ---")
    print("Risk:", risk)
    print("Indicator score:", score)

    for finding in findings:
        print("-", finding)

    print("\nNo connection to the URL was made.")
    print("This heuristic cannot certify a URL as safe.")

if __name__ == "__main__":
    main()
