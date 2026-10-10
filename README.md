
Phishing URL Risk Analyzer

About

Phishing URL Risk Analyzer is a Python-based cybersecurity project that identifies potentially suspicious URL characteristics using heuristic analysis.

Features

- Detects IP-address-based hosts.
- Identifies known URL shorteners.
- Flags URLs containing embedded credentials.
- Checks for suspicious URL structures.
- Generates a risk level with explanations.

Technologies Used

- Python
- Regular Expressions
- "urllib.parse"
- "ipaddress"

How to Run

1. Install Python 3.
2. Clone or download this repository.
3. Open a terminal in the project folder.
4. Run:

python url_analyzer.py

5. Enter a URL to analyze.

Testing

The analyzer was tested with multiple URL patterns to evaluate how it identifies potentially suspicious indicators.

| Test Case            | Example URL                             | Expected Behavior            | Actual Result       |
|----------------------|------------------------------------- ---|------------------------------|---------------------+
| Normal HTTPS website | `https://www.wikipedia.org`             | Few suspicious indicators    |Low Risk             |
| IP-based host        | `http://192.0.2.1/login`                | Flag an IP-based host        |High Risk            |
| Suspicious URL path  | `http://example.com/login               | May flag suspicious keywords | High Risk           |
| Embedded credentials | `http://user:pass@example.com/login     | Flag embedded credential   s | Medium Risk         |
| URL shortener        | `https://bit.ly/example`                | Flag if the domainrecognized | Medium Risk         |

 Limitations

- This tool uses heuristic-based checks to identify potentially suspicious URL patterns.
- A high-risk result does not guarantee that a URL is malicious.
- A low-risk result does not guarantee that a URL is safe.
- The analyzer does not replace professional security tools or a full investigation.

Disclaimer

This project is intended for educational and defensive cybersecurity purposes. It uses heuristic checks and may produce false positives or miss phishing URLs. A low-risk result does not guarantee that a URL is safe. The tool does not visit the submitted URL.

Author

BTech student interested in Cybersecurity and Digital Forensics.
