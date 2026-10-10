## Testing

The analyzer was tested with multiple URL patterns to evaluate how it identifies potentially suspicious indicators.

CASE 1:
www.google.com 
Expected: Low Risk , Score:0
Result : Low Risk, Indicator Score:0
CASE 2:
http://192.0.2.1/login
Expected: High risk, Score:5
Result: High Rosk,  Indicator Score:5
CASE 3:
https://bit.ly/example
Expected: Medium Risk, Score:2
Result: Medium Risk, Indicator Score:3


### Limitations

- This tool uses heuristic-based checks to identify potentially suspicious URL patterns.
- A high-risk result does not guarantee that a URL is malicious.
- A low-risk result does not guarantee that a URL is safe.
- The analyzer does not replace professional security tools or a full investigation.