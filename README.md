# Cyber URL Risk Analyzer

A defensive cybersecurity portfolio project that analyzes suspicious URLs and explains phishing risk signals in plain language.

## What It Does

- Scores a URL from low to critical risk.
- Flags common phishing indicators such as IP-address hosts, suspicious TLDs, misleading subdomains, excessive URL length, encoded characters, risky keywords, and unusual ports.
- Produces a clear analyst-style finding summary.
- Keeps all analysis local in the browser. No URLs are sent to a server.

## How To Run

Open `index.html` in a browser.

## Good Demo URLs

Try these examples:

```text
https://login.microsoftonline.com/common/oauth2/v2.0/authorize
http://192.168.1.15/paypal/verify-account
https://secure-paypal.com.account-login.example.ru/update?session=123
https://github.com/login
http://example.com:8080/%6c%6f%67%69%6e/free-gift
```

## Why This Is Cybersecurity-Relevant

Phishing triage is a common SOC and security analyst task. This project demonstrates practical knowledge of URL structure, risk indicators, detection logic, explainability, and analyst reporting.

## Project Structure

```text
cyber-url-risk-analyzer/
  index.html
  styles.css
  app.js
  README.md
```

## Notes

This is an educational defensive tool. It should support analyst judgment, not replace enterprise-grade threat intelligence, sandboxing, or email security tooling.
