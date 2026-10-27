# SSL/TLS Certificate & Protocol Auditor

A lightweight Python tool designed to inspect server SSL/TLS certificates, assess expiration risks, and detect deprecated encryption protocols (TLS 1.0 & 1.1).

## Key Features
- **Certificate Lifecycle Inspection:** Extracts certificate validity, expiration timeframe, issuer organization, and active cipher suites.
- **Expiration Alerts:** Highlights certificates expiring in less than 30 days.
- **Protocol Security Auditing:** Probes target hosts for deprecated TLS versions (TLS 1.0 and 1.1) to align with modern cryptographic standards.
- **Minimal Dependencies:** Implemented primarily using Python's native `ssl` and `socket` modules.

## Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/ssl-tls-auditor.git
   cd ssl-tls-auditor