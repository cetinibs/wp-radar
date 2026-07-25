<div align="center">

# 🛡️ WP Radar

### All-in-one WordPress security — firewall, malware & integrity scanning, login hardening, and instant alerts.

[![Version](https://img.shields.io/badge/version-2.9.0-2271b1.svg?style=flat-square)](https://github.com/cetinibs/wp-radar/releases)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-21759b.svg?style=flat-square&logo=wordpress&logoColor=white)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.0%2B-777bb4.svg?style=flat-square&logo=php&logoColor=white)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-GPL--2.0-2ea44f.svg?style=flat-square)](LICENSE)

*Tested across 20 live production sites · zero external dependencies for core protection*

</div>

---

WP Radar is a defensive, all-in-one security plugin that hardens WordPress against the attacks sites actually face: automated login brute-forcing, vulnerability probing, malicious uploads, SEO-spam injection, and privilege escalation. It works as an early-stage request firewall, backed by scheduled integrity and malware scans, and tells you the moment something matters — **the site stays open to legitimate visitors worldwide; only attacks and suspicious behaviour are blocked.**

## ✨ Why WP Radar

| | |
|---|---|
| 🔥 **Real firewall** | Request-signature WAF stops injection, traversal, web shells, and bots before WordPress loads |
| 🧠 **Behaviour-based blocking** | Bad IPs are blocked by what they *do*, not where they're from — no geo-walls, no blocked customers |
| 🔐 **Login hardening** | Two-factor auth (TOTP), CAPTCHA, brute-force lockouts, and IP allow/block lists |
| 🧬 **Malware & integrity** | Web-shell detection, WordPress.org checksum verification, and optional VirusTotal / WPScan lookups |
| 📨 **Smart alerts** | Instant, de-duplicated email on critical events — grouped by attack type and IP, so no inbox floods |
| 🪶 **Self-contained** | Core protection needs no paid feeds or external services |

## 🧩 Modules

<details open>
<summary><b>🔐 Authentication & login</b></summary>

- Two-factor authentication (TOTP) — works with Google Authenticator, Authy, Microsoft Authenticator; fully local
- Login CAPTCHA (no third-party service)
- Brute-force protection: per-IP rate limiting and temporary lockouts
- Generic login errors that prevent username enumeration
- Blocks unauthorized administrator creation and role escalation via a trusted-admin allowlist
- Manual IP allowlist (bypasses all blocks) and blocklist — CIDR supported

</details>

<details>
<summary><b>🔥 Network & request firewall</b></summary>

- Request-signature firewall: path traversal, LFI/RFI, SQL injection, web shells, XSS — with multi-pass URL decoding to defeat double-encoding
- Bad-bot & scanner blocking (sqlmap, Nikto, WPScan, Nmap, and more)
- **Behavioural auto-block**: an IP that produces many suspicious events in a short window is temporarily blocked outright — geography-independent; admins and the allowlist are exempt
- Per-IP rate limiting with temporary blocks
- IP-spoofing-resistant client IP detection (configurable proxy/CDN trust)

</details>

<details>
<summary><b>🧬 File, malware & integrity</b></summary>

- Detects web shells and executable files in `uploads/` and the web root (tuned, low false positives)
- Core file-integrity verification against official WordPress.org checksums
- Content-aware change analysis for `.htaccess` / `wp-config.php` (ignores legit host PHP-handler directives)
- Evidence-based detection and removal of SEO-spam / doorway folders
- Disables the dashboard file editor, protects sensitive files, blocks directory listing

</details>

<details>
<summary><b>🛡️ Hardening & reputation</b></summary>

- Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and optional HSTS with preload
- XML-RPC hardening: removes pingback / `system.multicall`, strips `X-Pingback`, optional full block
- Username-enumeration protection across `?author=N`, the REST users endpoint, and the users sitemap
- **VirusTotal** URL/file reputation lookups (70+ engines)
- **WPScan** known-vulnerability scanning of installed plugins, themes, and core

</details>

<details>
<summary><b>📨 Content & notifications</b></summary>

- Front-end spam/malicious link cleaning with a configurable domain blacklist
- Instant email alerts on critical events, multiple recipients
- De-duplicated alerts grouped by event type + attacker IP block, with a one-click test email

</details>

## 🚀 Quick start

1. Download the latest **[`wp-radar.zip`](https://github.com/cetinibs/wp-radar/releases)** (or copy the `wp-radar` folder into `wp-content/plugins/`).
2. In WordPress: **Plugins → Add New → Upload Plugin**, then **Activate**.
3. Open the **WP Radar** menu, review the dashboard, and enable the modules you want.

> 💡 **Tip:** add your own IP to the allowlist before enabling rate limiting or auto-block, and keep a backup admin account before turning on 2FA.

> 📧 **Email on shared hosting:** WordPress `wp_mail()` is often unreliable. If the test email doesn't arrive, configure an SMTP plugin (e.g. *WP Mail SMTP*).

## ⚙️ Configuration

Everything is managed from the **WP Radar** admin page — a card-based dashboard showing active modules, recent critical/warning counts, and last scan time. Toggle protection layers, set the brute-force and rate-limit thresholds, manage the trusted-admin and IP lists, and add optional VirusTotal / WPScan keys. Per-user two-factor setup lives under **WP Radar → 2FA**.

## 🔒 Security & responsible use

WP Radar is a **defensive** tool, intended for sites you own or are authorized to manage. Found a vulnerability in the plugin itself? Please report it privately to the maintainer rather than opening a public issue.

## 📄 License

Distributed under the **GPL-2.0-or-later** license. See [`LICENSE`](LICENSE) for details.

<div align="center">
<sub>Built for real-world WordPress security · See <a href="readme.txt">readme.txt</a> for the full changelog.</sub>
</div>
