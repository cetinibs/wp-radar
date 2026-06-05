# WP Radar

**Comprehensive security radar for WordPress** — brute-force and login protection, exploit and bot blocking, malware and file-integrity scanning, server hardening, and instant email alerts for critical events.

<p>
  <img alt="Version" src="https://img.shields.io/badge/version-2.2.1-blue.svg">
  <img alt="WordPress" src="https://img.shields.io/badge/WordPress-5.0%2B-21759b.svg">
  <img alt="PHP" src="https://img.shields.io/badge/PHP-7.0%2B-777bb4.svg">
  <img alt="License" src="https://img.shields.io/badge/license-GPL--2.0--or--later-green.svg">
</p>

---

## Overview

WP Radar is a defensive, all-in-one security plugin that hardens a WordPress site against the most common real-world attacks: automated login brute-forcing, vulnerability probing, malicious file uploads, SEO-spam injection, and unauthorized privilege escalation. It runs as an early-stage request filter combined with scheduled file and integrity scans, and notifies administrators the moment a critical event is detected.

## Features

### Authentication & login security
- Blocks unauthorized administrator creation and role escalation via a trusted-admin allowlist
- Brute-force protection with per-IP rate limiting and temporary lockouts
- Generic login errors that prevent username enumeration

### Network & request security
- Request-signature firewall for path traversal, LFI/RFI, SQL injection, web shells, and XSS
- Bad-bot and scanner blocking (sqlmap, Nikto, WPScan, Nmap, and more)
- XML-RPC hardening: removes pingback / `system.multicall` methods, strips the `X-Pingback` header, with an optional full block
- Username-enumeration protection across `?author=N`, the REST users endpoint, and the users sitemap
- Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and optional HSTS with preload

### File & system security
- Detects web shells and executable files in `uploads/` and the web root, with tuned, low-false-positive heuristics
- Identifies and (evidence-based) auto-removes SEO-spam / doorway folders in the document root
- Core file-integrity verification against official WordPress.org checksums
- Disables the in-dashboard file editor (`DISALLOW_FILE_EDIT`), protects sensitive files, and prevents directory listing via `.htaccess`

### Content security
- Cleans spam and malicious links on the front end, with a configurable domain blacklist

### Notifications
- Instant email alerts on critical events
- Multiple recipients
- De-duplicated alerts grouped by event type and attacker IP block (/24) to prevent inbox flooding during an attack
- One-click test email to verify delivery

## Installation

1. Download this repository as a ZIP, or copy the `wp-radar` directory into `wp-content/plugins/`.
2. In the WordPress dashboard, go to **Plugins** and activate **WP Radar**.
3. Open the **WP Radar** menu to configure protection modules and notification recipients.

> **Email delivery on shared hosting:** WordPress `wp_mail()` is often unreliable on shared hosts. If the test email does not arrive, configure an SMTP plugin (for example, *WP Mail SMTP*).

## Configuration

All modules are managed from the **WP Radar** admin page. Key settings include the login lockout threshold and duration, the trusted-administrator list, the malicious-domain blacklist, security headers / HSTS, XML-RPC handling, notification recipients, and the repeat-alert throttle window.

## Changelog

See the **Changelog** section in [`readme.txt`](readme.txt) for detailed, version-by-version release notes.

## Security

WP Radar is a defensive security tool intended for protecting sites you own or are authorized to manage. If you discover a vulnerability in the plugin itself, please report it privately to the maintainer rather than opening a public issue.

## License

Distributed under the **GPL-2.0-or-later** license. See [`LICENSE`](LICENSE) for details.
