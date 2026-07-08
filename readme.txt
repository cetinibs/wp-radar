=== CK Radar Security ===
Contributors: cetinpim
Tags: security, firewall, malware, brute force, hardening
Requires at least: 5.0
Tested up to: 7.0
Requires PHP: 7.0
Stable tag: 2.7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Multi-layered WordPress security: brute-force protection, hardening, core file integrity, intrusion blocking, and malware / SEO-spam cleanup.

== Description ==

CK Radar Security stops intrusion attempts across multiple layers:

* **Login protection (brute-force)** — IP-based rate limiting and temporary lockout against automated password attempts via wp-login.php / XML-RPC. After a configurable number of failed attempts the IP is blocked, and a generic error message that does not leak usernames is shown.
* **Hardening** — Security HTTP headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, optional HSTS), WordPress version/generator hiding, directory-listing disable, and protection of sensitive files (wp-config.php, .htaccess, debug.log, readme).
* **Core file integrity** — Compares core files against the official WordPress.org checksums to detect modified / injected core files.
* **User protection** — Blocks creation of new administrator accounts, role escalation, and hidden admin injection via profile updates outside a "trusted administrators" list captured at activation. Detects fake admins inserted directly into the database via a daily scan.
* **File protection** — Rejects PHP/shell and double-extension files during media upload, scans the uploads folder for web shells, and detects unexpected PHP files dropped in the web root and changes to critical files (wp-config.php, .htaccess, index.php). Disables PHP execution inside uploads via .htaccess. Disables the in-dashboard file editor.
* **Root-folder protection** — Detects unauthorized root folders that WordPress did not physically create (SEO-spam doorway folders such as category, tag, 2024, portfolio) on an hourly scan, on admin login, and at activation. It scans folder contents FIRST, then deletes ONLY those with malware evidence (web shell, obfuscated code, spam doorway, or permalink-mimicking name). Folders without evidence are reported, never deleted. Legitimate custom folders are protected via an "allowed root folders" list.
* **WordPress structure protection** — Verifies the integrity of core directories (wp-admin, wp-includes, wp-content) and reports missing/broken structure.
* **Malicious link protection** — On the front end (content, excerpt, comments, widgets) it cleans, at render time, links containing spam keywords, hidden links (display:none), or links to blacklisted domains, while preserving the visible text. This hides links already injected into the database from visitors.
* **Content protection** — Blocks porn, gambling/betting, illegal-gaming, and SEO-spam links injected into posts, comments, and site options; catches hidden (display:none) link injections. To reduce false positives, keywords are matched on Unicode word boundaries and auto-blocking triggers only when a spam keyword AND a link occur together.
* **Exploit protection** — Blocks path traversal, LFI/RFI wrappers (php://, data://, etc.), SQLi, XSS, and web-shell request signatures; stops known attack/scanning tools (sqlmap, nikto, wpscan, etc.) and empty-user-agent POST bots; trusted administrators are exempt from the firewall to avoid false-positive lockouts. Restricts unauthorized user listing/creation via REST/XML-RPC; stops unauthorized plugin/theme install and updates (wp-cron and WP-CLI auto-updates are unaffected); blocks username enumeration. Disabling XML-RPC is an optional setting.
* **Logging & notifications** — All events are stored in the database; critical events trigger an email to the administrator and an admin-area notice.

== External Services ==

This plugin does not send any data to external services by default. The two services below are used only when an administrator explicitly enables them and provides the relevant API key/token (both are OFF by default / opt-in):

1. VirusTotal — https://www.virustotal.com/
* Purpose: On-demand reputation / malware scanning of a URL or file chosen by the administrator.
* Data sent: Only the URL or the file hash to be scanned; no other data. The API key is supplied by the administrator.
* API endpoint: https://www.virustotal.com/api/v3/
* Terms of Service: https://docs.virustotal.com/docs/terms-of-service
* Privacy Policy: https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy

2. WPScan — https://wpscan.com/
* Purpose: Compares installed plugin/theme/core versions against the known-vulnerability database (Vulnerability Scan module).
* Data sent: Only the version strings of installed components. The WPScan token is supplied by the administrator.
* API endpoint: https://wpscan.com/api/v3/
* Terms of Service: https://wpscan.com/terms/
* Privacy Policy: https://automattic.com/privacy/

Core file integrity uses WordPress's own get_core_checksums() (api.wordpress.org); that request is handled by WordPress and contains only the core version information.

== Installation ==

1. Upload the `ck-radar-security` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the "Plugins" menu in WordPress.
3. At activation, all current administrator accounts are stored as "trusted" — therefore activate the plugin only when you are confident your accounts are clean.
4. Configure the modules, the login lockout threshold, and the notification email from the "CK Radar Security" menu.

== Frequently Asked Questions ==

= Does the plugin send data to third parties? =
Not by default. The VirusTotal and WPScan integrations are opt-in and require an API key/token that you provide yourself. See the "External Services" section for exactly what is sent.

= Does the .htaccess hardening work on Nginx? =
The .htaccess hardening is for Apache. On Nginx, disable PHP execution in the uploads directory from your server configuration instead.

= The root-folder protection deletes spam folders, but they keep coming back. Why? =
If folders are recreated repeatedly, the real problem is a backdoor/web shell. Review log entries such as "uploads_shell_imza" and "supheli_root_php", clean the suspicious files, change all passwords, and update your plugins/themes. Otherwise the spam folders will keep being recreated.

= Does the content filter affect trusted administrators? =
No. Content from trusted administrators is never blocked, only logged.

== Important Notes ==

* The .htaccess hardening is for Apache. On Nginx, disable PHP execution in the uploads directory from the server configuration.
* The content filter can produce false positives; content from trusted administrators is not blocked, only logged.
* This plugin is defensive; it complements, but does not replace, regular backups and core/plugin updates.
* Root-folder protection automatically cleans spam folders, BUT if those folders are recreated repeatedly by a backdoor/web shell, the real issue is the backdoor. Inspect log entries, clean suspicious files, change all passwords, and update plugins/themes.

== Changelog ==

= 2.7.0 =
* Active response, upgraded from passive detection. Recurring root-directory backdoors (e.g. default.php) and database-injected rogue administrators previously produced only log/email alerts; they can now be neutralized automatically.
* Root backdoor auto-quarantine (default ON): an unexpected .php file in the site root is now inspected for web-shell BEHAVIOR signatures (code execution, obfuscation, dynamic calls from user input, file upload) rather than the mere "<?php" tag, so legitimate custom files are not touched. A file matching a backdoor signature is moved into a fully access-denied "wp-content/uploads/wpgk-karantina" folder under a non-executable ".txt" name (evidence preserved, execution stopped) and logged as root_php_karantina.
* Rogue administrator auto-neutralization (default OFF, opt-in): the scheduled fake-admin scan can now demote any administrator not on the trusted allowlist to "subscriber" and destroy all of that user's sessions. A safety interlock ensures at least one trusted administrator remains, so it cannot lock out legitimate admins.
* Faster response: the integrity + root-backdoor scan now also runs hourly (previously daily).
* Note: these measures are defense-in-depth. While a web shell with server access remains on the host, malicious accounts and files can be recreated; the underlying backdoor and entry vector must still be removed at the server level.

= 2.6.0 =
* Removed the country/geographic (GeoIP) blocking module entirely. The site is now open to legitimate visitors worldwide; blocking is purely BEHAVIORAL: attack/suspicious request signatures, bad bots, brute-force, rate-limit overflow, and a behavioral automatic IP block triggered by repeated suspicious events. Legitimate overseas visitors and search engines are no longer blocked; only malicious traffic is stopped.

= 2.5.2 =
* Added behavioral automatic IP blocking: if the same IP produces more suspicious events than a configured threshold within a configured window (firewall signature match, bad bot, failed login, rate-limit overflow, etc.), that IP is temporarily blocked. Independent of geography; administrators and the IP allowlist are exempt. Threshold, window, and block duration are configurable (default: 20 events in 60 min -> 60 min block). Triggers a critical log entry and an email.

= 2.5.1 =
* (Legacy) Added an allowlist mode and verified-search-engine exemption (reverse/forward DNS) to the country-blocking module so search engines could keep crawling. Note: the GeoIP module was later removed entirely in 2.6.0.

= 2.5.0 =
* New protection modules (all OFF by default / opt-in):
  - Two-factor authentication (2FA / TOTP): compatible with Google Authenticator and similar apps, fully local (no external service). Enabled per user from the "2FA Setup" page.
  - Login CAPTCHA: a simple math question that requires no external service.
  - Manual IP block/allow lists (CIDR supported): the allowlist bypasses all blocks; the blocklist denies access entirely.
  - Rate limiting: a temporary block when the per-IP request/window threshold is exceeded; administrators and the allowlist are exempt.
  - Vulnerability scanning (WPScan API): compares installed plugin/theme/core versions against known vulnerabilities; requires a token, and logs a critical event + email when a vulnerability is found.

= 2.4.0 =
* Security-review hardening:
  - IP spoofing protection: unconditional trust of `X-Forwarded-For` / `CF-Connecting-IP` headers was removed. A new "proxy/CDN trust" setting controls behavior: when off, only REMOTE_ADDR is used; when on, the first PUBLIC address from CF-Connecting-IP / X-Forwarded-For is used.
  - Firewall bypass fix: the request URI is now multi-decoded (up to 3 times) before signature scanning, so double-encoded path-traversal/LFI payloads such as `..%252f` can no longer slip through.
  - The VirusTotal API key is masked in the admin panel.

= 2.3.3 =
* Fixed false positives in the .htaccess integrity check: common shared-hosting PHP handler directives are no longer flagged on their own; .htaccess is marked critical only for genuine danger (inline PHP/obfuscation, auto_prepend/append injection, or enabling PHP execution on a non-PHP extension).

= 2.3.2 =
* Smart notifications for web-shell scan attempts: requests to a known web-shell filename are always blocked (403), but the notification level depends on whether the file actually exists on the server (warning + no email if absent; critical + email + VirusTotal check if present). Real code injection (e.g. eval($_POST...)) is always treated as critical.

= 2.3.1 =
* False-positive reduction tuned from real-world data (uploads index.php guard files, image/binary signature scanning, bad-bot detection), plus smarter file-integrity checks with a self-refreshing baseline.

= 2.3.0 =
* Added VirusTotal integration (API v3 URL/file reputation, on-demand "Scan with VirusTotal" tool, optional auto-verification of suspicious uploads, 1-hour result caching) and a more user-friendly admin panel (status dashboard, grouped settings).

= 2.2.1 =
* Notification grouping by IP block (/24): a single email per "event type + attacker IP block". Default repeat-notification throttle raised from 10 to 60 minutes.

= 2.2.0 =
* Improved email notifications: multiple recipients, a configurable repeat-notification throttle, a "Send Test Email" button, and a richer notification body (site URL, user ID, event-log link).

= 2.1.1 =
* Fixed uploads-scanner false positives (.htaccess no longer treated as executable unless it re-enables PHP execution; empty index.php guards skipped; images scanned only for a real PHP opening tag).

= 2.1.0 =
* Strengthened XML-RPC hardening (removes pingback.ping and system.multicall, removes the X-Pingback header and RSD link, optional full xmlrpc.php 403). Closed username enumeration via ?author=N and the XML sitemap user listing. Added HSTS preload support.

= 2.0.0 =
* Major rebrand and feature consolidation: login brute-force protection (IP rate limiting, lockout, generic login error), hardening module (security headers, version hiding, directory-listing disable, sensitive-file protection), core file integrity via WordPress.org checksums, and bad-bot / empty-user-agent POST blocking in the firewall.

= 1.3.0 =
* "Scan first, then block" approach: root-folder deletion is evidence-based. Added WordPress structure protection and front-end malicious-link cleaning, plus a "Scan Now" button and a malicious-domain blacklist.

= 1.2.0 =
* Added root-folder protection: detects unauthorized physical folders (SEO-spam doorways) WordPress did not create and optionally deletes them, with a panel-managed "allowed root folders" list; deletion happens only in direct subfolders of ABSPATH while protecting core and hidden system folders.

= 1.1.0 =
* Targeted PHP 7.0+. Rewrote the content filter (Unicode word-boundary matching, "keyword + link" blocking) to greatly reduce false positives. The firewall exempts trusted administrators; install/update checks do not block wp-cron and WP-CLI auto-updates; XML-RPC disabling is now optional; added automatic log-table pruning and uninstall.php.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 2.6.0 =
Behavioral-only blocking; the GeoIP module has been removed. Legitimate worldwide visitors and search engines are no longer geo-blocked.
