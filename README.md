# WP Radar

Kapsamlı WordPress güvenlik radarı: brute-force / giriş koruması, sızma (exploit) engelleme, zararlı dosya & klasör tespiti, çekirdek bütünlüğü doğrulama, güvenlik sertleştirmesi ve kritik olaylarda anlık e-posta bildirimi.

> Sürüm: **2.2.1** · Gereksinim: WordPress 5.0+ / PHP 7.0+ · Lisans: GPL-2.0-or-later

## Özellikler

### Kullanıcı & Giriş güvenliği
- Yetkisiz yönetici oluşturma / rol yükseltme engelleme (güvenilir admin listesi)
- Brute-force koruması: IP bazlı oran sınırlama ve geçici kilitleme
- Kullanıcı adı sızdırmayan jenerik giriş hataları

### Ağ & İstek güvenliği
- Exploit imza taraması (path traversal, LFI/RFI, SQLi, web shell, XSS)
- Kötü bot / tarama aracı engelleme (sqlmap, nikto, wpscan, nmap vb.)
- XML-RPC sertleştirme: pingback / `system.multicall` kaldırma, X-Pingback gizleme, isteğe bağlı tam engelleme
- Kullanıcı adı enumerasyonu engeli (`?author=N`, REST users, sitemap users)
- Güvenlik HTTP başlıkları (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) ve HSTS

### Dosya & Sistem güvenliği
- uploads / kök dizinde web shell ve çalıştırılabilir dosya tespiti (yanlış pozitif azaltılmış)
- Kök dizinde SEO spam / doorway klasörü tespiti ve kanıta dayalı otomatik temizleme
- Çekirdek dosya bütünlüğü doğrulama (WordPress.org checksums)
- Panel içi dosya düzenleyiciyi kapatma (DISALLOW_FILE_EDIT), hassas dosya ve dizin listeleme koruması (.htaccess)

### İçerik güvenliği
- Ön yüzde spam / zararlı bağlantı temizleme, kara liste domain desteği

### Bildirimler
- Kritik olaylarda anlık e-posta bildirimi
- Çoklu alıcı desteği
- "Olay türü + IP bloğu (/24)" bazlı tekrar-bildirim engeli (e-posta yağmuru önleme)
- Tek tıkla test e-postası

## Kurulum

1. Bu depoyu ZIP olarak indirin ya da `wp-radar` klasörünü `wp-content/plugins/` altına kopyalayın.
2. WordPress yönetim panelinde **Eklentiler** > **WP Radar**'ı etkinleştirin.
3. **WP Radar** menüsünden ayarları yapılandırın ve bildirim e-postalarını girin.

## Güvenlik notu

Bu eklenti savunmaya yönelik (defensive) bir güvenlik aracıdır. Sorumlu kullanım içindir.

## Sürüm geçmişi

Ayrıntılı değişiklikler için `readme.txt` dosyasındaki "Sürüm Geçmişi" bölümüne bakın.
