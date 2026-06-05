=== WP Radar ===
Contributors: wpradar
Tags: güvenlik, security, malware, firewall, hardening, brute force, login, malware scanner
Requires at least: 5.0
Tested up to: 6.5
Requires PHP: 7.0
Stable tag: 2.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Kapsamlı WordPress güvenlik radarı: brute-force/giriş koruması, sertleştirme, çekirdek dosya bütünlüğü, sızma engeli, zararlı dosya/klasör tespiti ve spam link temizliği.

== Açıklama ==

WP Radar, hosta sızma girişimlerini birden çok katmanda durdurur:

* **Giriş koruması (brute-force)** — wp-login.php / XML-RPC üzerinden otomatik şifre
  denemelerine karşı IP bazlı oran sınırlama ve geçici kilitleme. Belirli sayıda başarısız
  denemeden sonra IP engellenir; kullanıcı adı sızdırmayan jenerik hata mesajı gösterilir.
* **Sertleştirme (hardening)** — Güvenlik HTTP başlıkları (X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, isteğe bağlı HSTS), WordPress sürüm/generator gizleme,
  dizin listeleme kapatma ve hassas dosya (wp-config.php, .htaccess, debug.log, readme) koruması.
* **Çekirdek dosya bütünlüğü** — WordPress.org resmi checksum'larıyla çekirdek dosyalarını
  karşılaştırır; değiştirilmiş/enjekte edilmiş çekirdek dosyalarını tespit eder.
* **Kullanıcı koruması** — Etkinleştirme anında kaydedilen "güvenilir yönetici" listesi
  dışında yeni yönetici hesabı oluşturulmasını, rol yükseltmeyi ve profil üzerinden gizli
  admin sızmasını engeller. Doğrudan veritabanına eklenen sahte adminleri günlük taramayla yakalar.
* **Dosya koruması** — Medya yükleme sırasında PHP/shell ve çift uzantılı dosyaları reddeder,
  uploads klasöründe web shell tarar, root dizinine bırakılan beklenmeyen PHP dosyalarını ve
  kritik dosya (wp-config.php, .htaccess, index.php) değişikliklerini tespit eder. uploads içinde
  PHP çalıştırmayı .htaccess ile kapatır. Panel içi dosya düzenleyiciyi devre dışı bırakır.
* **Kök klasör koruması** — WordPress'in fiziksel olarak oluşturmadığı izinsiz kök klasörleri
  (category, tag, 2024, portfolio gibi SEO spam doorway klasörleri) saatlik tarama, yönetici
  girişi ve etkinleştirme anında tespit eder. ÖNCE klasör içeriğini tarar, SONRA yalnızca
  zararlı kanıtı bulunanları (web shell, gizlenmiş kod, spam doorway veya permalink-taklidi
  ad) siler. Kanıt yoksa silmez, yalnızca raporlar. Meşru özel klasörler "izinli kök klasörler"
  listesiyle korunur.
* **WordPress yapı koruması** — Çekirdek dizinlerin (wp-admin, wp-includes, wp-content)
  bütünlüğünü doğrular; eksik/bozuk yapıyı raporlar.
* **Zararlı link koruması** — Ön yüzde (içerik, alıntı, yorum, widget) render anında spam
  anahtar kelime içeren, gizli (display:none) veya kara listedeki domaine giden bağlantıları
  otomatik temizler; görünen metni korur. Böylece veritabanına zaten enjekte edilmiş linkler
  ziyaretçilere gösterilmez.
* **İçerik koruması** — Yazı, yorum ve site seçeneklerine enjekte edilen porno, kumar/bahis,
  yasa dışı oyun ve SEO spam linklerini engeller; gizli (display:none) link enjeksiyonlarını yakalar.
  Yanlış pozitifleri azaltmak için anahtar kelimeler Unicode kelime sınırlarıyla eşleştirilir
  ("bet" → "Betül" eşleşmez) ve otomatik engelleme yalnızca "spam kelime + link" birlikte
  bulunduğunda tetiklenir.
* **Exploit koruması** — Path traversal, LFI/RFI sarmalayıcıları (php://, data:// vb.), SQLi,
  XSS ve web shell istek imzalarını engeller; bilinen saldırı/tarama araçlarını (sqlmap, nikto,
  wpscan vb.) ve boş user-agent'lı POST botlarını durdurur; güvenilir yöneticiler yanlış
  pozitiflerle kilitlenmemek için duvardan muaf tutulur. REST/XML-RPC üzerinden yetkisiz kullanıcı
  listeleme/oluşturmayı kısıtlar; yetkisiz eklenti/tema kurulum ve güncellemelerini durdurur
  (wp-cron ve WP-CLI otomatik güncellemeleri etkilenmez); kullanıcı adı enumerasyonunu engeller.
  XML-RPC kapatma isteğe bağlı bir ayardır.
* **Loglama & bildirim** — Tüm olaylar veritabanına kaydedilir, kritik olaylarda yöneticiye
  e-posta gönderilir ve panelde uyarı gösterilir.

== Kurulum ==

1. `wp-radar` klasörünü `/wp-content/plugins/` dizinine kopyalayın.
2. WordPress yönetim panelinde "Eklentiler" sayfasından etkinleştirin.
3. Etkinleştirme anında mevcut tüm yönetici hesapları "güvenilir" olarak kaydedilir —
   bu nedenle eklentiyi yalnızca hesaplarınızın temiz olduğundan emin olduğunuzda etkinleştirin.
4. "WP Radar" menüsünden modülleri, giriş kilidi eşiğini ve bildirim e-postasını yapılandırın.

== Önemli Notlar ==

* `.htaccess` sertleştirmesi Apache içindir. Nginx kullanıyorsanız, uploads dizininde PHP
  çalıştırmayı sunucu yapılandırmasından kapatmanız önerilir.
* İçerik filtresi yanlış pozitif üretebilir; güvenilir yöneticilerin içeriği engellenmez,
  yalnızca loglanır.
* Bu eklenti savunma amaçlıdır; düzenli yedekleme ve çekirdek/eklenti güncellemelerinin
  yerini tutmaz, onları tamamlar.
* ÖNEMLİ: Kök klasör koruması spam klasörleri otomatik temizler, ANCAK bu klasörler bir
  arka kapı (backdoor/web shell) tarafından tekrar tekrar oluşturuluyorsa asıl sorun arka
  kapıdır. Olay günlüğünde "uploads_shell_imza", "supheli_root_php" gibi kayıtları inceleyin;
  şüpheli dosyaları temizleyin, tüm şifreleri değiştirin ve eklenti/temaları güncelleyin.
  Aksi halde spam klasörler yeniden oluşturulmaya devam eder.

== Sürüm Geçmişi ==

= 2.2.1 =
* Bildirim gruplaması IP bloğuna göre yapılır hale getirildi: tekrar-bildirim engeli
  artık "olay türü + saldıran IP bloğu (/24)" bazında çalışıyor. Aynı IP'den veya
  aynı /24 bloğundan gelen yüzlerce istek (brute-force, bot seli, yetkisiz admin/rol
  denemesi, kök klasör oluşturma vb.) için tek e-posta gönderiliyor.
* Tekrar-bildirim engeli varsayılanı 10 dakikadan 60 dakikaya yükseltildi.

= 2.2.0 =
* E-posta bildirimleri geliştirildi:
  - Birden çok alıcı adresi desteği (virgül veya satır başıyla ayrılmış).
  - Tekrar-bildirim engeli (throttle): aynı tür kritik olay için yapılandırılabilir
    süre boyunca tek bildirim — saldırı sırasında e-posta yağmurunu önler. İlk olay
    yine anında gönderilir.
  - "Test E-postası Gönder" butonu: bildirim yapılandırmasını tek tıkla doğrulama.
  - Bildirim gövdesine site adresi, kullanıcı kimliği ve olay günlüğü bağlantısı eklendi.

= 2.1.1 =
* Uploads tarayıcısı yanlış pozitifleri giderildi:
  - `.htaccess` artık "çalıştırılabilir dosya" sayılmıyor; yalnızca PHP çalıştırmayı
    yeniden etkinleştiren direktif (AddHandler/SetHandler/AddType php, php_value …)
    içeriyorsa tehlikeli olarak işaretleniyor. WPForms/Contact Form 7 ve eklentinin
    kendi koruyucu .htaccess dosyaları artık tehdit sanılmıyor.
  - Boş "silence is golden" index.php guard dosyaları atlanıyor.
  - Görsel/ikili dosyalarda yalnızca gerçek PHP açılış etiketi (<?php) aranıyor;
    geniş shell imzasının PNG/JPEG ikili verisine tesadüfen eşleşmesi önlendi.

= 2.1.0 =
* XML-RPC sertleştirmesi güçlendirildi: `xmlrpc_enabled` filtresinin kapatmadığı
  `pingback.ping` ve `system.multicall` metodları artık kaldırılıyor (pingback
  tabanlı DDoS/SSRF amplifikasyonu engellendi). `X-Pingback` başlığı ve RSD bağlantısı
  kaldırıldı. İsteğe bağlı "XML-RPC tam engel" seçeneğiyle `xmlrpc.php` tamamen 403.
* Kullanıcı adı enumerasyonu açığı kapatıldı: author engeli artık `template_redirect`
  öncelik 0'da çalışıyor ve WordPress'in `redirect_canonical` yönlendirmesi iptal
  ediliyor; `?author=N` artık `/author/slug/` kullanıcı adını sızdırmıyor.
* XML sitemap kullanıcı listesi gizleme eklendi (`/wp-sitemap-users-1.xml` üzerinden
  kullanıcı adı sızıntısı engellendi).
* HSTS başlığına `preload` desteği eklendi (yeni "HSTS preload" seçeneği).

= 2.0.0 =
* Eklenti "WP Radar" olarak yeniden adlandırıldı.
* Giriş koruması (brute-force) modülü: IP bazlı oran sınırlama, geçici kilitleme,
  jenerik giriş hatası (kullanıcı adı enumerasyonunu önler).
* Sertleştirme modülü: güvenlik HTTP başlıkları, sürüm gizleme, dizin listeleme
  kapatma ve .htaccess ile hassas dosya koruması.
* Çekirdek dosya bütünlüğü: WordPress.org checksums ile değiştirilmiş çekirdek
  dosyalarının tespiti.
* Kötü bot / güvenlik tarama aracı (sqlmap, nikto, wpscan …) ve boş user-agent
  POST engellemesi firewall'a eklendi.
* Yeni ayarlar paneli seçenekleri ve giriş kilidi eşik yapılandırması.

= 1.3.0 =
* "Önce tara, sonra engelle" yaklaşımı: kök klasör silme artık kanıta dayalı.
  Klasör içeriği taranır; web shell, gizlenmiş kod veya SEO spam doorway kanıtı
  bulunursa silinir. Kanıt yoksa yalnızca raporlanır (meşru klasör silinmez).
  WordPress'in oluşturmadığı permalink-taklidi klasörler (category, tag, 2024,
  portfolio …) isimleriyle zararlı sayılır.
* WordPress klasör yapısı koruması (çekirdek dizin bütünlüğü) eklendi.
* Zararlı link koruması: ön yüzde (the_content, alıntı, yorum, widget) render
  anında spam/gizli/kara-liste-domain bağlantıları otomatik temizlenir; görünen
  metin korunur.
* Panele "Şimdi Tara" butonu ve zararlı domain kara listesi eklendi.

= 1.2.0 =
* Kök klasör koruması eklendi: WordPress'in oluşturmadığı (category, tag, 2024,
  portfolio gibi) izinsiz fiziksel klasörleri (SEO spam doorway) saatlik tarama,
  yönetici girişi ve etkinleştirmede tespit eder ve isteğe bağlı olarak otomatik siler.
* Panelden yönetilebilen "izinli kök klasörler" listesi eklendi.
* Silme işlemi yalnızca ABSPATH'in doğrudan alt klasörlerinde, çekirdek dizinleri
  (wp-admin/wp-content/wp-includes) ve gizli sistem klasörlerini koruyarak yapılır.

= 1.1.0 =
* PHP 7.0+ hedeflendi.
* İçerik filtresi yeniden yazıldı: Unicode kelime sınırı eşleşmesi ve "kelime + link"
  tabanlı engelleme ile yanlış pozitifler büyük ölçüde azaltıldı.
* Güvenlik duvarı güvenilir yöneticileri muaf tutuyor; LFI/RFI imzası daraltılarak meşru
  redirect_to=https:// girişleri engellenmiyor.
* Kurulum/güncelleme denetimi wp-cron ve WP-CLI otomatik güncellemelerini engellemiyor.
* XML-RPC kapatma artık isteğe bağlı.
* Log tablosu için otomatik budama (DoS koruması) eklendi.
* Temiz kaldırma için uninstall.php eklendi.

= 1.0.0 =
* İlk sürüm.
