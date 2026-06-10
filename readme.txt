=== WP Radar ===
Contributors: wpradar
Tags: güvenlik, security, malware, firewall, hardening, brute force, login, malware scanner
Requires at least: 5.0
Tested up to: 6.5
Requires PHP: 7.0
Stable tag: 2.5.1
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

= 2.5.1 =
* Ülke engellemeye "beyaz liste" modu eklendi: yalnızca seçili ülkelere izin verip
  (ör. yalnızca TR) diğer tüm yurt dışı trafiği engelleyebilirsiniz. Türkiye içi
  şüpheli trafik diğer modüller (firewall, oran sınırlama, bot/imza) tarafından
  zaten ele alınır.
* SEO koruması: doğrulanmış arama motoru botları (Googlebot, Bingbot, YandexBot vb.)
  reverse/forward DNS ile doğrulanarak coğrafi engelden muaf tutulur — beyaz liste
  modunda Google'ın siteyi taramaya devam etmesini sağlar. Sahte bot user-agent'ları
  DNS teyidini geçemez.

= 2.5.0 =
* Wordfence benzeri yeni koruma modülleri (hepsi varsayılan kapalı / opt-in):
  - İki faktörlü doğrulama (2FA / TOTP): Google Authenticator vb. ile uyumlu,
    tamamen yerel (dış servis yok). Kullanıcı bazında "2FA Kurulumu" sayfasından
    etkinleştirilir.
  - Giriş CAPTCHA'sı: dış servis gerektirmeyen matematik sorusu.
  - Elle IP kara/beyaz liste (CIDR destekli): beyaz liste tüm engelleri atlar,
    kara liste erişimi tamamen reddeder.
  - Oran sınırlama (rate limiting): IP başına istek/pencere eşiği aşılırsa geçici
    engel; yöneticiler ve beyaz liste muaf.
  - Ülke engelleme (GeoIP): yapılandırılabilir sağlayıcı (ip-api anahtarsız /
    ipinfo token), IP başına önbellek, servis kesintisinde fail-open.
  - Zafiyet taraması (WPScan API): kurulu eklenti/tema/çekirdek sürümlerini bilinen
    açıklarla karşılaştırır; token gerektirir, açık bulunursa kritik + e-posta.
* Not: Wordfence'in gerçek zamanlı tehdit istihbaratı (lisanslı IP/firewall/malware
  feed'leri) bir altyapı hizmeti olduğundan birebir taklit edilmez; bu modüller
  kendi kodunuzla veya sizin sağladığınız anahtarlarla çalışır.

= 2.4.0 =
* Uçtan uca güvenlik incelemesi sonucu sertleştirmeler:
  - IP sahteciliğine karşı koruma: `X-Forwarded-For`/`CF-Connecting-IP` başlıkları
    istemci tarafından sahte gönderilebildiğinden, bunlara koşulsuz güven kaldırıldı.
    Yeni "proxy/CDN güveni" ayarı: kapalıyken yalnızca REMOTE_ADDR kullanılır
    (sahtecilikle giriş-kilidi atlatma engellenir); açıkken CF-Connecting-IP ve
    X-Forwarded-For içindeki ilk PUBLIC adres kullanılır (özel-aralık enjeksiyonu
    atlanır). CDN/ters proxy arkasındaki siteler için varsayılan açıktır.
  - Firewall imza atlatma düzeltmesi: istek URI'si artık imza taramasından önce
    çok katlı (en çok 3 kez) URL-decode edilir; `..%252f` gibi çift kodlanmış
    path-traversal/LFI payload'ları artık atlatamaz.
  - VirusTotal API anahtarı yönetim panelinde maskelenir (HTML kaynağında açık
    görünmez); boş bırakılıp kaydedilirse mevcut anahtar korunur, kaldırmak için
    ayrı bir seçenek sunulur.
  - Panel uyarı sayacındaki saat dilimi tutarsızlığı giderildi.

= 2.3.3 =
* .htaccess bütünlük denetiminde yanlış pozitif düzeltmesi:
  - Paylaşımlı hostingde (Hostinger/cPanel) olağan olan PHP sürüm handler'ı
    (`AddHandler ... .php .phtml`) ve `php_value`/`php_flag` direktifleri artık TEK
    BAŞINA "şüpheli değişiklik" sayılmıyor; bu direktifler meşrudur.
  - .htaccess artık yalnızca gerçek tehlikelerde kritik işaretleniyor:
    (a) doğrudan PHP kodu/gizleme (`<?php`, `eval(`, `base64_decode(` …),
    (b) `auto_prepend_file`/`auto_append_file` enjeksiyonu,
    (c) PHP yürütmeyi PHP-olmayan bir uzantıya (.jpg, .png, .txt …) açan
        AddHandler/AddType/SetHandler satırı.
  - Böylece PHP sürümü değiştirildiğinde veya bir eklenti php_value eklediğinde
    gereksiz "kritik" e-posta gönderilmiyor; değişiklik "uyari" olarak loglanıyor.

= 2.3.2 =
* Web shell tarama denemelerinde akıllı bildirim:
  - Bilinen bir web shell DOSYA ADINA (c99, r57, wso, b374k, filesman, phpspy)
    yapılan istek artık her zaman olduğu gibi 403 ile ENGELLENİR; ancak bildirim
    seviyesi dosyanın sunucuda gerçekten var olup olmadığına göre belirlenir:
    - Dosya sunucuda YOKSA (rutin internet taraması) → "uyari" loglanır, e-posta
      GÖNDERİLMEZ. Böylece gece boyu süren bot taramaları için gereksiz uyarı gelmez.
    - Dosya sunucuda VARSA → "kritik" loglanır, e-posta gönderilir ve (VirusTotal
      açıksa) dosya otomatik olarak VirusTotal ile doğrulanır.
  - Gerçek kod enjeksiyonu (ör. eval($_POST...)) bu istisnadan etkilenmez; her zaman
    kritik kabul edilir.

= 2.3.1 =
* Yanlış pozitif (false-positive) azaltma — gerçek saha verilerine göre ayarlandı:
  - uploads içi `index.php` guard dosyaları: eklentilerin (WPForms, WooCommerce,
    Elementor vb.) bıraktığı zararsız ABSPATH-kontrollü `index.php` dosyaları artık
    "çalıştırılabilir dosya" olarak işaretlenmiyor (boyut sınırı 256 → 2048 bayt).
  - Görsel/ikili dosya imza taraması: bir görselin (`.jpg` vb.) ikili verisinde
    tesadüfen oluşabilen kısa `<?=` etiketi tek başına alarm üretmiyor; artık gerçek
    polyglot shell için HEM PHP açılış etiketi HEM de tehlikeli bir çağrı
    (`eval`/`base64_decode`/`system`/`$_REQUEST` vb.) birlikte aranıyor.
  - Kötü bot tespiti: user-agent kalıbındaki `x?spider` → `xspider`. Bytespider,
    Baiduspider, Sogou Spider, 360Spider gibi MEŞRU tarayıcılar artık "saldırı aracı"
    sayılmıyor; yalnızca gerçek XSpider zafiyet tarayıcısı engelleniyor.
* Dosya bütünlük denetimi akıllandırıldı:
  - Değişen `.htaccess` / `wp-config.php` gibi dosyalar körlemesine "kritik"
    işaretlenmiyor; içerik analiziyle yalnızca PHP çalıştırmayı etkinleştiren direktif
    veya web shell/gizlenmiş kod imzası bulunursa kritik, aksi halde "uyari" loglanıyor.
  - Baseline (temel hash) bir değişiklik raporlandıktan sonra kendini yeniliyor; aynı
    meşru değişiklik için her taramada tekrar e-posta gönderilmiyor.

= 2.3.0 =
* VirusTotal entegrasyonu eklendi:
  - API v3 ile URL ve dosya (SHA-256) itibar sorgusu; 70+ güvenlik motorunun
    "zararlı / şüpheli / zararsız" sonuçları.
  - Yönetim panelinde anlık "VirusTotal ile Tara" aracı (URL veya hash).
  - Şüpheli upload dosyalarının otomatik VirusTotal doğrulaması (isteğe bağlı,
    oran sınırı için çalışma başına en fazla 4 sorgu); zararlı çıkarsa kritik
    olay olarak loglanır ve e-posta bildirimi tetikler.
  - Sonuçlar 1 saat önbelleğe alınır (ücretsiz API sınırına saygı).
* Yönetim paneli kullanıcı dostu hale getirildi:
  - Üstte durum panosu (aktif modül sayısı, son 24 saat kritik/uyarı, VirusTotal
    durumu, son tarama zamanı).
  - Ayarlar mantıksal kartlara/gruplara ayrıldı (Giriş & Kullanıcı, Ağ & İstek,
    Dosya & Sistem, Sertleştirme, İçerik, VirusTotal, Bildirim).
  - Daha okunaklı geçiş anahtarları ve açıklamalar.

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
