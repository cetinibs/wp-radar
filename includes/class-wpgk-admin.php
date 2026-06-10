<?php
/**
 * Yönetim paneli: ayarlar, güvenilir admin yönetimi ve olay günlüğü görünümü.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Admin {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'menu_ekle' ) );
		add_action( 'admin_init', array( $this, 'ayarlari_kaydet' ) );
		add_action( 'admin_init', array( $this, 'taramayi_calistir' ) );
		add_action( 'admin_init', array( $this, 'test_eposta_gonder' ) );
		add_action( 'admin_notices', array( $this, 'kritik_uyari_goster' ) );
		add_action( 'admin_notices', array( $this, 'tarama_sonucu_goster' ) );
		add_action( 'admin_notices', array( $this, 'test_eposta_sonucu_goster' ) );
	}

	/**
	 * Birden çok e-posta adresini (virgül/satır ayrımlı) doğrulayıp normalize eder.
	 */
	protected static function epostalari_temizle( $ham ) {
		$temiz = array();
		foreach ( preg_split( '/[\r\n,;]+/', (string) $ham ) as $e ) {
			$e = sanitize_email( trim( $e ) );
			if ( $e && is_email( $e ) ) {
				$temiz[] = $e;
			}
		}
		$temiz = array_values( array_unique( $temiz ) );
		return empty( $temiz ) ? get_option( 'admin_email' ) : implode( "\n", $temiz );
	}

	/**
	 * VirusTotal API anahtarını kaydeder. Alan maskelenmiş gösterildiğinden,
	 * boş gönderildiyse mevcut kayıtlı anahtar korunur; doğrudan kaldırmak için
	 * "wpgk_vt_temizle" işaretlenir.
	 */
	protected function vt_anahtar_kaydet() {
		$mevcut = get_option( 'wpgk_ayarlar', array() );
		$eski   = isset( $mevcut['vt_api_key'] ) ? (string) $mevcut['vt_api_key'] : '';

		if ( isset( $_POST['wpgk_vt_temizle'] ) ) {
			return '';
		}
		$girilen = isset( $_POST['vt_api_key'] ) ? preg_replace( '/[^a-zA-Z0-9]/', '', wp_unslash( $_POST['vt_api_key'] ) ) : '';
		return ( '' !== $girilen ) ? $girilen : $eski;
	}

	/**
	 * "Test e-postası gönder" butonu: kayıtlı alıcılara test bildirimi yollar.
	 */
	public function test_eposta_gonder() {
		if ( ! isset( $_POST['wpgk_test_mail_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_test_mail_nonce'] ) ), 'wpgk_test_mail' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$ok = WPGK_Logger::test_bildirimi_gonder();
		set_transient( 'wpgk_test_mail_sonuc', $ok ? 'ok' : 'hata', 30 );
		wp_safe_redirect( admin_url( 'admin.php?page=wpgk-panel&wpgk_test_mail=1' ) );
		exit;
	}

	/**
	 * Test e-postası sonucunu bildirim olarak göster.
	 */
	public function test_eposta_sonucu_goster() {
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['wpgk_test_mail'] ) ) {
			return;
		}
		$sonuc = get_transient( 'wpgk_test_mail_sonuc' );
		if ( ! $sonuc ) {
			return;
		}
		if ( 'ok' === $sonuc ) {
			echo '<div class="notice notice-success is-dismissible"><p><strong>Test e-postası gönderildi.</strong> Gelen kutunuzu (ve spam klasörünü) kontrol edin. E-posta gelmediyse Hostinger\'da SMTP eklentisi yapılandırmanız gerekebilir.</p></div>';
		} else {
			echo '<div class="notice notice-error is-dismissible"><p><strong>Test e-postası gönderilemedi.</strong> Geçerli bir alıcı adresi girip kaydettiğinizden emin olun; sorun sürerse bir SMTP eklentisi kurun.</p></div>';
		}
	}

	/**
	 * "Şimdi Tara" butonu: tüm tarayıcıları senkron çalıştırır.
	 */
	public function taramayi_calistir() {
		if ( ! isset( $_POST['wpgk_tara_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_tara_nonce'] ) ), 'wpgk_tarama' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		@set_time_limit( 0 );

		// 1) ÖNCE TARA: kök klasör analizi (bulguları döndürür).
		$kok_bulgular = WPGK_File_Guard::kok_klasor_tara();

		// 2) Diğer tarayıcıları çalıştır (uploads shell, bütünlük, yapı, sahte admin, içerik).
		do_action( 'wpgk_gunluk_tarama' );

		$silinen = 0;
		$tespit  = 0;
		foreach ( (array) $kok_bulgular as $b ) {
			if ( 'silindi' === $b['durum'] ) {
				$silinen++;
			} elseif ( 'tespit' === $b['durum'] || 'supheli' === $b['durum'] ) {
				$tespit++;
			}
		}

		set_transient(
			'wpgk_tarama_sonuc',
			array( 'silinen' => $silinen, 'tespit' => $tespit, 'zaman' => current_time( 'mysql' ) ),
			60
		);
		update_option( 'wpgk_son_tarama', current_time( 'mysql' ) );

		wp_safe_redirect( admin_url( 'admin.php?page=wpgk-panel&wpgk_tarandi=1' ) );
		exit;
	}

	/**
	 * Tarama sonucunu bildirim olarak göster.
	 */
	public function tarama_sonucu_goster() {
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['wpgk_tarandi'] ) ) {
			return;
		}
		$sonuc = get_transient( 'wpgk_tarama_sonuc' );
		if ( ! $sonuc ) {
			return;
		}
		printf(
			'<div class="notice notice-info is-dismissible"><p><strong>Tarama tamamlandı.</strong> Silinen zararlı kök klasör: %d, incelenmesi gereken bulgu: %d. Ayrıntılar için <a href="%s">Olay Günlüğü</a>.</p></div>',
			(int) $sonuc['silinen'],
			(int) $sonuc['tespit'],
			esc_url( admin_url( 'admin.php?page=wpgk-gunluk' ) )
		);
	}

	public function menu_ekle() {
		add_menu_page(
			'WP Radar',
			'WP Radar',
			'manage_options',
			'wpgk-panel',
			array( $this, 'panel_render' ),
			'dashicons-shield',
			80
		);
		add_submenu_page( 'wpgk-panel', 'Olay Günlüğü', 'Olay Günlüğü', 'manage_options', 'wpgk-gunluk', array( $this, 'gunluk_render' ) );
		// 2FA kurulumu: her oturum açmış kullanıcı kendi hesabı için yapabilir.
		$ls = WPGK_Plugin::instance()->login_security;
		if ( $ls ) {
			add_submenu_page( 'wpgk-panel', 'İki Faktörlü Doğrulama', '2FA Kurulumu', 'read', 'wpgk-2fa', array( $ls, 'sayfa_render' ) );
		}
	}

	/**
	 * Ayar formunu işle.
	 */
	public function ayarlari_kaydet() {
		if ( ! isset( $_POST['wpgk_ayar_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_ayar_nonce'] ) ), 'wpgk_ayar_kaydet' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$ayarlar = array(
			'kullanici_korumasi'    => isset( $_POST['kullanici_korumasi'] ) ? 1 : 0,
			'dosya_korumasi'        => isset( $_POST['dosya_korumasi'] ) ? 1 : 0,
			'icerik_korumasi'       => isset( $_POST['icerik_korumasi'] ) ? 1 : 0,
			'exploit_korumasi'      => isset( $_POST['exploit_korumasi'] ) ? 1 : 0,
			'dosya_duzenleme_kapat' => isset( $_POST['dosya_duzenleme_kapat'] ) ? 1 : 0,
			'xmlrpc_kapat'          => isset( $_POST['xmlrpc_kapat'] ) ? 1 : 0,
			'xmlrpc_tam_engel'      => isset( $_POST['xmlrpc_tam_engel'] ) ? 1 : 0,
			'pingback_kapat'        => isset( $_POST['pingback_kapat'] ) ? 1 : 0,
			'sitemap_kullanici_gizle' => isset( $_POST['sitemap_kullanici_gizle'] ) ? 1 : 0,
			'kok_klasor_korumasi'   => isset( $_POST['kok_klasor_korumasi'] ) ? 1 : 0,
			'kok_klasor_otomatik_sil' => isset( $_POST['kok_klasor_otomatik_sil'] ) ? 1 : 0,
			'kok_izinli'            => isset( $_POST['kok_izinli'] ) ? sanitize_textarea_field( wp_unslash( $_POST['kok_izinli'] ) ) : '',
			'yapi_korumasi'         => isset( $_POST['yapi_korumasi'] ) ? 1 : 0,
			'cekirdek_butunluk'     => isset( $_POST['cekirdek_butunluk'] ) ? 1 : 0,
			'link_korumasi'         => isset( $_POST['link_korumasi'] ) ? 1 : 0,
			'zararli_domainler'     => isset( $_POST['zararli_domainler'] ) ? sanitize_textarea_field( wp_unslash( $_POST['zararli_domainler'] ) ) : '',
			// VirusTotal — anahtar maskelenmiş gösterildiğinden, boş gönderilirse
			// mevcut anahtar korunur (kazara silinmesini önler).
			'vt_api_key'            => $this->vt_anahtar_kaydet(),
			'vt_otomatik'           => isset( $_POST['vt_otomatik'] ) ? 1 : 0,
			// IP kaynağı (proxy/CDN güveni).
			'proxy_guven'           => isset( $_POST['proxy_guven'] ) ? 1 : 0,
			// Giriş güvenliği
			'giris_2fa'             => isset( $_POST['giris_2fa'] ) ? 1 : 0,
			'giris_captcha'         => isset( $_POST['giris_captcha'] ) ? 1 : 0,
			'ip_kara_liste'         => isset( $_POST['ip_kara_liste'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ip_kara_liste'] ) ) : '',
			'ip_beyaz_liste'        => isset( $_POST['ip_beyaz_liste'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ip_beyaz_liste'] ) ) : '',
			// Oran sınırlama
			'oran_limit'            => isset( $_POST['oran_limit'] ) ? 1 : 0,
			'oran_max'              => isset( $_POST['oran_max'] ) ? max( 10, min( 100000, (int) $_POST['oran_max'] ) ) : 120,
			'oran_pencere_sn'       => isset( $_POST['oran_pencere_sn'] ) ? max( 10, min( 3600, (int) $_POST['oran_pencere_sn'] ) ) : 60,
			'oran_kilit_dk'         => isset( $_POST['oran_kilit_dk'] ) ? max( 1, min( 1440, (int) $_POST['oran_kilit_dk'] ) ) : 10,
			// Ülke engelleme (GeoIP)
			'ulke_engel'            => isset( $_POST['ulke_engel'] ) ? 1 : 0,
			'engelli_ulkeler'       => isset( $_POST['engelli_ulkeler'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['engelli_ulkeler'] ) ) ) : '',
			'geoip_saglayici'       => ( isset( $_POST['geoip_saglayici'] ) && 'ipinfo' === $_POST['geoip_saglayici'] ) ? 'ipinfo' : 'ip-api',
			'geoip_token'           => isset( $_POST['geoip_token'] ) ? sanitize_text_field( wp_unslash( $_POST['geoip_token'] ) ) : '',
			// Zafiyet taraması (WPScan)
			'vuln_tarama'           => isset( $_POST['vuln_tarama'] ) ? 1 : 0,
			'wpscan_token'          => isset( $_POST['wpscan_token'] ) ? preg_replace( '/[^a-zA-Z0-9]/', '', wp_unslash( $_POST['wpscan_token'] ) ) : '',
			// Giriş / brute-force
			'giris_korumasi'        => isset( $_POST['giris_korumasi'] ) ? 1 : 0,
			'giris_jenerik_hata'    => isset( $_POST['giris_jenerik_hata'] ) ? 1 : 0,
			'giris_max_deneme'      => isset( $_POST['giris_max_deneme'] ) ? max( 1, min( 50, (int) $_POST['giris_max_deneme'] ) ) : 5,
			'giris_kilit_dk'        => isset( $_POST['giris_kilit_dk'] ) ? max( 1, min( 1440, (int) $_POST['giris_kilit_dk'] ) ) : 15,
			// Sertleştirme
			'guvenlik_basliklari'   => isset( $_POST['guvenlik_basliklari'] ) ? 1 : 0,
			'hsts'                  => isset( $_POST['hsts'] ) ? 1 : 0,
			'hsts_preload'          => isset( $_POST['hsts_preload'] ) ? 1 : 0,
			'surum_gizle'           => isset( $_POST['surum_gizle'] ) ? 1 : 0,
			'dizin_listeleme_kapat' => isset( $_POST['dizin_listeleme_kapat'] ) ? 1 : 0,
			'hassas_dosya_koru'     => isset( $_POST['hassas_dosya_koru'] ) ? 1 : 0,
			'kotu_bot_engelle'      => isset( $_POST['kotu_bot_engelle'] ) ? 1 : 0,
			'eposta_bildirimi'      => isset( $_POST['eposta_bildirimi'] ) ? 1 : 0,
			'bildirim_eposta'       => isset( $_POST['bildirim_eposta'] ) ? self::epostalari_temizle( wp_unslash( $_POST['bildirim_eposta'] ) ) : get_option( 'admin_email' ),
			'bildirim_throttle_dk'  => isset( $_POST['bildirim_throttle_dk'] ) ? max( 0, min( 1440, (int) $_POST['bildirim_throttle_dk'] ) ) : 60,
		);
		update_option( 'wpgk_ayarlar', $ayarlar );

		// Sertleştirme ayarları .htaccess'i etkilediği için yeniden yaz.
		WPGK_Hardening::htaccess_yaz();

		// Güvenilir admin listesini yeniden senkronla isteği.
		if ( isset( $_POST['wpgk_admin_senkron'] ) ) {
			$adminler = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) );
			update_option( 'wpgk_guvenilir_adminler', array_map( 'intval', wp_list_pluck( $adminler, 'ID' ) ) );
		}

		add_settings_error( 'wpgk', 'kaydedildi', 'Ayarlar kaydedildi.', 'updated' );
	}

	public function panel_render() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		settings_errors( 'wpgk' );

		// VirusTotal anlık tarama (URL veya SHA-256). Salt-okunur eylem; burada işlenir.
		$vt_sonuc = null;
		$vt_girdi = '';
		if ( isset( $_POST['wpgk_vt_nonce'] )
			&& wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_vt_nonce'] ) ), 'wpgk_vt_tara' )
			&& current_user_can( 'manage_options' ) ) {
			$vt_girdi = isset( $_POST['wpgk_vt_girdi'] ) ? sanitize_text_field( wp_unslash( $_POST['wpgk_vt_girdi'] ) ) : '';
			if ( '' !== $vt_girdi ) {
				$vt_sonuc = preg_match( '/^[a-fA-F0-9]{64}$/', $vt_girdi )
					? WPGK_VirusTotal::dosya_raporu( $vt_girdi )
					: WPGK_VirusTotal::url_raporu( $vt_girdi );
			}
		}

		$secenekler = array(
			'kullanici_korumasi'    => 'Kullanıcı koruması (yetkisiz admin oluşturma/rol yükseltme engelle)',
			'dosya_korumasi'        => 'Dosya koruması (root/uploads içine shell & PHP yazımını engelle)',
			'icerik_korumasi'       => 'İçerik koruması (porno/kumar/oyun spam linklerini engelle)',
			'exploit_korumasi'      => 'Exploit koruması (zafiyetli istek ve sızma denemelerini engelle)',
			'kotu_bot_engelle'      => 'Kötü bot / tarama aracı engelleme (sqlmap, nikto, wpscan vb.)',
			'giris_korumasi'        => 'Giriş koruması (brute-force / IP bazlı kilitleme)',
			'giris_jenerik_hata'    => 'Jenerik giriş hatası (kullanıcı adı sızdırmaz)',
			'guvenlik_basliklari'   => 'Güvenlik HTTP başlıkları (clickjacking/MIME-sniffing koruması)',
			'hsts'                  => 'HSTS başlığı (yalnızca tam HTTPS sitelerde açın)',
			'hsts_preload'          => 'HSTS preload (yalnızca tüm alt alan adları HTTPS ise; geri alması zordur)',
			'surum_gizle'           => 'WordPress sürümünü gizle (bilgi ifşasını azaltır)',
			'dizin_listeleme_kapat' => 'Dizin listelemeyi kapat (.htaccess)',
			'hassas_dosya_koru'     => 'Hassas dosyaları koru (wp-config, .htaccess, debug.log …)',
			'dosya_duzenleme_kapat' => 'Panel içi dosya düzenleyiciyi kapat (DISALLOW_FILE_EDIT)',
			'xmlrpc_kapat'          => 'XML-RPC arayüzünü kapat (brute-force/pingback istismarını azaltır)',
			'xmlrpc_tam_engel'      => 'XML-RPC tam engel (xmlrpc.php\'yi 403 ile tamamen kapat; Jetpack/mobil uygulama kullanıyorsanız kapalı tutun)',
			'pingback_kapat'        => 'Pingback & X-Pingback kaldır (pingback.ping / system.multicall DDoS-SSRF amplifikasyonunu engeller)',
			'sitemap_kullanici_gizle' => 'XML sitemap kullanıcı listesini gizle (/wp-sitemap-users-1.xml ile kullanıcı adı sızıntısını engeller)',
			'kok_klasor_korumasi'   => 'Kök klasör koruması (izinsiz klasör/SEO spam doorway tespiti)',
			'kok_klasor_otomatik_sil' => 'Zararlı kök klasörleri otomatik sil (önce tarar, kanıt bulursa siler)',
			'yapi_korumasi'         => 'WordPress klasör yapısı koruması (çekirdek dizin bütünlüğü)',
			'cekirdek_butunluk'     => 'Çekirdek dosya bütünlüğü (WordPress.org checksums ile doğrula)',
			'link_korumasi'         => 'Zararlı link koruması (ön yüzde spam linklerini otomatik temizle)',
			'eposta_bildirimi'      => 'Kritik olaylarda e-posta bildirimi gönder',
		);
		// Gruplandırılmış koruma seçenekleri (kullanıcı dostu kartlar).
		$gruplar = array(
			'Giriş & Kullanıcı'        => array( 'kullanici_korumasi', 'giris_korumasi', 'giris_jenerik_hata' ),
			'Ağ & İstek (Firewall)'    => array( 'exploit_korumasi', 'kotu_bot_engelle', 'xmlrpc_kapat', 'xmlrpc_tam_engel', 'pingback_kapat', 'sitemap_kullanici_gizle' ),
			'Dosya & Sistem'           => array( 'dosya_korumasi', 'dosya_duzenleme_kapat', 'cekirdek_butunluk', 'yapi_korumasi', 'kok_klasor_korumasi', 'kok_klasor_otomatik_sil', 'hassas_dosya_koru', 'dizin_listeleme_kapat' ),
			'Sertleştirme (Hardening)' => array( 'guvenlik_basliklari', 'surum_gizle', 'hsts', 'hsts_preload' ),
			'İçerik'                   => array( 'icerik_korumasi', 'link_korumasi' ),
		);

		// Pano metrikleri.
		$sayim       = WPGK_Logger::seviye_sayimlari( 24 );
		$tum_toggle  = array_merge( array( 'eposta_bildirimi' ), $gruplar['Giriş & Kullanıcı'], $gruplar['Ağ & İstek (Firewall)'], $gruplar['Dosya & Sistem'], $gruplar['Sertleştirme (Hardening)'], $gruplar['İçerik'] );
		$aktif_sayi  = 0;
		foreach ( $tum_toggle as $k ) {
			if ( ! empty( $ayarlar[ $k ] ) ) {
				$aktif_sayi++;
			}
		}
		$toplam_modul = count( $tum_toggle );
		$vt_aktif     = WPGK_VirusTotal::aktif();
		$son_tarama   = get_option( 'wpgk_son_tarama', '' );
		?>
		<div class="wrap wpgk-wrap">
			<h1><span class="dashicons dashicons-shield" style="font-size:28px;width:28px;height:28px;vertical-align:-4px;"></span> WP Radar</h1>
			<p class="description">Kapsamlı WordPress güvenlik radarı: brute-force, sızma, zararlı dosya/klasör, spam link koruması ve VirusTotal itibar kontrolü.</p>

			<style>
				.wpgk-cards{display:flex;flex-wrap:wrap;gap:14px;margin:16px 0 24px}
				.wpgk-card{flex:1 1 200px;background:#fff;border:1px solid #dcdcde;border-left-width:4px;border-radius:6px;padding:14px 16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
				.wpgk-card .num{font-size:26px;font-weight:600;line-height:1.2}
				.wpgk-card .lbl{color:#646970;font-size:12px;text-transform:uppercase;letter-spacing:.3px}
				.wpgk-card.ok{border-left-color:#00a32a}.wpgk-card.warn{border-left-color:#dba617}.wpgk-card.bad{border-left-color:#d63638}.wpgk-card.info{border-left-color:#2271b1}
				.wpgk-section{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:4px 18px 10px;margin:0 0 18px}
				.wpgk-section h2{font-size:15px;margin:14px 0 4px;padding-bottom:8px;border-bottom:1px solid #f0f0f1}
				.wpgk-toggle{display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid #f6f7f7}
				.wpgk-toggle:last-child{border-bottom:0}
				.wpgk-toggle input{margin-top:3px}
				.wpgk-badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}
				.wpgk-badge.on{background:#edfaef;color:#00782b}.wpgk-badge.off{background:#fcf0f1;color:#b32d2e}
			</style>

			<!-- DURUM PANOSU -->
			<div class="wpgk-cards">
				<div class="wpgk-card ok">
					<div class="num"><?php echo (int) $aktif_sayi; ?>/<?php echo (int) $toplam_modul; ?></div>
					<div class="lbl">Aktif koruma modülü</div>
				</div>
				<div class="wpgk-card <?php echo $sayim['kritik'] > 0 ? 'bad' : 'ok'; ?>">
					<div class="num"><?php echo (int) $sayim['kritik']; ?></div>
					<div class="lbl">Son 24s kritik olay</div>
				</div>
				<div class="wpgk-card <?php echo $sayim['uyari'] > 0 ? 'warn' : 'ok'; ?>">
					<div class="num"><?php echo (int) $sayim['uyari']; ?></div>
					<div class="lbl">Son 24s uyarı</div>
				</div>
				<div class="wpgk-card <?php echo $vt_aktif ? 'ok' : 'info'; ?>">
					<div class="num"><span class="wpgk-badge <?php echo $vt_aktif ? 'on' : 'off'; ?>"><?php echo $vt_aktif ? 'Aktif' : 'Pasif'; ?></span></div>
					<div class="lbl">VirusTotal</div>
				</div>
				<div class="wpgk-card info">
					<div class="num" style="font-size:15px;padding-top:6px;"><?php echo $son_tarama ? esc_html( $son_tarama ) : '—'; ?></div>
					<div class="lbl">Son tarama</div>
				</div>
			</div>

			<form method="post" style="margin-bottom:20px;">
				<?php wp_nonce_field( 'wpgk_tarama', 'wpgk_tara_nonce' ); ?>
				<?php submit_button( 'Şimdi Tara', 'primary large', 'wpgk_tara_simdi', false ); ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpgk-gunluk' ) ); ?>" class="button button-secondary" style="margin-left:6px;">Olay Günlüğü</a>
				<span class="description" style="margin-left:8px;">Önce tarar, ardından kanıtlı zararlıları engeller.</span>
			</form>

			<!-- VIRUSTOTAL ARACI -->
			<div class="wpgk-section">
				<h2><span class="dashicons dashicons-search" style="vertical-align:-3px;"></span> VirusTotal ile Tara</h2>
				<p class="description">Bir URL veya dosya SHA-256 özetini 70+ güvenlik motoruyla kontrol edin. <?php echo $vt_aktif ? '' : '<strong>Önce aşağıdan API anahtarını kaydedin.</strong>'; ?></p>
				<form method="post" style="margin:8px 0;">
					<?php wp_nonce_field( 'wpgk_vt_tara', 'wpgk_vt_nonce' ); ?>
					<input type="text" name="wpgk_vt_girdi" class="regular-text" style="width:60%;" placeholder="https://ornek.com/  veya  SHA-256 özeti" value="<?php echo esc_attr( $vt_girdi ); ?>" <?php disabled( ! $vt_aktif ); ?> />
					<?php submit_button( 'Tara', 'secondary', 'wpgk_vt_gonder', false, $vt_aktif ? array() : array( 'disabled' => 'disabled' ) ); ?>
				</form>
				<?php if ( null !== $vt_sonuc ) : ?>
					<?php if ( is_wp_error( $vt_sonuc ) ) : ?>
						<div class="notice notice-error inline"><p><?php echo esc_html( $vt_sonuc->get_error_message() ); ?></p></div>
					<?php elseif ( ! empty( $vt_sonuc['beklemede'] ) ) : ?>
						<div class="notice notice-info inline"><p><?php echo esc_html( $vt_sonuc['mesaj'] ); ?></p></div>
					<?php elseif ( empty( $vt_sonuc['bulundu'] ) ) : ?>
						<div class="notice notice-warning inline"><p>VirusTotal kaydı bulunamadı (bu öğe daha önce taranmamış).</p></div>
					<?php else :
						$z = (int) $vt_sonuc['zararli'];
						$s = (int) $vt_sonuc['supheli'];
						$t = (int) $vt_sonuc['toplam'];
						$sinif = $z > 0 ? 'error' : ( $s > 0 ? 'warning' : 'success' );
						?>
						<div class="notice notice-<?php echo esc_attr( $sinif ); ?> inline">
							<p>
								<strong><?php echo esc_html( $z ); ?>/<?php echo esc_html( $t ); ?></strong> motor <strong>zararlı</strong>, <strong><?php echo esc_html( $s ); ?></strong> şüpheli olarak işaretledi.
								<?php if ( ! empty( $vt_sonuc['gui'] ) ) : ?>
									&nbsp;<a href="<?php echo esc_url( $vt_sonuc['gui'] ); ?>" target="_blank" rel="noopener">VirusTotal'da aç ↗</a>
								<?php endif; ?>
							</p>
						</div>
					<?php endif; ?>
				<?php endif; ?>
			</div>

			<!-- AYARLAR -->
			<form method="post">
				<?php wp_nonce_field( 'wpgk_ayar_kaydet', 'wpgk_ayar_nonce' ); ?>

				<?php foreach ( $gruplar as $baslik => $anahtarlar ) : ?>
					<div class="wpgk-section">
						<h2><?php echo esc_html( $baslik ); ?></h2>
						<?php foreach ( $anahtarlar as $anahtar ) : ?>
							<label class="wpgk-toggle">
								<input type="checkbox" name="<?php echo esc_attr( $anahtar ); ?>" value="1" <?php checked( ! empty( $ayarlar[ $anahtar ] ) ); ?> />
								<span><?php echo esc_html( isset( $secenekler[ $anahtar ] ) ? $secenekler[ $anahtar ] : $anahtar ); ?></span>
							</label>
						<?php endforeach; ?>

						<?php if ( 'Giriş & Kullanıcı' === $baslik ) : ?>
							<div style="padding:12px 0 6px;">
								<strong>Giriş kilidi eşiği:</strong>
								<input type="number" name="giris_max_deneme" min="1" max="50" value="<?php echo esc_attr( isset( $ayarlar['giris_max_deneme'] ) ? $ayarlar['giris_max_deneme'] : 5 ); ?>" class="small-text" /> başarısız denemeden sonra
								<input type="number" name="giris_kilit_dk" min="1" max="1440" value="<?php echo esc_attr( isset( $ayarlar['giris_kilit_dk'] ) ? $ayarlar['giris_kilit_dk'] : 15 ); ?>" class="small-text" /> dakika kilitle.
							</div>
							<label class="wpgk-toggle">
								<input type="checkbox" name="proxy_guven" value="1" <?php checked( ! empty( $ayarlar['proxy_guven'] ) ); ?> />
								<span>IP kaynağı: proxy/CDN başlıklarına (X-Forwarded-For / CF-Connecting-IP) güven. <strong>Site bir CDN/ters proxy arkasındaysa açık tutun</strong> (Hostinger CDN, Cloudflare vb.). Doğrudan erişimli bir siteyse, IP sahteciliğiyle giriş-kilidi atlatmayı önlemek için <strong>kapatın</strong> (yalnızca REMOTE_ADDR kullanılır).</span>
							</label>
						<?php elseif ( 'Dosya & Sistem' === $baslik ) : ?>
							<div style="padding:12px 0 6px;">
								<strong>İzinli kök klasörler:</strong>
								<textarea name="kok_izinli" rows="2" class="large-text" placeholder="Her satıra bir klasör adı (ör. shop, blog)"><?php echo esc_textarea( isset( $ayarlar['kok_izinli'] ) ? $ayarlar['kok_izinli'] : '' ); ?></textarea>
								<p class="description">wp-admin, wp-content, wp-includes ve sistem klasörleri zaten izinlidir. Kök dizinde meşru özel bir klasörünüz varsa adını buraya ekleyin.</p>
							</div>
						<?php elseif ( 'İçerik' === $baslik ) : ?>
							<div style="padding:12px 0 6px;">
								<strong>Zararlı domainler (kara liste):</strong>
								<textarea name="zararli_domainler" rows="2" class="large-text" placeholder="Her satıra bir domain (ör. kotusite.com)"><?php echo esc_textarea( isset( $ayarlar['zararli_domainler'] ) ? $ayarlar['zararli_domainler'] : '' ); ?></textarea>
								<p class="description">Bu domainlere giden bağlantılar ön yüzde otomatik temizlenir (alt alan adları dahil).</p>
							</div>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>

				<!-- VIRUSTOTAL AYARI -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-shield-alt" style="vertical-align:-3px;"></span> VirusTotal</h2>
					<?php $vt_kayitli = ! empty( $ayarlar['vt_api_key'] ); ?>
					<div style="padding:10px 0 6px;">
						<strong>API anahtarı:</strong>
						<input type="password" name="vt_api_key" class="regular-text" autocomplete="off" value="" placeholder="<?php echo esc_attr( $vt_kayitli ? '•••••••• kayıtlı — değiştirmek için yeni anahtar girin' : 'VirusTotal API anahtarınız' ); ?>" />
						<?php if ( $vt_kayitli ) : ?>
							<label style="margin-left:10px;"><input type="checkbox" name="wpgk_vt_temizle" value="1" /> Anahtarı kaldır</label>
						<?php endif; ?>
						<p class="description"><a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener">virustotal.com</a> üzerinden ücretsiz bir hesap açıp API anahtarınızı buraya yapıştırın. Anahtar güvenlik için maskelenir; boş bırakıp kaydederseniz mevcut anahtar korunur. Ücretsiz anahtar ~4 istek/dakika ile sınırlıdır.</p>
					</div>
					<label class="wpgk-toggle">
						<input type="checkbox" name="vt_otomatik" value="1" <?php checked( ! empty( $ayarlar['vt_otomatik'] ) ); ?> />
						<span>Otomatik doğrulama: uploads taramasında bulunan şüpheli dosyaların SHA-256 özetini VirusTotal ile doğrula (çalışma başına en fazla 4 sorgu).</span>
					</label>
				</div>

				<!-- GİRİŞ GÜVENLİĞİ (2FA / CAPTCHA / IP) -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-lock" style="vertical-align:-3px;"></span> Giriş Güvenliği</h2>
					<label class="wpgk-toggle">
						<input type="checkbox" name="giris_2fa" value="1" <?php checked( ! empty( $ayarlar['giris_2fa'] ) ); ?> />
						<span>İki faktörlü doğrulama (2FA / TOTP) etkin. Açtıktan sonra her kullanıcı <a href="<?php echo esc_url( admin_url( 'admin.php?page=wpgk-2fa' ) ); ?>">2FA Kurulumu</a> sayfasından kendi hesabını korumalı (Google Authenticator vb.).</span>
					</label>
					<label class="wpgk-toggle">
						<input type="checkbox" name="giris_captcha" value="1" <?php checked( ! empty( $ayarlar['giris_captcha'] ) ); ?> />
						<span>Giriş formunda CAPTCHA (basit matematik sorusu) — otomatik giriş botlarını yavaşlatır.</span>
					</label>
					<div style="padding:12px 0 6px;">
						<strong>IP beyaz listesi (engelleri atlar):</strong>
						<textarea name="ip_beyaz_liste" rows="2" class="large-text" placeholder="Her satıra bir IP veya CIDR (ör. 203.0.113.5 veya 203.0.113.0/24)"><?php echo esc_textarea( isset( $ayarlar['ip_beyaz_liste'] ) ? $ayarlar['ip_beyaz_liste'] : '' ); ?></textarea>
						<p class="description">Buradaki IP'ler tüm WP Radar engellerinden muaftır (kendi IP'nizi eklemeniz önerilir — kazara kilitlenmeyi önler).</p>
					</div>
					<div style="padding:6px 0;">
						<strong>IP kara listesi (tamamen engellenir):</strong>
						<textarea name="ip_kara_liste" rows="2" class="large-text" placeholder="Her satıra bir IP veya CIDR"><?php echo esc_textarea( isset( $ayarlar['ip_kara_liste'] ) ? $ayarlar['ip_kara_liste'] : '' ); ?></textarea>
						<p class="description">Bu IP/bloklardan gelen tüm istekler 403 ile reddedilir.</p>
					</div>
				</div>

				<!-- ORAN SINIRLAMA -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-performance" style="vertical-align:-3px;"></span> Oran Sınırlama (Rate Limiting)</h2>
					<label class="wpgk-toggle">
						<input type="checkbox" name="oran_limit" value="1" <?php checked( ! empty( $ayarlar['oran_limit'] ) ); ?> />
						<span>Tek IP'den gelen aşırı isteği frenle (agresif bot / kazıma / uygulama DoS). Yöneticiler ve beyaz listedeki IP'ler muaftır.</span>
					</label>
					<div style="padding:8px 0;">
						<input type="number" name="oran_max" min="10" max="100000" value="<?php echo esc_attr( isset( $ayarlar['oran_max'] ) ? $ayarlar['oran_max'] : 120 ); ?>" class="small-text" /> istek /
						<input type="number" name="oran_pencere_sn" min="10" max="3600" value="<?php echo esc_attr( isset( $ayarlar['oran_pencere_sn'] ) ? $ayarlar['oran_pencere_sn'] : 60 ); ?>" class="small-text" /> saniyeyi aşarsa,
						<input type="number" name="oran_kilit_dk" min="1" max="1440" value="<?php echo esc_attr( isset( $ayarlar['oran_kilit_dk'] ) ? $ayarlar['oran_kilit_dk'] : 10 ); ?>" class="small-text" /> dakika engelle.
						<p class="description">Engellenen istekler Olay Günlüğü'ne (canlı trafik görünümü) yazılır. Çok düşük değerler meşru ziyaretçileri etkileyebilir.</p>
					</div>
				</div>

				<!-- ÜLKE ENGELLEME (GEOIP) -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-admin-site" style="vertical-align:-3px;"></span> Ülke Engelleme (GeoIP)</h2>
					<label class="wpgk-toggle">
						<input type="checkbox" name="ulke_engel" value="1" <?php checked( ! empty( $ayarlar['ulke_engel'] ) ); ?> />
						<span>Belirli ülkelerden erişimi engelle. Servis erişilemezse erişim engellenmez (fail-open).</span>
					</label>
					<div style="padding:8px 0;">
						<strong>Engellenecek ülke kodları (ISO-2):</strong>
						<input type="text" name="engelli_ulkeler" class="regular-text" value="<?php echo esc_attr( isset( $ayarlar['engelli_ulkeler'] ) ? $ayarlar['engelli_ulkeler'] : '' ); ?>" placeholder="ör. RU, CN, KP" />
						<p class="description">Virgülle ayırın. Boşsa engelleme yapılmaz.</p>
					</div>
					<div style="padding:6px 0;">
						<strong>GeoIP sağlayıcı:</strong>
						<label style="margin-right:12px;"><input type="radio" name="geoip_saglayici" value="ip-api" <?php checked( 'ipinfo' !== ( isset( $ayarlar['geoip_saglayici'] ) ? $ayarlar['geoip_saglayici'] : 'ip-api' ) ); ?> /> ip-api (anahtarsız)</label>
						<label><input type="radio" name="geoip_saglayici" value="ipinfo" <?php checked( 'ipinfo' === ( isset( $ayarlar['geoip_saglayici'] ) ? $ayarlar['geoip_saglayici'] : '' ) ); ?> /> ipinfo (token)</label>
						<input type="text" name="geoip_token" class="regular-text" style="margin-left:8px;" value="<?php echo esc_attr( isset( $ayarlar['geoip_token'] ) ? $ayarlar['geoip_token'] : '' ); ?>" placeholder="ipinfo token (yalnızca ipinfo için)" />
						<p class="description">ip-api ücretsiz/anahtarsızdır (ticari olmayan kullanım, HTTP). Yoğun ticari trafikte ipinfo (token, HTTPS) önerilir. Sonuçlar IP başına 12 saat önbelleğe alınır.</p>
					</div>
				</div>

				<!-- ZAFİYET TARAMASI -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-search" style="vertical-align:-3px;"></span> Zafiyet Taraması (WPScan)</h2>
					<label class="wpgk-toggle">
						<input type="checkbox" name="vuln_tarama" value="1" <?php checked( ! empty( $ayarlar['vuln_tarama'] ) ); ?> />
						<span>Kurulu eklenti/tema/çekirdek sürümlerini bilinen güvenlik açıklarına karşı günlük tara. Açık bulunursa kritik olay + e-posta.</span>
					</label>
					<?php $ws_kayitli = ! empty( $ayarlar['wpscan_token'] ); ?>
					<div style="padding:8px 0;">
						<strong>WPScan API token:</strong>
						<input type="password" name="wpscan_token" class="regular-text" autocomplete="off" value="<?php echo esc_attr( isset( $ayarlar['wpscan_token'] ) ? $ayarlar['wpscan_token'] : '' ); ?>" placeholder="<?php echo esc_attr( $ws_kayitli ? '•••• kayıtlı' : 'WPScan API token' ); ?>" />
						<p class="description"><a href="https://wpscan.com/api" target="_blank" rel="noopener">wpscan.com/api</a> üzerinden ücretsiz token alın (~25 istek/gün). Token olmadan bu modül çalışmaz.</p>
					</div>
				</div>

				<!-- BİLDİRİM -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-email-alt" style="vertical-align:-3px;"></span> Bildirim</h2>
					<label class="wpgk-toggle">
						<input type="checkbox" name="eposta_bildirimi" value="1" <?php checked( ! empty( $ayarlar['eposta_bildirimi'] ) ); ?> />
						<span>Kritik olaylarda e-posta bildirimi gönder</span>
					</label>
					<div style="padding:10px 0 6px;">
						<strong>Bildirim e-posta adresleri:</strong>
						<textarea name="bildirim_eposta" rows="2" class="regular-text" placeholder="Her satıra bir e-posta adresi (veya virgülle ayırın)"><?php echo esc_textarea( isset( $ayarlar['bildirim_eposta'] ) ? $ayarlar['bildirim_eposta'] : get_option( 'admin_email' ) ); ?></textarea>
						<p class="description">Kritik güvenlik olaylarında bu adreslere anlık e-posta gönderilir. Birden çok adres ekleyebilirsiniz.</p>
					</div>
					<div style="padding:6px 0;">
						<strong>Tekrar-bildirim engeli:</strong> Aynı saldırı için
						<input type="number" name="bildirim_throttle_dk" min="0" max="1440" value="<?php echo esc_attr( isset( $ayarlar['bildirim_throttle_dk'] ) ? $ayarlar['bildirim_throttle_dk'] : 60 ); ?>" class="small-text" /> dakikada bir bildir.
						<p class="description">Bildirimler <strong>olay türü + saldıran IP bloğu (/24)</strong> bazında gruplanır; aynı kaynaktan gelen yüzlerce istek için tek e-posta gider. İlk olay anında iletilir. <strong>0</strong> = her olayda, <strong>1440</strong> = günde bir.</p>
					</div>
				</div>

				<!-- GÜVENİLİR YÖNETİCİLER -->
				<div class="wpgk-section">
					<h2><span class="dashicons dashicons-admin-users" style="vertical-align:-3px;"></span> Güvenilir Yöneticiler</h2>
					<p style="margin:8px 0;">
						<?php
						$guvenilir = WPGK_User_Guard::guvenilir_adminler();
						if ( $guvenilir ) {
							$adlar = array();
							foreach ( $guvenilir as $id ) {
								$u = get_userdata( $id );
								if ( $u ) {
									$adlar[] = esc_html( $u->user_login . ' (ID ' . $id . ')' );
								}
							}
							echo wp_kses_post( implode( ', ', $adlar ) );
						} else {
							echo 'Tanımlı değil';
						}
						?>
					</p>
					<label class="wpgk-toggle"><input type="checkbox" name="wpgk_admin_senkron" value="1" /> <span>Mevcut tüm yöneticileri güvenilir listeyle yeniden senkronla</span></label>
					<p class="description">Dikkat: Senkron, o anda var olan tüm administrator hesaplarını güvenilir kabul eder. Yalnızca hesapların temiz olduğundan eminseniz işaretleyin.</p>
				</div>

				<?php submit_button( 'Ayarları Kaydet', 'primary large' ); ?>
			</form>

			<form method="post" style="margin-top:-6px;">
				<?php wp_nonce_field( 'wpgk_test_mail', 'wpgk_test_mail_nonce' ); ?>
				<?php submit_button( 'Test E-postası Gönder', 'secondary', 'wpgk_test_mail_gonder', false ); ?>
				<span class="description" style="margin-left:8px;">Kayıtlı alıcılara bir test bildirimi yollar. Önce adresleri kaydedin, sonra test edin.</span>
			</form>
		</div>
		<?php
	}

	public function gunluk_render() {
		$olaylar = WPGK_Logger::son_olaylar( 200 );
		?>
		<div class="wrap">
			<h1>Olay Günlüğü</h1>
			<table class="widefat striped">
				<thead>
					<tr>
						<th>Zaman</th><th>Seviye</th><th>Modül</th><th>Olay</th><th>Mesaj</th><th>IP</th>
					</tr>
				</thead>
				<tbody>
				<?php if ( $olaylar ) : ?>
					<?php foreach ( $olaylar as $o ) : ?>
						<tr>
							<td><?php echo esc_html( $o->zaman ); ?></td>
							<td><?php echo esc_html( $o->seviye ); ?></td>
							<td><?php echo esc_html( $o->modul ); ?></td>
							<td><?php echo esc_html( $o->olay ); ?></td>
							<td><?php echo esc_html( $o->mesaj ); ?></td>
							<td><?php echo esc_html( $o->ip ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr><td colspan="6">Henüz olay kaydı yok.</td></tr>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * Son 24 saatte kritik olay varsa panelde uyarı göster.
	 */
	public function kritik_uyari_goster() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// Saat dilimi tutarlılığı için merkezi sayım metodunu kullan (zaman yerel
		// saatle saklanır; doğrudan time()/gmdate karşılaştırması offset hatası verir).
		$sayimlar = WPGK_Logger::seviye_sayimlari( 24 );
		$sayi     = (int) $sayimlar['kritik'];
		if ( $sayi > 0 ) {
			printf(
				'<div class="notice notice-error"><p><strong>WP Radar:</strong> Son 24 saatte %d kritik güvenlik olayı tespit edildi. <a href="%s">Olay günlüğünü inceleyin</a>.</p></div>',
				esc_html( $sayi ),
				esc_url( admin_url( 'admin.php?page=wpgk-gunluk' ) )
			);
		}
	}
}
