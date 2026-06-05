<?php
/**
 * Plugin Name:       WP Radar
 * Plugin URI:        https://example.com/wp-radar
 * Description:        Kapsamlı WordPress güvenlik radarı: brute-force/giriş koruması, güvenlik başlıkları ve sertleştirme, çekirdek dosya bütünlüğü, eklenti/tema açığı sızma engeli, yetkisiz kullanıcı/kök klasör tespiti ve zararlı link/SEO spam temizliği.
 * Version:           2.2.1
 * Requires at least: 5.0
 * Requires PHP:      7.0
 * Author:            WP Radar
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-radar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Doğrudan erişim engellendi.
}

define( 'WPGK_VERSION', '2.2.1' );
define( 'WPGK_FILE', __FILE__ );
define( 'WPGK_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPGK_URL', plugin_dir_url( __FILE__ ) );
define( 'WPGK_BASENAME', plugin_basename( __FILE__ ) );

require_once WPGK_DIR . 'includes/class-wpgk-util.php';
require_once WPGK_DIR . 'includes/class-wpgk-logger.php';
require_once WPGK_DIR . 'includes/class-wpgk-user-guard.php';
require_once WPGK_DIR . 'includes/class-wpgk-file-guard.php';
require_once WPGK_DIR . 'includes/class-wpgk-content-guard.php';
require_once WPGK_DIR . 'includes/class-wpgk-exploit-guard.php';
require_once WPGK_DIR . 'includes/class-wpgk-login-guard.php';
require_once WPGK_DIR . 'includes/class-wpgk-hardening.php';
require_once WPGK_DIR . 'includes/class-wpgk-admin.php';
require_once WPGK_DIR . 'includes/class-wpgk-plugin.php';

/**
 * Çekirdek bootstrap.
 */
function wpgk_baslat() {
	return WPGK_Plugin::instance();
}
add_action( 'plugins_loaded', 'wpgk_baslat', 1 );

/**
 * Varsayılan ayarlar.
 */
function wpgk_varsayilan_ayarlar() {
	return array(
		// Çekirdek korumalar
		'kullanici_korumasi'      => 1,
		'dosya_korumasi'          => 1,
		'icerik_korumasi'         => 1,
		'exploit_korumasi'        => 1,
		'dosya_duzenleme_kapat'   => 1,
		'xmlrpc_kapat'            => 1,
		'xmlrpc_tam_engel'        => 1,
		'pingback_kapat'          => 1,
		'sitemap_kullanici_gizle' => 1,
		// Kök klasör / yapı
		'kok_klasor_korumasi'     => 1,
		'kok_klasor_otomatik_sil' => 1,
		'kok_izinli'              => '',
		'yapi_korumasi'           => 1,
		'cekirdek_butunluk'       => 1,
		// İçerik / link
		'link_korumasi'           => 1,
		'zararli_domainler'       => '',
		// Giriş / brute-force
		'giris_korumasi'          => 1,
		'giris_max_deneme'        => 5,
		'giris_kilit_dk'          => 15,
		'giris_jenerik_hata'      => 1,
		// Sertleştirme
		'guvenlik_basliklari'     => 1,
		'hsts'                    => 0,
		'hsts_preload'            => 0,
		'surum_gizle'             => 1,
		'dizin_listeleme_kapat'   => 1,
		'hassas_dosya_koru'       => 1,
		'kotu_bot_engelle'        => 1,
		// Bildirim
		'bildirim_eposta'         => get_option( 'admin_email' ),
		'eposta_bildirimi'        => 1,
		'bildirim_throttle_dk'    => 60,
	);
}

/**
 * Etkinleştirme.
 */
function wpgk_etkinlestir() {
	if ( false === get_option( 'wpgk_ayarlar' ) ) {
		add_option( 'wpgk_ayarlar', wpgk_varsayilan_ayarlar() );
	} else {
		// Yükseltmede yeni anahtarları mevcut ayarlara ekle.
		$mevcut = get_option( 'wpgk_ayarlar', array() );
		update_option( 'wpgk_ayarlar', array_merge( wpgk_varsayilan_ayarlar(), (array) $mevcut ) );
	}

	// Kurulum anındaki yöneticileri "güvenilir" olarak kilitle.
	if ( false === get_option( 'wpgk_guvenilir_adminler' ) ) {
		$adminler = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) );
		$ids      = wp_list_pluck( $adminler, 'ID' );
		add_option( 'wpgk_guvenilir_adminler', array_map( 'intval', $ids ) );
	}

	WPGK_Logger::tablo_olustur();
	WPGK_File_Guard::baseline_olustur();
	WPGK_Hardening::htaccess_yaz();

	if ( ! wp_next_scheduled( 'wpgk_gunluk_tarama' ) ) {
		wp_schedule_event( time(), 'daily', 'wpgk_gunluk_tarama' );
	}
	if ( ! wp_next_scheduled( 'wpgk_saatlik_tarama' ) ) {
		wp_schedule_event( time(), 'hourly', 'wpgk_saatlik_tarama' );
	}

	WPGK_File_Guard::kok_klasor_tara();
}
register_activation_hook( __FILE__, 'wpgk_etkinlestir' );

/**
 * Devre dışı bırakma: zamanlanmış görevleri ve .htaccess kurallarını temizler.
 */
function wpgk_devre_disi() {
	foreach ( array( 'wpgk_gunluk_tarama', 'wpgk_saatlik_tarama' ) as $kanca ) {
		$zaman = wp_next_scheduled( $kanca );
		if ( $zaman ) {
			wp_unschedule_event( $zaman, $kanca );
		}
	}
	WPGK_Hardening::htaccess_temizle();
}
register_deactivation_hook( __FILE__, 'wpgk_devre_disi' );
