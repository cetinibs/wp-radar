<?php
/**
 * Sertleştirme (hardening): güvenlik HTTP başlıkları, WordPress sürüm/bilgi
 * gizleme ve .htaccess ile dizin listeleme + hassas dosya koruması.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Hardening {

	const HTACCESS_ETIKET = 'WP Radar';

	public function __construct() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );

		if ( ! empty( $ayarlar['guvenlik_basliklari'] ) ) {
			add_action( 'send_headers', array( $this, 'guvenlik_basliklari' ) );
		}

		if ( ! empty( $ayarlar['surum_gizle'] ) ) {
			$this->surum_gizle();
		}
	}

	/**
	 * Güvenlik HTTP başlıkları (clickjacking, MIME-sniffing, referrer sızıntısı).
	 */
	public function guvenlik_basliklari() {
		if ( headers_sent() ) {
			return;
		}
		$ayarlar = get_option( 'wpgk_ayarlar', array() );

		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
		header( 'X-XSS-Protection: 0' ); // Modern tarayıcılarda CSP tercih edilir; eski XSS auditor kapatılır.

		if ( ! empty( $ayarlar['hsts'] ) && is_ssl() ) {
			$hsts = 'max-age=31536000; includeSubDomains';
			if ( ! empty( $ayarlar['hsts_preload'] ) ) {
				$hsts .= '; preload';
			}
			header( 'Strict-Transport-Security: ' . $hsts );
		}
	}

	/**
	 * WordPress sürümünü ve gereksiz bilgi ifşasını gizler.
	 */
	protected function surum_gizle() {
		// <meta name="generator"> kaldır.
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		// RSS jeneratör etiketlerini temizle.
		foreach ( array( 'rss2_head', 'commentsrss2_head', 'rss_head', 'rdf_header', 'atom_head', 'comments_atom_head', 'opml_head', 'app_head' ) as $kanca ) {
			add_filter( $kanca, array( $this, 'generator_temizle' ), 9 );
		}

		// Script/style sürüm sorgu parametrelerini (?ver=x.y) kaldır.
		add_filter( 'style_loader_src', array( $this, 'surum_parametresi_temizle' ), 9999 );
		add_filter( 'script_loader_src', array( $this, 'surum_parametresi_temizle' ), 9999 );

		// X-Powered-By gibi başlıkları kaldırmaya çalış.
		if ( ! headers_sent() && function_exists( 'header_remove' ) ) {
			@header_remove( 'X-Powered-By' );
		}
	}

	public function generator_temizle() {
		return '';
	}

	/**
	 * Çekirdek/eklenti varlık URL'lerinden WordPress sürümünü taşıyan ?ver= değerini temizler.
	 */
	public function surum_parametresi_temizle( $src ) {
		global $wp_version;
		if ( $src && false !== strpos( $src, 'ver=' ) ) {
			// Yalnızca WP çekirdek sürümünü maskele (eklenti sürümlerine dokunma riski düşük tut).
			if ( isset( $wp_version ) && false !== strpos( $src, 'ver=' . $wp_version ) ) {
				$src = remove_query_arg( 'ver', $src );
			}
		}
		return $src;
	}

	/**
	 * .htaccess'e güvenlik kurallarını yazar (Apache).
	 */
	public static function htaccess_yaz() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$htaccess = self::htaccess_yolu();
		if ( ! $htaccess ) {
			return;
		}

		$kurallar = array();

		if ( ! empty( $ayarlar['dizin_listeleme_kapat'] ) ) {
			$kurallar[] = '# Dizin listelemeyi kapat';
			$kurallar[] = 'Options -Indexes';
			$kurallar[] = '';
		}

		if ( ! empty( $ayarlar['hassas_dosya_koru'] ) ) {
			$kurallar[] = '# Hassas dosyalara erişimi engelle';
			$kurallar[] = '<FilesMatch "^(wp-config\.php|wp-config-sample\.php|\.htaccess|\.htpasswd|readme\.html|readme\.txt|license\.txt|debug\.log)$">';
			$kurallar[] = '<IfModule mod_authz_core.c>';
			$kurallar[] = '  Require all denied';
			$kurallar[] = '</IfModule>';
			$kurallar[] = '<IfModule !mod_authz_core.c>';
			$kurallar[] = '  Order allow,deny';
			$kurallar[] = '  Deny from all';
			$kurallar[] = '</IfModule>';
			$kurallar[] = '</FilesMatch>';
			$kurallar[] = '';
			$kurallar[] = '# Yedek/dump/log uzantılarını engelle';
			$kurallar[] = '<FilesMatch "\.(sql|bak|old|orig|save|swp|swo|tmp|log|ini|sh)$">';
			$kurallar[] = '<IfModule mod_authz_core.c>';
			$kurallar[] = '  Require all denied';
			$kurallar[] = '</IfModule>';
			$kurallar[] = '<IfModule !mod_authz_core.c>';
			$kurallar[] = '  Order allow,deny';
			$kurallar[] = '  Deny from all';
			$kurallar[] = '</IfModule>';
			$kurallar[] = '</FilesMatch>';
		}

		require_once ABSPATH . 'wp-admin/includes/misc.php';
		if ( function_exists( 'insert_with_markers' ) ) {
			insert_with_markers( $htaccess, self::HTACCESS_ETIKET, $kurallar );
		}
	}

	/**
	 * Eklenti devre dışı bırakılınca .htaccess kurallarını kaldırır.
	 */
	public static function htaccess_temizle() {
		$htaccess = self::htaccess_yolu();
		if ( ! $htaccess ) {
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		if ( function_exists( 'insert_with_markers' ) ) {
			insert_with_markers( $htaccess, self::HTACCESS_ETIKET, array() );
		}
	}

	/**
	 * Yazılabilir .htaccess yolunu döndürür (yoksa oluşturmayı dener).
	 */
	protected static function htaccess_yolu() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$yol = get_home_path() . '.htaccess';
		if ( file_exists( $yol ) && is_writable( $yol ) ) {
			return $yol;
		}
		// Yoksa ve dizin yazılabilirse oluştur.
		if ( ! file_exists( $yol ) && is_writable( dirname( $yol ) ) ) {
			return $yol;
		}
		return false;
	}
}
