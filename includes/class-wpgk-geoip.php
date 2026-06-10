<?php
/**
 * Ülke bazlı engelleme (GeoIP).
 *
 * Belirli ülkelerden gelen erişimi engeller. IP→ülke çözümü harici bir
 * IP-geo servisinden alınır ve IP başına önbelleğe alınır (varsayılan 12 saat).
 * Servis erişilemezse veya yapılandırılmamışsa erişim ENGELLENMEZ (fail-open) —
 * böylece bir API kesintisi siteyi kilitlemez.
 *
 * Sağlayıcılar:
 *  - ip-api  : anahtarsız (ücretsiz; ticari olmayan kullanım, ~45 istek/dk, HTTP).
 *  - ipinfo  : token gerektirir (HTTPS).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_GeoIP {

	public function __construct() {
		add_action( 'init', array( $this, 'denetle' ), 2 );
	}

	/**
	 * Engellenecek ülke kodları (ISO-2, büyük harf).
	 */
	protected static function engelli_ulkeler() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$ham     = isset( $ayarlar['engelli_ulkeler'] ) ? (string) $ayarlar['engelli_ulkeler'] : '';
		$liste   = array();
		foreach ( preg_split( '/[\r\n,\s]+/', strtoupper( $ham ) ) as $k ) {
			$k = trim( $k );
			if ( preg_match( '/^[A-Z]{2}$/', $k ) ) {
				$liste[] = $k;
			}
		}
		return $liste;
	}

	/**
	 * Yalnızca izin verilen ülke kodları (beyaz liste modu, ISO-2).
	 */
	protected static function izinli_ulkeler() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$ham     = isset( $ayarlar['izinli_ulkeler'] ) ? (string) $ayarlar['izinli_ulkeler'] : '';
		$liste   = array();
		foreach ( preg_split( '/[\r\n,\s]+/', strtoupper( $ham ) ) as $k ) {
			$k = trim( $k );
			if ( preg_match( '/^[A-Z]{2}$/', $k ) ) {
				$liste[] = $k;
			}
		}
		return $liste;
	}

	public function denetle() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['ulke_engel'] ) ) {
			return;
		}

		$mod = ( isset( $ayarlar['ulke_mod'] ) && 'beyaz' === $ayarlar['ulke_mod'] ) ? 'beyaz' : 'kara';

		if ( 'beyaz' === $mod ) {
			$izinli = self::izinli_ulkeler();
			if ( empty( $izinli ) ) {
				return; // Yapılandırılmamış → hiçbir şey yapma (kazara tüm dünyayı engelleme).
			}
		} else {
			$engelli = self::engelli_ulkeler();
			if ( empty( $engelli ) ) {
				return;
			}
		}

		// Sistem / yönetici / beyaz liste muaf.
		if ( ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return;
		}
		$ip = WPGK_Logger::ip_al();
		if ( '0.0.0.0' === $ip || ( class_exists( 'WPGK_Login_Security' ) && WPGK_Login_Security::beyaz_listede_mi( $ip ) ) ) {
			return;
		}

		$ulke = self::ulke_kodu( $ip );
		if ( '' === $ulke ) {
			return; // Çözülemedi → fail-open.
		}

		$engelle = ( 'beyaz' === $mod ) ? ! in_array( $ulke, $izinli, true ) : in_array( $ulke, $engelli, true );
		if ( ! $engelle ) {
			return;
		}

		// SEO koruması: doğrulanmış arama motoru botlarını (Googlebot/Bingbot vb.)
		// coğrafi engelden muaf tut (ayar açıksa). UA + reverse/forward DNS ile doğrulanır.
		if ( ! empty( $ayarlar['ulke_arama_motoru_izin'] ) && self::dogrulanmis_arama_motoru( $ip ) ) {
			return;
		}

		WPGK_Logger::kaydet( 'geoip', 'ulke_engellendi', sprintf( 'Coğrafi engel: %s (%s) — mod: %s', $ip, $ulke, $mod ), 'uyari' );
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html__( 'Bu içeriğe bulunduğunuz bölgeden erişim kısıtlanmıştır.', 'wp-radar' ),
			esc_html__( 'Erişim Engellendi', 'wp-radar' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Bir IP'nin gerçek bir arama motoru botu olup olmadığını doğrular.
	 * UA eşleşmesi + reverse DNS + (IPv4 için) forward DNS teyidi. Önbellekli.
	 * Spooflanmış UA'lar reverse/forward DNS teyidini geçemez.
	 */
	protected static function dogrulanmis_arama_motoru( $ip ) {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		if ( '' === $ua || ! preg_match( '/(googlebot|bingbot|slurp|duckduckbot|yandex(bot)?|applebot|baiduspider)/i', $ua ) ) {
			return false;
		}
		$cache = get_transient( 'wpgk_bot_' . md5( $ip ) );
		if ( false !== $cache ) {
			return '1' === $cache;
		}
		$ok   = false;
		$host = @gethostbyaddr( $ip );
		if ( $host && preg_match( '/(\.googlebot\.com|\.google\.com|\.search\.msn\.com|\.crawl\.yahoo\.net|\.yandex\.(com|net|ru)|\.duckduckgo\.com|applebot\.apple\.com|\.crawl\.baidu\.com)$/i', $host ) ) {
			if ( false !== strpos( $ip, ':' ) ) {
				$ok = true; // IPv6: reverse eşleşmesi yeterli (forward IPv4 döndürür).
			} else {
				$ok = ( @gethostbyname( $host ) === $ip ); // IPv4: forward teyidi (anti-spoof).
			}
		}
		set_transient( 'wpgk_bot_' . md5( $ip ), $ok ? '1' : '0', DAY_IN_SECONDS );
		return $ok;
	}

	/**
	 * Bir IP'nin ülke kodunu döndürür (önbellekli). Çözülemezse '' döner.
	 */
	public static function ulke_kodu( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$cache = get_transient( 'wpgk_geo_' . md5( $ip ) );
		if ( false !== $cache ) {
			return (string) $cache;
		}

		$ayarlar   = get_option( 'wpgk_ayarlar', array() );
		$saglayici = isset( $ayarlar['geoip_saglayici'] ) ? $ayarlar['geoip_saglayici'] : 'ip-api';
		$ulke      = '';

		if ( 'ipinfo' === $saglayici && ! empty( $ayarlar['geoip_token'] ) ) {
			$yanit = wp_remote_get(
				'https://ipinfo.io/' . rawurlencode( $ip ) . '/country?token=' . rawurlencode( $ayarlar['geoip_token'] ),
				array( 'timeout' => 4 )
			);
			if ( ! is_wp_error( $yanit ) && 200 === (int) wp_remote_retrieve_response_code( $yanit ) ) {
				$ulke = strtoupper( trim( wp_remote_retrieve_body( $yanit ) ) );
			}
		} else {
			// ip-api (anahtarsız, HTTP).
			$yanit = wp_remote_get(
				'http://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=status,countryCode',
				array( 'timeout' => 4 )
			);
			if ( ! is_wp_error( $yanit ) && 200 === (int) wp_remote_retrieve_response_code( $yanit ) ) {
				$govde = json_decode( wp_remote_retrieve_body( $yanit ), true );
				if ( isset( $govde['status'] ) && 'success' === $govde['status'] && ! empty( $govde['countryCode'] ) ) {
					$ulke = strtoupper( $govde['countryCode'] );
				}
			}
		}

		if ( ! preg_match( '/^[A-Z]{2}$/', $ulke ) ) {
			$ulke = '';
		}
		// Çözülenleri 12 saat, çözülemeyenleri kısa süre önbelleğe al.
		set_transient( 'wpgk_geo_' . md5( $ip ), $ulke, $ulke ? 12 * HOUR_IN_SECONDS : 10 * MINUTE_IN_SECONDS );
		return $ulke;
	}
}
