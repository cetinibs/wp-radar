<?php
/**
 * Olay loglama ve e-posta bildirimleri.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Logger {

	const TABLO = 'wpgk_olaylar';

	/**
	 * Veritabanı log tablosunu oluşturur.
	 */
	public static function tablo_olustur() {
		global $wpdb;
		$tablo   = $wpdb->prefix . self::TABLO;
		$collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$tablo} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			zaman DATETIME NOT NULL,
			seviye VARCHAR(20) NOT NULL DEFAULT 'uyari',
			modul VARCHAR(50) NOT NULL,
			olay VARCHAR(100) NOT NULL,
			mesaj TEXT NULL,
			ip VARCHAR(45) NULL,
			kullanici_id BIGINT(20) UNSIGNED NULL,
			istek_uri VARCHAR(255) NULL,
			PRIMARY KEY (id),
			KEY zaman (zaman),
			KEY modul (modul)
		) {$collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Bir güvenlik olayını kaydeder.
	 *
	 * @param string $modul  Olayı üreten modül (kullanici, dosya, icerik, exploit).
	 * @param string $olay   Kısa olay kodu.
	 * @param string $mesaj  Açıklama.
	 * @param string $seviye bilgi|uyari|kritik.
	 */
	public static function kaydet( $modul, $olay, $mesaj = '', $seviye = 'uyari' ) {
		global $wpdb;
		$tablo = $wpdb->prefix . self::TABLO;

		$wpdb->insert(
			$tablo,
			array(
				'zaman'        => current_time( 'mysql' ),
				'seviye'       => $seviye,
				'modul'        => $modul,
				'olay'         => $olay,
				'mesaj'        => $mesaj,
				'ip'           => self::ip_al(),
				'kullanici_id' => get_current_user_id(),
				'istek_uri'    => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);

		if ( 'kritik' === $seviye ) {
			self::bildir( $modul, $olay, $mesaj );
		}

		// Davranışsal otomatik IP engelleme: aynı IP kısa sürede çok sayıda
		// şüpheli olay üretirse geçici olarak engellenir.
		self::ihlal_say( $modul, $olay, $seviye );
	}

	/**
	 * İstek-temelli şüpheli olayları IP başına sayar; eşik aşılırsa IP'yi
	 * geçici olarak otomatik engeller (transient). Coğrafyadan bağımsızdır.
	 */
	protected static function ihlal_say( $modul, $olay, $seviye ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['oto_engel'] ) ) {
			return;
		}
		// Yalnızca istek bağlamındaki şüpheli olaylar sayılır.
		if ( ! in_array( $seviye, array( 'uyari', 'kritik' ), true ) ) {
			return;
		}
		if ( ! in_array( $modul, array( 'exploit', 'giris', 'oran', 'geoip', 'icerik', 'dosya' ), true ) ) {
			return;
		}
		// Meta/engel olaylarını sayma (kendini besleme / döngü önlemi).
		if ( in_array( $olay, array( 'otomatik_ip_engel', 'oran_limit_kilit', 'ip_kara_liste' ), true ) ) {
			return;
		}

		$ip = self::ip_al();
		if ( '0.0.0.0' === $ip ) {
			return;
		}
		if ( class_exists( 'WPGK_Login_Security' ) && WPGK_Login_Security::beyaz_listede_mi( $ip ) ) {
			return;
		}

		$esik    = max( 3, (int) ( isset( $ayarlar['oto_engel_esik'] ) ? $ayarlar['oto_engel_esik'] : 20 ) );
		$pencere = max( 1, (int) ( isset( $ayarlar['oto_engel_pencere_dk'] ) ? $ayarlar['oto_engel_pencere_dk'] : 60 ) );
		$sure    = max( 1, (int) ( isset( $ayarlar['oto_engel_sure_dk'] ) ? $ayarlar['oto_engel_sure_dk'] : 60 ) );

		$sayac = 'wpgk_ihlal_' . md5( $ip );
		$n     = (int) get_transient( $sayac ) + 1;
		set_transient( $sayac, $n, $pencere * MINUTE_IN_SECONDS );

		if ( $n >= $esik ) {
			set_transient( 'wpgk_otoblok_' . md5( $ip ), 1, $sure * MINUTE_IN_SECONDS );
			delete_transient( $sayac );
			// Not: 'otomatik_ip_engel' olayı yukarıda sayımdan muaf tutulduğu için
			// bu çağrı sonsuz döngüye girmez; kritik seviye e-posta bildirimi tetikler.
			self::kaydet(
				'giris',
				'otomatik_ip_engel',
				sprintf( 'IP %s, %d dk içinde %d şüpheli olay üretti; %d dk otomatik engellendi.', $ip, $pencere, $n, $sure ),
				'kritik'
			);
		}
	}

	/**
	 * IP davranışsal otomatik engel altında mı?
	 */
	public static function otomatik_engelli_mi( $ip = null ) {
		$ip = $ip ? $ip : self::ip_al();
		return (bool) get_transient( 'wpgk_otoblok_' . md5( $ip ) );
	}

	/**
	 * Kritik olaylarda yöneticiye e-posta gönderir.
	 *
	 * Anti-flood: aynı (modül+olay) türü için yapılandırılan süre boyunca yalnızca
	 * bir bildirim gönderilir. İlk olay anında iletilir; tekrarları susturulur.
	 */
	protected static function bildir( $modul, $olay, $mesaj ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['eposta_bildirimi'] ) ) {
			return;
		}

		// Tekrar-bildirim engeli (dakika). 0 = engelleme yok, her olay gönderilir.
		// Anahtar = olay türü + saldıran IP BLOĞU (/24). Böylece aynı IP veya aynı
		// /24 bloğundan gelen yüzlerce istek/deneme için TEK e-posta gönderilir;
		// bir bot selinde gelen kutusu dolmaz.
		$throttle = isset( $ayarlar['bildirim_throttle_dk'] ) ? (int) $ayarlar['bildirim_throttle_dk'] : 60;
		if ( $throttle > 0 ) {
			$anahtar = 'wpgk_bldr_' . md5( $modul . '|' . $olay . '|' . self::ip_blok( self::ip_al() ) );
			if ( get_transient( $anahtar ) ) {
				return; // Bu olay türü + IP bloğu için bekleme süresi henüz dolmadı.
			}
			set_transient( $anahtar, 1, $throttle * MINUTE_IN_SECONDS );
		}

		$alicilar = self::bildirim_alicilari();
		if ( empty( $alicilar ) ) {
			return;
		}

		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$konu  = sprintf( '[%s] Kritik Güvenlik Olayı: %s', $site, $olay );
		$govde = sprintf(
			"WP Radar kritik bir güvenlik olayı tespit etti.\n\n"
			. "Site: %s\nModül: %s\nOlay: %s\nMesaj: %s\nIP: %s\nKullanıcı ID: %s\nZaman: %s\nİstek: %s\n\n"
			. "Olay günlüğünü inceleyin: %s\n",
			home_url(),
			$modul,
			$olay,
			$mesaj,
			self::ip_al(),
			get_current_user_id(),
			current_time( 'mysql' ),
			isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '-',
			admin_url( 'admin.php?page=wpgk-gunluk' )
		);

		wp_mail( $alicilar, $konu, $govde );
	}

	/**
	 * Yapılandırılmış bildirim alıcılarını (geçerli e-postalar) dizi olarak döndürür.
	 * Virgül, noktalı virgül veya satır başıyla ayrılmış birden çok adresi destekler.
	 */
	public static function bildirim_alicilari() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$ham     = ! empty( $ayarlar['bildirim_eposta'] ) ? $ayarlar['bildirim_eposta'] : get_option( 'admin_email' );

		$temiz = array();
		foreach ( preg_split( '/[\r\n,;]+/', (string) $ham ) as $e ) {
			$e = sanitize_email( trim( $e ) );
			if ( $e && is_email( $e ) ) {
				$temiz[] = $e;
			}
		}
		return array_values( array_unique( $temiz ) );
	}

	/**
	 * Bildirim yapılandırmasını doğrulamak için test e-postası gönderir.
	 *
	 * @return bool wp_mail başarılıysa true.
	 */
	public static function test_bildirimi_gonder() {
		$alicilar = self::bildirim_alicilari();
		if ( empty( $alicilar ) ) {
			return false;
		}
		$site  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$konu  = sprintf( '[%s] WP Radar test bildirimi', $site );
		$govde = sprintf(
			"Bu bir test e-postasıdır.\n\nWP Radar e-posta bildirimleri düzgün çalışıyor.\nBu mesajı aldıysanız kritik güvenlik olaylarında da bildirim alacaksınız.\n\nSite: %s\nZaman: %s\nAlıcılar: %s\n",
			home_url(),
			current_time( 'mysql' ),
			implode( ', ', $alicilar )
		);
		return wp_mail( $alicilar, $konu, $govde );
	}

	/**
	 * İstemci IP adresini güvenli biçimde döndürür.
	 *
	 * GÜVENLİK: X-Forwarded-For / CF-Connecting-IP istemci tarafından sahte
	 * gönderilebilen başlıklardır. Bunlara körlemesine güvenmek, saldırganın her
	 * istekte farklı bir sahte IP göndererek giriş kilidini (brute-force koruması)
	 * atlamasına ya da kurbanın IP'sini taklit ederek onu kilitletmesine olanak tanır.
	 *
	 * Bu nedenle:
	 *  - Varsayılan/CDN dışı: yalnızca REMOTE_ADDR (sahtelenemez soket adresi).
	 *  - Proxy/CDN modu açık (proxy_guven): önce CF-Connecting-IP, sonra
	 *    X-Forwarded-For içindeki ilk PUBLIC adres (özel-aralık enjeksiyonu atlanır),
	 *    sonra REMOTE_ADDR.
	 */
	public static function ip_al() {
		$ayarlar     = get_option( 'wpgk_ayarlar', array() );
		$proxy_guven = ! empty( $ayarlar['proxy_guven'] );

		if ( $proxy_guven ) {
			// Cloudflare gibi proxy'lerin yazdığı, istemcinin geçersiz kılamadığı başlık.
			if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$cf = trim( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				if ( filter_var( $cf, FILTER_VALIDATE_IP ) ) {
					return $cf;
				}
			}
			// X-Forwarded-For: yalnızca ilk PUBLIC adresi kabul et (özel/rezerve aralıkları atla).
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				foreach ( explode( ',', wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) as $aday ) {
					$aday = trim( $aday );
					if ( filter_var( $aday, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
						return $aday;
					}
				}
			}
		}

		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
	}

	/**
	 * Bir IP adresini bildirim grupla­ma için ağ bloğuna indirger.
	 * IPv4 -> /24 (ilk 3 oktet), IPv6 -> ilk 4 grup (~/64). Böylece bir IP
	 * bloğundan gelen dağıtık saldırı tek bir bildirim grubunda toplanır.
	 */
	public static function ip_blok( $ip ) {
		$ip = (string) $ip;
		if ( false !== strpos( $ip, ':' ) ) {
			$parcalar = explode( ':', $ip );
			return strtolower( implode( ':', array_slice( $parcalar, 0, 4 ) ) ) . '::/64';
		}
		$parcalar = explode( '.', $ip );
		if ( 4 === count( $parcalar ) ) {
			return $parcalar[0] . '.' . $parcalar[1] . '.' . $parcalar[2] . '.0/24';
		}
		return $ip;
	}

	/**
	 * Son N saatteki olay sayımlarını seviyeye göre döndürür (panel panosu için).
	 *
	 * @param int $saat Geriye dönük pencere (saat).
	 * @return array array('kritik'=>int,'uyari'=>int,'bilgi'=>int)
	 */
	public static function seviye_sayimlari( $saat = 24 ) {
		global $wpdb;
		$tablo = $wpdb->prefix . self::TABLO;
		// zaman yerel saatle (current_time('mysql')) saklandığı için eşik de yerel olmalı:
		// gmdate(yerel_epoch) yerel duvar-saati dizesini verir.
		$esik = gmdate( 'Y-m-d H:i:s', (int) current_time( 'timestamp' ) - ( (int) $saat * HOUR_IN_SECONDS ) );
		$satirlar = $wpdb->get_results(
			$wpdb->prepare( "SELECT seviye, COUNT(*) AS adet FROM {$tablo} WHERE zaman >= %s GROUP BY seviye", $esik )
		);
		$cikti = array( 'kritik' => 0, 'uyari' => 0, 'bilgi' => 0 );
		foreach ( (array) $satirlar as $s ) {
			if ( isset( $cikti[ $s->seviye ] ) ) {
				$cikti[ $s->seviye ] = (int) $s->adet;
			}
		}
		return $cikti;
	}

	/**
	 * Son olayları getirir.
	 */
	public static function son_olaylar( $limit = 100 ) {
		global $wpdb;
		$tablo = $wpdb->prefix . self::TABLO;
		return $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$tablo} ORDER BY id DESC LIMIT %d", $limit )
		);
	}

	/**
	 * Log tablosunu son N kayıtla sınırlayıp eskiyi siler (sınırsız büyüme/DoS koruması).
	 *
	 * @param int $tut Saklanacak en güncel kayıt sayısı.
	 */
	public static function buda( $tut = 5000 ) {
		global $wpdb;
		$tablo = $wpdb->prefix . self::TABLO;
		$tut   = max( 100, (int) $tut );

		// N. en güncel kaydın id eşiğini bul.
		$esik = $wpdb->get_var(
			$wpdb->prepare( "SELECT id FROM {$tablo} ORDER BY id DESC LIMIT 1 OFFSET %d", $tut )
		);

		if ( $esik ) {
			$wpdb->query(
				$wpdb->prepare( "DELETE FROM {$tablo} WHERE id <= %d", (int) $esik )
			);
		}
	}
}
