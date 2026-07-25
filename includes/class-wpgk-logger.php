<?php
/**
 * Olay loglama ve e-posta bildirimleri.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Logger {

	const TABLO = 'wpgk_olaylar';

	/** Atomik sayaç tablosu (yarış koşulu olmadan IP başına olay sayımı). */
	const SAYAC_TABLO = 'wpgk_sayaclar';

	/**
	 * IP/olay sayacını ATOMİK olarak artırır ve yeni değeri döndürür.
	 *
	 * Neden gerekli: get_transient() → ++ → set_transient() kalıbı bir
	 * read-modify-write yarış koşuludur. Eşzamanlı N istek aynı değeri okuyup
	 * aynı değeri yazabilir; böylece N başarısız giriş 1 olarak sayılır ve
	 * brute-force kilidi paralel isteklerle atlatılabilir. MySQL'in
	 * "INSERT ... ON DUPLICATE KEY UPDATE" ifadesi tek satır üzerinde atomiktir.
	 *
	 * @param string $anahtar Sayaç anahtarı.
	 * @param int    $ttl     Pencere süresi (saniye).
	 * @return int Artırım sonrası değer (en az 1).
	 */
	public static function sayac_arttir( $anahtar, $ttl ) {
		global $wpdb;
		$tablo   = $wpdb->prefix . self::SAYAC_TABLO;
		$anahtar = substr( (string) $anahtar, 0, 64 );
		$simdi   = time();
		$biten   = $simdi + max( 1, (int) $ttl );

		// Pencere dolmuşsa sayacı 1'e sıfırla ve yeni pencere aç; aksi halde artır.
		$sonuc = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$tablo} (anahtar, sayi, biten) VALUES (%s, 1, %d)
				ON DUPLICATE KEY UPDATE
					sayi  = IF(biten < %d, 1, sayi + 1),
					biten = IF(biten < %d, %d, biten)",
				$anahtar,
				$biten,
				$simdi,
				$simdi,
				$biten
			)
		);

		if ( false === $sonuc ) {
			// Tablo yoksa/sorgu başarısızsa güvenli tarafa düş: transient'e geri dön.
			$n = (int) get_transient( 'wpgk_sayac_' . md5( $anahtar ) ) + 1;
			set_transient( 'wpgk_sayac_' . md5( $anahtar ), $n, max( 1, (int) $ttl ) );
			return $n;
		}

		$deger = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT sayi FROM {$tablo} WHERE anahtar = %s", $anahtar )
		);
		return max( 1, $deger );
	}

	/**
	 * Bir sayacı sıfırlar (kilit uygulandıktan sonra).
	 */
	public static function sayac_sifirla( $anahtar ) {
		global $wpdb;
		$tablo = $wpdb->prefix . self::SAYAC_TABLO;
		$wpdb->delete( $tablo, array( 'anahtar' => substr( (string) $anahtar, 0, 64 ) ), array( '%s' ) );
		delete_transient( 'wpgk_sayac_' . md5( (string) $anahtar ) );
	}

	/**
	 * Süresi geçmiş sayaç satırlarını temizler (günlük bakım).
	 */
	public static function sayac_buda() {
		global $wpdb;
		$tablo = $wpdb->prefix . self::SAYAC_TABLO;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$tablo} WHERE biten < %d", time() ) );
	}

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

		$sayac_tablo = $wpdb->prefix . self::SAYAC_TABLO;
		$sql        .= " CREATE TABLE {$sayac_tablo} (
			anahtar VARCHAR(64) NOT NULL,
			sayi INT UNSIGNED NOT NULL DEFAULT 0,
			biten BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY (anahtar),
			KEY biten (biten)
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
				// Yalnızca YOL kısmı saklanır; sorgu dizesi ATILIR. Aksi halde
				// şifre sıfırlama anahtarı (?key=...&login=...) gibi hassas
				// parametreler log tablosuna ve e-postalara sızabilir.
				'istek_uri'    => self::istek_yolu(),
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
		if ( ! in_array( $modul, array( 'exploit', 'giris', 'oran', 'icerik', 'dosya' ), true ) ) {
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

		// Atomik sayaç: eşzamanlı isteklerle eşiğin atlatılmasını önler.
		$sayac = 'ihlal_' . md5( $ip );
		$n     = self::sayac_arttir( $sayac, $pencere * MINUTE_IN_SECONDS );

		if ( $n >= $esik ) {
			set_transient( 'wpgk_otoblok_' . md5( $ip ), 1, $sure * MINUTE_IN_SECONDS );
			self::sayac_sifirla( $sayac );
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
			"CK Radar Security kritik bir güvenlik olayı tespit etti.\n\n"
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
		$konu  = sprintf( '[%s] CK Radar Security test bildirimi', $site );
		$govde = sprintf(
			"Bu bir test e-postasıdır.\n\nCK Radar Security e-posta bildirimleri düzgün çalışıyor.\nBu mesajı aldıysanız kritik güvenlik olaylarında da bildirim alacaksınız.\n\nSite: %s\nZaman: %s\nAlıcılar: %s\n",
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
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		// Proxy başlıklarına YALNIZCA hem ayar açıksa hem de isteğin gerçekten
		// güvenilir bir proxy/CDN kenarından geldiği (REMOTE_ADDR doğrulaması)
		// kanıtlanmışsa güvenilir. Aksi halde herkes X-Forwarded-For uydurup
		// tüm IP tabanlı korumaları atlatabilir ya da masum bir IP'yi engelletebilir.
		$proxy_guven = ! empty( $ayarlar['proxy_guven'] ) && self::proxy_kaynagi_guvenilir_mi();

		if ( $proxy_guven ) {
			// Cloudflare gibi proxy'lerin yazdığı, istemcinin geçersiz kılamadığı başlık.
			if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$cf = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) );
				if ( filter_var( $cf, FILTER_VALIDATE_IP ) ) {
					return $cf;
				}
			}
			// X-Forwarded-For: yalnızca ilk PUBLIC adresi kabul et (özel/rezerve aralıkları atla).
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				foreach ( explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ) as $aday ) {
					$aday = trim( $aday );
					if ( filter_var( $aday, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
						return $aday;
					}
				}
			}
		}

		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
	}

	/**
	 * İstek, GERÇEKTEN güvenilir bir proxy/CDN kenarından mı geliyor?
	 *
	 * Yalnızca soket adresi (REMOTE_ADDR — sahtelenemez) bilinen bir Cloudflare
	 * aralığında ya da yöneticinin tanımladığı özel proxy listesindeyse true.
	 * Böylece "proxy_guven" açık olsa bile doğrudan gelen istekler kendi
	 * IP'lerini uyduramaz.
	 *
	 * Özel proxy/yük dengeleyici için: add_filter( 'wpgk_guvenilir_proxyler', ... )
	 * ile kendi IP/CIDR listenizi ekleyebilirsiniz.
	 */
	protected static function proxy_kaynagi_guvenilir_mi() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// Cloudflare yayınlanmış kenar aralıkları (IPv4 + IPv6 önekleri).
		$guvenilir = array(
			'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
			'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
			'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
			'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		);
		$ipv6_onek = array( '2400:cb00:', '2606:4700:', '2803:f800:', '2405:b500:', '2405:8100:', '2a06:98c0:', '2c0f:f248:' );

		/**
		 * Güvenilir proxy IP/CIDR listesini genişletmeye izin ver.
		 */
		$guvenilir = apply_filters( 'wpgk_guvenilir_proxyler', $guvenilir );

		// IPv6 önek eşleşmesi (Cloudflare).
		if ( false !== strpos( $remote, ':' ) ) {
			$dusuk = strtolower( $remote );
			foreach ( $ipv6_onek as $onek ) {
				if ( 0 === strpos( $dusuk, $onek ) ) {
					return true;
				}
			}
		}

		if ( ! class_exists( 'WPGK_Login_Security' ) ) {
			return false;
		}
		foreach ( $guvenilir as $kural ) {
			if ( WPGK_Login_Security::ip_eslesir_mi( $remote, $kural ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * İstek URI'sinin YALNIZCA yol kısmını döndürür (sorgu dizesi atılır).
	 *
	 * Sorgu dizesi şifre sıfırlama anahtarı, nonce veya oturum jetonu gibi
	 * hassas veriler taşıyabilir; bunlar log tablosuna veya e-postaya yazılmamalıdır.
	 */
	public static function istek_yolu() {
		if ( empty( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}
		$uri = wp_unslash( $_SERVER['REQUEST_URI'] );
		$yol = wp_parse_url( $uri, PHP_URL_PATH );
		if ( ! is_string( $yol ) || '' === $yol ) {
			$yol = strtok( (string) $uri, '?' );
		}
		return substr( esc_url_raw( (string) $yol ), 0, 255 );
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
