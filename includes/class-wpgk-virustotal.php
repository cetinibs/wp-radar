<?php
/**
 * VirusTotal entegrasyonu.
 *
 * VirusTotal API v3 üzerinden URL ve dosya (SHA-256) itibar sorgusu yapar.
 * Bir URL veya dosyayı 70+ antivirüs/güvenlik motoruyla kontrol ederek
 * "zararlı / şüpheli / zararsız" sayımlarını döndürür.
 *
 * Ücretsiz genel API anahtarı sınırlıdır (yaklaşık 4 istek/dakika, 500/gün);
 * bu nedenle sonuçlar bir saat boyunca önbelleğe alınır ve otomatik tarama
 * çalışma başına sınırlandırılır.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_VirusTotal {

	const API        = 'https://www.virustotal.com/api/v3/';
	const GUI_URL    = 'https://www.virustotal.com/gui/url/';
	const GUI_FILE   = 'https://www.virustotal.com/gui/file/';
	const CACHE_SURE = HOUR_IN_SECONDS;

	/**
	 * API anahtarı tanımlı mı?
	 */
	public static function aktif() {
		return '' !== self::api_key();
	}

	/**
	 * Ayarlardaki VirusTotal API anahtarını döndürür.
	 */
	public static function api_key() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		return isset( $ayarlar['vt_api_key'] ) ? trim( (string) $ayarlar['vt_api_key'] ) : '';
	}

	/**
	 * Bir URL'nin VirusTotal raporunu döndürür.
	 *
	 * @param string $url     Sorgulanacak URL.
	 * @param bool   $gonder  Rapor yoksa URL'yi taramaya gönder.
	 * @return array|WP_Error Normalize edilmiş rapor ya da hata.
	 */
	public static function url_raporu( $url, $gonder = true ) {
		$url = esc_url_raw( trim( (string) $url ) );
		if ( '' === $url || ! preg_match( '#^https?://#i', $url ) ) {
			return new WP_Error( 'wpgk_vt_url', 'Geçerli bir http(s) URL girin.' );
		}

		// VT v3 URL kimliği: base64url(url), padding olmadan.
		$kimlik = rtrim( strtr( base64_encode( $url ), '+/', '-_' ), '=' );

		$rapor = self::istek( 'urls/' . $kimlik );

		// Rapor yoksa (404) ve gönderme açıksa, taramaya gönderip bir kez sonucu yokla.
		if ( ! is_wp_error( $rapor ) && empty( $rapor['bulundu'] ) && $gonder ) {
			$analiz = self::url_gonder( $url );
			if ( ! is_wp_error( $analiz ) && ! empty( $analiz['analiz_id'] ) ) {
				$sonuc = self::istek( 'analyses/' . $analiz['analiz_id'], false );
				if ( ! is_wp_error( $sonuc ) && ! empty( $sonuc['tamamlandi'] ) ) {
					$sonuc['gui'] = self::GUI_URL . $kimlik;
					return $sonuc;
				}
				return array(
					'bulundu'  => false,
					'beklemede' => true,
					'mesaj'    => 'URL taramaya gönderildi. Sonuç birkaç dakika içinde hazır olur; lütfen tekrar sorgulayın.',
				);
			}
		}

		if ( ! is_wp_error( $rapor ) && ! empty( $rapor['bulundu'] ) ) {
			$rapor['gui'] = self::GUI_URL . $kimlik;
		}
		return $rapor;
	}

	/**
	 * Bir dosyanın SHA-256 özetiyle VirusTotal raporunu döndürür.
	 */
	public static function dosya_raporu( $sha256 ) {
		$sha256 = strtolower( trim( (string) $sha256 ) );
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $sha256 ) ) {
			return new WP_Error( 'wpgk_vt_hash', 'Geçerli bir SHA-256 özeti girin.' );
		}
		$rapor = self::istek( 'files/' . $sha256 );
		if ( ! is_wp_error( $rapor ) && ! empty( $rapor['bulundu'] ) ) {
			$rapor['gui'] = self::GUI_FILE . $sha256;
		}
		return $rapor;
	}

	/**
	 * Bir URL'yi VirusTotal taramasına gönderir, analiz kimliğini döndürür.
	 */
	protected static function url_gonder( $url ) {
		$key = self::api_key();
		if ( '' === $key ) {
			return new WP_Error( 'wpgk_vt_key', 'VirusTotal API anahtarı tanımlı değil.' );
		}
		$yanit = wp_remote_post(
			self::API . 'urls',
			array(
				'headers' => array(
					'x-apikey'     => $key,
					'Accept'       => 'application/json',
					'Content-Type' => 'application/x-www-form-urlencoded',
				),
				'body'    => array( 'url' => $url ),
				'timeout' => 20,
			)
		);
		if ( is_wp_error( $yanit ) ) {
			return $yanit;
		}
		$govde = json_decode( wp_remote_retrieve_body( $yanit ), true );
		$id    = isset( $govde['data']['id'] ) ? $govde['data']['id'] : '';
		if ( '' === $id ) {
			return new WP_Error( 'wpgk_vt_gonder', 'URL taramaya gönderilemedi.' );
		}
		return array( 'analiz_id' => $id );
	}

	/**
	 * API'ye GET isteği yapar ve sonucu normalize eder. Sonuçlar önbelleğe alınır.
	 *
	 * @param string $yol         API yolu (ör. 'urls/<id>' veya 'files/<sha256>').
	 * @param bool   $onbellek    Sonucu önbelleğe al.
	 * @return array|WP_Error
	 */
	protected static function istek( $yol, $onbellek = true ) {
		$key = self::api_key();
		if ( '' === $key ) {
			return new WP_Error( 'wpgk_vt_key', 'VirusTotal API anahtarı tanımlı değil. Ayarlardan ekleyin.' );
		}

		$cache_anahtar = 'wpgk_vt_' . md5( $yol );
		if ( $onbellek ) {
			$onbellekli = get_transient( $cache_anahtar );
			if ( false !== $onbellekli ) {
				return $onbellekli;
			}
		}

		$yanit = wp_remote_get(
			self::API . $yol,
			array(
				'headers' => array(
					'x-apikey' => $key,
					'Accept'   => 'application/json',
				),
				'timeout' => 20,
			)
		);

		if ( is_wp_error( $yanit ) ) {
			return $yanit;
		}

		$kod   = (int) wp_remote_retrieve_response_code( $yanit );
		$govde = json_decode( wp_remote_retrieve_body( $yanit ), true );

		if ( 404 === $kod ) {
			$cikti = array( 'bulundu' => false );
			if ( $onbellek ) {
				set_transient( $cache_anahtar, $cikti, self::CACHE_SURE );
			}
			return $cikti;
		}
		if ( 401 === $kod ) {
			return new WP_Error( 'wpgk_vt_401', 'VirusTotal API anahtarı geçersiz (401).' );
		}
		if ( 429 === $kod ) {
			return new WP_Error( 'wpgk_vt_429', 'VirusTotal istek sınırı aşıldı (429). Bir süre sonra tekrar deneyin.' );
		}
		if ( 200 !== $kod ) {
			return new WP_Error( 'wpgk_vt_http', 'VirusTotal hatası: HTTP ' . $kod );
		}

		$attr  = isset( $govde['data']['attributes'] ) ? $govde['data']['attributes'] : array();
		$stats = isset( $attr['last_analysis_stats'] ) ? $attr['last_analysis_stats'] : array();

		$cikti = self::normalize( $stats );
		$cikti['bulundu']     = true;
		$cikti['tamamlandi']  = ! empty( $stats );
		$cikti['itibar']      = isset( $attr['reputation'] ) ? (int) $attr['reputation'] : 0;
		$cikti['son_analiz']  = isset( $attr['last_analysis_date'] ) ? (int) $attr['last_analysis_date'] : 0;

		if ( $onbellek ) {
			set_transient( $cache_anahtar, $cikti, self::CACHE_SURE );
		}
		return $cikti;
	}

	/**
	 * last_analysis_stats dizisini normalize eder.
	 */
	protected static function normalize( $stats ) {
		$zararli  = isset( $stats['malicious'] ) ? (int) $stats['malicious'] : 0;
		$supheli  = isset( $stats['suspicious'] ) ? (int) $stats['suspicious'] : 0;
		$zararsiz = isset( $stats['harmless'] ) ? (int) $stats['harmless'] : 0;
		$tespitsiz = isset( $stats['undetected'] ) ? (int) $stats['undetected'] : 0;
		$toplam   = $zararli + $supheli + $zararsiz + $tespitsiz;

		return array(
			'zararli'   => $zararli,
			'supheli'   => $supheli,
			'zararsiz'  => $zararsiz,
			'tespitsiz' => $tespitsiz,
			'toplam'    => $toplam,
		);
	}

	/**
	 * Bir rapordan insan-okunur kısa özet üretir.
	 */
	public static function ozet_metni( $rapor ) {
		if ( is_wp_error( $rapor ) ) {
			return $rapor->get_error_message();
		}
		if ( ! empty( $rapor['beklemede'] ) ) {
			return $rapor['mesaj'];
		}
		if ( empty( $rapor['bulundu'] ) ) {
			return 'VirusTotal kaydı bulunamadı (daha önce taranmamış).';
		}
		return sprintf(
			'%d/%d motor zararlı, %d şüpheli olarak işaretledi.',
			(int) $rapor['zararli'],
			(int) $rapor['toplam'],
			(int) $rapor['supheli']
		);
	}

	/**
	 * Bir dosyayı (yol) hash'leyip VirusTotal'da doğrular; zararlıysa loglar.
	 * Otomatik tarama akışı için tasarlanmıştır.
	 *
	 * @return array|WP_Error|null Rapor; anahtar yoksa null.
	 */
	public static function dosyayi_dogrula( $yol ) {
		if ( ! self::aktif() || ! is_readable( $yol ) ) {
			return null;
		}
		$sha256 = @hash_file( 'sha256', $yol );
		if ( ! $sha256 ) {
			return null;
		}
		$rapor = self::dosya_raporu( $sha256 );
		if ( ! is_wp_error( $rapor ) && ! empty( $rapor['bulundu'] ) && (int) $rapor['zararli'] > 0 ) {
			WPGK_Logger::kaydet(
				'virustotal',
				'vt_zararli_dogrulandi',
				sprintf( 'VirusTotal %d motorda zararlı işaretledi: %s (SHA-256: %s)', (int) $rapor['zararli'], $yol, $sha256 ),
				'kritik'
			);
		}
		return $rapor;
	}
}
