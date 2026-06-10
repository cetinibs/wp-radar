<?php
/**
 * Zafiyet (vulnerability) taraması.
 *
 * Kurulu eklenti, tema ve WordPress çekirdeğinin sürümlerini WPScan API'sindeki
 * bilinen güvenlik açıklarıyla karşılaştırır. Kurulu sürümü etkileyen bir açık
 * bulunursa kritik olay olarak loglanır ve e-posta bildirimi tetiklenir.
 *
 * WPScan API anahtarı gerektirir (ücretsiz katman ~25 istek/gün). Anahtar yoksa
 * modül sessizce devre dışıdır. Sonuçlar 24 saat önbelleğe alınır ve çalışma
 * başına istek sayısı sınırlandırılır (kotayı korumak için).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Vuln_Scan {

	const API = 'https://wpscan.com/api/v3/';

	public function __construct() {
		add_action( 'wpgk_gunluk_tarama', array( $this, 'tara' ) );
	}

	public static function aktif() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		return ! empty( $ayarlar['vuln_tarama'] ) && ! empty( $ayarlar['wpscan_token'] );
	}

	/**
	 * Kurulu bileşenleri tarar.
	 */
	public function tara() {
		if ( ! self::aktif() ) {
			return;
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$istek_butcesi = 20; // Bu çalışmada en fazla bu kadar API isteği.
		$bulgu         = 0;

		// 1) Eklentiler (slug = klasör adı).
		foreach ( get_plugins() as $dosya => $veri ) {
			if ( $istek_butcesi <= 0 ) {
				break;
			}
			$slug   = dirname( $dosya );
			$slug   = ( '.' === $slug || '' === $slug ) ? basename( $dosya, '.php' ) : $slug;
			$surum  = isset( $veri['Version'] ) ? $veri['Version'] : '';
			if ( '' === $surum ) {
				continue;
			}
			$istek_butcesi--;
			$bulgu += $this->bilesen_denetle( 'plugins/' . rawurlencode( $slug ), $slug, $surum, 'eklenti' );
		}

		// 2) Temalar.
		foreach ( wp_get_themes() as $slug => $tema ) {
			if ( $istek_butcesi <= 0 ) {
				break;
			}
			$surum = $tema->get( 'Version' );
			if ( ! $surum ) {
				continue;
			}
			$istek_butcesi--;
			$bulgu += $this->bilesen_denetle( 'themes/' . rawurlencode( $slug ), $slug, $surum, 'tema' );
		}

		// 3) WordPress çekirdeği.
		if ( $istek_butcesi > 0 ) {
			global $wp_version;
			if ( ! empty( $wp_version ) ) {
				$surum_anahtar = str_replace( '.', '', $wp_version );
				$this->bilesen_denetle( 'wordpresses/' . rawurlencode( $surum_anahtar ), 'WordPress', $wp_version, 'cekirdek', true );
			}
		}

		WPGK_Logger::kaydet( 'zafiyet', 'vuln_tarama_tamam', sprintf( 'Zafiyet taraması tamamlandı; etkilenen bileşen: %d.', $bulgu ), $bulgu > 0 ? 'kritik' : 'bilgi' );
	}

	/**
	 * Tek bir bileşeni WPScan'de sorgular; kurulu sürümü etkileyen açıkları loglar.
	 *
	 * @return int Bulunan (etkileyen) açık sayısı.
	 */
	protected function bilesen_denetle( $yol, $ad, $surum, $tur, $cekirdek = false ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$token   = $ayarlar['wpscan_token'];

		$cache_anahtar = 'wpgk_vuln_' . md5( $yol );
		$veri = get_transient( $cache_anahtar );
		if ( false === $veri ) {
			$yanit = wp_remote_get(
				self::API . $yol,
				array(
					'headers' => array( 'Authorization' => 'Token token=' . $token ),
					'timeout' => 15,
				)
			);
			if ( is_wp_error( $yanit ) ) {
				return 0;
			}
			$kod = (int) wp_remote_retrieve_response_code( $yanit );
			if ( 404 === $kod ) {
				set_transient( $cache_anahtar, array(), 12 * HOUR_IN_SECONDS );
				return 0; // WPScan'de kayıt yok.
			}
			if ( 200 !== $kod ) {
				return 0; // 401 (token), 429 (kota) vb. → sessizce geç.
			}
			$govde = json_decode( wp_remote_retrieve_body( $yanit ), true );
			$veri  = $this->aciklari_cikar( $govde, $cekirdek ? $ad : $ad );
			set_transient( $cache_anahtar, $veri, 12 * HOUR_IN_SECONDS );
		}

		$bulundu = 0;
		foreach ( (array) $veri as $acik ) {
			$fixed = isset( $acik['fixed_in'] ) ? $acik['fixed_in'] : null;
			$etkilenir = ( null === $fixed || '' === $fixed )
				? true
				: version_compare( $surum, $fixed, '<' );
			if ( $etkilenir ) {
				$bulundu++;
				WPGK_Logger::kaydet(
					'zafiyet',
					'bilinen_acik',
					sprintf(
						'Bilinen güvenlik açığı (%s): %s %s — %s%s',
						$tur,
						$ad,
						$surum,
						isset( $acik['title'] ) ? WPGK_Util::kes( $acik['title'], 0, 140 ) : 'açık',
						$fixed ? ' (düzeltildi: ' . $fixed . ')' : ' (henüz yama yok)'
					),
					'kritik'
				);
			}
		}
		return $bulundu;
	}

	/**
	 * WPScan yanıtından açık listesini normalize eder.
	 */
	protected function aciklari_cikar( $govde, $ad ) {
		if ( ! is_array( $govde ) ) {
			return array();
		}
		// Yanıt biçimi: { "<slug>": { "vulnerabilities": [ ... ] } }
		$ilk = reset( $govde );
		if ( is_array( $ilk ) && isset( $ilk['vulnerabilities'] ) && is_array( $ilk['vulnerabilities'] ) ) {
			$cikti = array();
			foreach ( $ilk['vulnerabilities'] as $v ) {
				$fixed = null;
				if ( isset( $v['fixed_in'] ) ) {
					$fixed = $v['fixed_in'];
				}
				$cikti[] = array(
					'title'    => isset( $v['title'] ) ? $v['title'] : '',
					'fixed_in' => $fixed,
				);
			}
			return $cikti;
		}
		return array();
	}
}
