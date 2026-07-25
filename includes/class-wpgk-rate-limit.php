<?php
/**
 * Oran sınırlama (rate limiting): tek bir IP'den gelen aşırı istekleri
 * (agresif bot / kazıma / uygulama katmanı DoS) frenler.
 *
 * Belirli bir zaman penceresinde eşik aşılırsa IP geçici olarak engellenir.
 * Oturum açmış yöneticiler, beyaz listedeki IP'ler ve sistem bağlamları
 * (cron / WP-CLI) muaftır. Engellenen istekler olay günlüğüne yazılır;
 * "Olay Günlüğü" sayfası bu modül için canlı trafik görünümü işlevi görür.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Rate_Limit {

	public function __construct() {
		add_action( 'init', array( $this, 'denetle' ), 1 );
	}

	public function denetle() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['oran_limit'] ) ) {
			return;
		}

		// Sistem bağlamları muaf.
		if ( ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		// Oturum açmış düzenleme yetkili kullanıcılar muaf (yanlış kilitlemeyi önler).
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return;
		}

		$ip = WPGK_Logger::ip_al();
		if ( '0.0.0.0' === $ip || ( class_exists( 'WPGK_Login_Security' ) && WPGK_Login_Security::beyaz_listede_mi( $ip ) ) ) {
			return;
		}

		$max     = max( 10, (int) ( isset( $ayarlar['oran_max'] ) ? $ayarlar['oran_max'] : 120 ) );
		$pencere = max( 10, (int) ( isset( $ayarlar['oran_pencere_sn'] ) ? $ayarlar['oran_pencere_sn'] : 60 ) );
		$kilit   = max( 1, (int) ( isset( $ayarlar['oran_kilit_dk'] ) ? $ayarlar['oran_kilit_dk'] : 10 ) );

		$ip_md   = md5( $ip );
		$kilit_anahtar = 'wpgk_oran_kilit_' . $ip_md;

		// Zaten kilitliyse reddet.
		if ( get_transient( $kilit_anahtar ) ) {
			$this->reddet( $kilit );
		}

		// ATOMİK sayaç (yarış koşulu olmadan): paralel isteklerle sınır atlatılamaz.
		$sayac_anahtar = 'oran_' . $ip_md;
		$sayi          = WPGK_Logger::sayac_arttir( $sayac_anahtar, $pencere );

		if ( $sayi > $max ) {
			set_transient( $kilit_anahtar, 1, $kilit * MINUTE_IN_SECONDS );
			WPGK_Logger::sayac_sifirla( $sayac_anahtar );
			WPGK_Logger::kaydet(
				'oran',
				'oran_limit_kilit',
				sprintf( 'IP %s oran sınırını aştı (%d istek / %d sn); %d dk engellendi.', $ip, $sayi, $pencere, $kilit ),
				'uyari'
			);
			$this->reddet( $kilit );
		}
	}

	/**
	 * İsteği 429 ile sonlandırır (Retry-After başlığıyla).
	 */
	protected function reddet( $kilit_dk ) {
		if ( ! headers_sent() ) {
			status_header( 429 );
			nocache_headers();
			header( 'Retry-After: ' . ( (int) $kilit_dk * 60 ) );
		}
		wp_die(
			esc_html__( 'Çok fazla istek gönderdiniz. Lütfen bir süre sonra tekrar deneyin.', 'ck-radar-security' ),
			esc_html__( 'Hız Sınırı', 'ck-radar-security' ),
			array( 'response' => 429 )
		);
	}
}
