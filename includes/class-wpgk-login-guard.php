<?php
/**
 * Giriş koruması: brute-force / credential-stuffing saldırılarına karşı
 * IP bazlı oran sınırlama, geçici kilitleme ve kullanıcı adı sızdırmayan
 * jenerik hata mesajları.
 *
 * WordPress'e yönelik en yaygın saldırı, wp-login.php / XML-RPC üzerinden
 * otomatik şifre denemeleridir. Bu modül belirli sayıda başarısız denemeden
 * sonra ilgili IP'yi geçici olarak engeller.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Login_Guard {

	public function __construct() {
		// Kilitli IP'leri giriş denemesinden önce engelle.
		add_filter( 'authenticate', array( $this, 'kilit_kontrol' ), 50, 1 );

		// Başarısız / başarılı giriş takibi.
		add_action( 'wp_login_failed', array( $this, 'basarisiz_giris' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'basarili_giris' ), 10, 2 );

		// Kullanıcı adı/e-posta sızdırmamak için jenerik hata.
		add_filter( 'login_errors', array( $this, 'jenerik_hata' ) );
	}

	protected function ayar( $anahtar, $varsayilan = null ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		return isset( $ayarlar[ $anahtar ] ) ? $ayarlar[ $anahtar ] : $varsayilan;
	}

	protected function aktif() {
		return ! empty( $this->ayar( 'giris_korumasi' ) );
	}

	protected function deneme_anahtari() {
		return 'wpgk_giris_' . md5( WPGK_Logger::ip_al() );
	}

	protected function kilit_anahtari() {
		return 'wpgk_kilit_' . md5( WPGK_Logger::ip_al() );
	}

	/**
	 * IP kilitliyse her giriş denemesini reddet.
	 */
	public function kilit_kontrol( $user ) {
		if ( ! $this->aktif() ) {
			return $user;
		}
		if ( get_transient( $this->kilit_anahtari() ) ) {
			$dk = (int) $this->ayar( 'giris_kilit_dk', 15 );
			return new WP_Error(
				'wpgk_giris_kilit',
				sprintf(
					/* translators: %d: dakika */
					esc_html__( 'Çok fazla başarısız giriş denemesi. Lütfen %d dakika sonra tekrar deneyin.', 'wp-radar' ),
					$dk
				)
			);
		}
		return $user;
	}

	/**
	 * Başarısız girişte sayacı artır; eşik aşılırsa kilitle.
	 */
	public function basarisiz_giris( $username ) {
		if ( ! $this->aktif() ) {
			return;
		}

		$max   = max( 1, (int) $this->ayar( 'giris_max_deneme', 5 ) );
		$dk    = max( 1, (int) $this->ayar( 'giris_kilit_dk', 15 ) );
		$pencere = max( $dk, 15 );

		$anahtar = $this->deneme_anahtari();
		$sayi    = (int) get_transient( $anahtar );
		$sayi++;
		set_transient( $anahtar, $sayi, $pencere * MINUTE_IN_SECONDS );

		if ( $sayi >= $max ) {
			set_transient( $this->kilit_anahtari(), 1, $dk * MINUTE_IN_SECONDS );
			delete_transient( $anahtar );
			WPGK_Logger::kaydet(
				'giris',
				'brute_force_kilit',
				sprintf( 'IP %s %d başarısız denemeden sonra %d dakika kilitlendi. Son kullanıcı adı: %s', WPGK_Logger::ip_al(), $sayi, $dk, sanitize_user( (string) $username ) ),
				'kritik'
			);
		} else {
			WPGK_Logger::kaydet( 'giris', 'basarisiz_giris', sprintf( 'Başarısız giriş (%d/%d). Kullanıcı: %s', $sayi, $max, sanitize_user( (string) $username ) ), 'uyari' );
		}
	}

	/**
	 * Başarılı girişte sayaçları temizle.
	 */
	public function basarili_giris( $user_login, $user = null ) {
		delete_transient( $this->deneme_anahtari() );
		delete_transient( $this->kilit_anahtari() );
	}

	/**
	 * Giriş hatalarını jenerik hale getir (kullanıcı enumerasyonunu önler).
	 */
	public function jenerik_hata( $hata ) {
		if ( ! $this->aktif() || empty( $this->ayar( 'giris_jenerik_hata' ) ) ) {
			return $hata;
		}
		return esc_html__( 'Giriş bilgileri hatalı.', 'wp-radar' );
	}
}
