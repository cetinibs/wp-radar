<?php
/**
 * Giriş güvenliği: iki faktörlü doğrulama (TOTP), giriş CAPTCHA'sı ve
 * elle IP kara/beyaz liste yönetimi.
 *
 * - 2FA: RFC 6238 uyumlu TOTP (Google Authenticator, Authy vb.). Kullanıcı
 *   bazında etkinleştirilir; gizli anahtar kullanıcı meta'sında saklanır.
 * - CAPTCHA: dış servis gerektirmeyen basit matematik sorusu.
 * - IP listeleri: beyaz liste tüm CK Radar Security engellerini atlar; kara liste
 *   erişimi tamamen reddeder (CIDR /24 vb. desteklenir).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Login_Security {

	const META_SECRET = 'wpgk_2fa_secret';
	const META_AKTIF  = 'wpgk_2fa_aktif';

	public function __construct() {
		// IP kara/beyaz liste uygulaması (mümkün olan en erken aşama).
		add_action( 'init', array( $this, 'ip_listesi_uygula' ), 0 );
		add_action( 'login_init', array( $this, 'ip_listesi_uygula' ), 0 );

		// Giriş formuna CAPTCHA ve 2FA alanlarını ekle.
		add_action( 'login_form', array( $this, 'giris_alanlari' ) );

		// Kimlik doğrulama: CAPTCHA (önce) ve 2FA (sonra) denetimi.
		add_filter( 'authenticate', array( $this, 'captcha_dogrula' ), 21, 1 );
		add_filter( 'authenticate', array( $this, 'iki_faktor_dogrula' ), 30, 3 );

		// Kullanıcının 2FA kurulum sayfası (CK Radar Security alt menüsü) işlemleri.
		add_action( 'admin_init', array( $this, 'iki_faktor_form_isle' ) );
	}

	/* ===================== IP KARA / BEYAZ LİSTE ===================== */

	/**
	 * Ayardaki bir liste alanını satırlara böler.
	 */
	protected static function liste( $anahtar ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$ham     = isset( $ayarlar[ $anahtar ] ) ? (string) $ayarlar[ $anahtar ] : '';
		$cikti   = array();
		foreach ( preg_split( '/[\r\n,\s]+/', $ham ) as $p ) {
			$p = trim( $p );
			if ( '' !== $p ) {
				$cikti[] = $p;
			}
		}
		return $cikti;
	}

	/**
	 * Bir IP, verilen kurala (tam IP veya IPv4 CIDR) uyuyor mu?
	 */
	protected static function ip_eslesir_mi( $ip, $kural ) {
		if ( $ip === $kural ) {
			return true;
		}
		// IPv4 CIDR (ör. 203.0.113.0/24).
		if ( false !== strpos( $kural, '/' ) && false !== strpos( $ip, '.' ) ) {
			list( $alt, $bit ) = array_pad( explode( '/', $kural, 2 ), 2, '32' );
			$bit = (int) $bit;
			if ( $bit < 0 || $bit > 32 || false === filter_var( $alt, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return false;
			}
			$ip_uzun  = ip2long( $ip );
			$alt_uzun = ip2long( $alt );
			if ( false === $ip_uzun || false === $alt_uzun ) {
				return false;
			}
			$maske = 0 === $bit ? 0 : ( -1 << ( 32 - $bit ) ) & 0xFFFFFFFF;
			return ( $ip_uzun & $maske ) === ( $alt_uzun & $maske );
		}
		return false;
	}

	/**
	 * IP beyaz listede mi? (Diğer modüller bunu "engelleri atla" için kullanır.)
	 */
	public static function beyaz_listede_mi( $ip = null ) {
		$ip = $ip ? $ip : WPGK_Logger::ip_al();
		foreach ( self::liste( 'ip_beyaz_liste' ) as $kural ) {
			if ( self::ip_eslesir_mi( $ip, $kural ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * IP kara listede mi?
	 */
	public static function kara_listede_mi( $ip = null ) {
		$ip = $ip ? $ip : WPGK_Logger::ip_al();
		foreach ( self::liste( 'ip_kara_liste' ) as $kural ) {
			if ( self::ip_eslesir_mi( $ip, $kural ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Kara listedeki IP'leri reddet (beyaz liste önceliklidir).
	 */
	public function ip_listesi_uygula() {
		$ip = WPGK_Logger::ip_al();
		if ( self::beyaz_listede_mi( $ip ) ) {
			return;
		}
		// Oturum açmış düzenleme yetkili kullanıcıları otomatik engelden muaf tut.
		$duzenleyici = is_user_logged_in() && current_user_can( 'edit_posts' );

		// Elle kara liste: her zaman uygulanır.
		if ( self::kara_listede_mi( $ip ) ) {
			WPGK_Logger::kaydet( 'giris', 'ip_kara_liste', 'Kara listedeki IP engellendi: ' . $ip, 'uyari' );
			$this->engelle( __( 'Erişiminiz engellendi.', 'ck-radar-security' ) );
		}

		// Davranışsal otomatik engel (tekrarlayan şüpheli olaylar).
		if ( ! $duzenleyici && WPGK_Logger::otomatik_engelli_mi( $ip ) ) {
			$this->engelle( __( 'Şüpheli etkinlik nedeniyle erişiminiz geçici olarak engellendi.', 'ck-radar-security' ) );
		}
	}

	/**
	 * İsteği 403 ile sonlandırır.
	 */
	protected function engelle( $mesaj ) {
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html( $mesaj ),
			esc_html__( 'Erişim Engellendi', 'ck-radar-security' ),
			array( 'response' => 403 )
		);
	}

	/* ===================== GİRİŞ FORMU ALANLARI ===================== */

	/**
	 * Giriş formuna CAPTCHA ve (gerekiyorsa) 2FA kod alanını ekler.
	 */
	public function giris_alanlari() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );

		if ( ! empty( $ayarlar['giris_captcha'] ) ) {
			$a = wp_rand( 1, 9 );
			$b = wp_rand( 1, 9 );
			$token = wp_generate_password( 20, false );
			set_transient( 'wpgk_captcha_' . $token, $a + $b, 10 * MINUTE_IN_SECONDS );
			echo '<p><label for="wpgk_captcha">' . esc_html( sprintf( 'Güvenlik sorusu: %d + %d = ?', $a, $b ) ) . '</label>';
			echo '<input type="text" name="wpgk_captcha" id="wpgk_captcha" class="input" autocomplete="off" inputmode="numeric" /></p>';
			echo '<input type="hidden" name="wpgk_captcha_token" value="' . esc_attr( $token ) . '" />';
		}

		if ( ! empty( $ayarlar['giris_2fa'] ) ) {
			echo '<p><label for="wpgk_2fa_kod">Doğrulama kodu (2FA, etkinse)</label>';
			echo '<input type="text" name="wpgk_2fa_kod" id="wpgk_2fa_kod" class="input" autocomplete="one-time-code" inputmode="numeric" /></p>';
		}
	}

	/* ===================== CAPTCHA ===================== */

	/**
	 * Giriş CAPTCHA'sını doğrula (parola denetiminden hemen sonra).
	 */
	public function captcha_dogrula( $user ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['giris_captcha'] ) ) {
			return $user;
		}
		// Yalnızca asıl giriş POST'unda denetle (XML-RPC vb. değil).
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '' ) ) {
			return $user;
		}
		if ( empty( $_POST['log'] ) && empty( $_POST['pwd'] ) ) {
			return $user; // Giriş gönderimi değil.
		}

		$token = isset( $_POST['wpgk_captcha_token'] ) ? sanitize_text_field( wp_unslash( $_POST['wpgk_captcha_token'] ) ) : '';
		$cevap = isset( $_POST['wpgk_captcha'] ) ? (int) wp_unslash( $_POST['wpgk_captcha'] ) : null;
		$beklenen = $token ? get_transient( 'wpgk_captcha_' . $token ) : false;
		if ( $token ) {
			delete_transient( 'wpgk_captcha_' . $token );
		}

		if ( false === $beklenen || null === $cevap || (int) $beklenen !== $cevap ) {
			return new WP_Error( 'wpgk_captcha', __( '<strong>Hata:</strong> Güvenlik sorusunun yanıtı yanlış.', 'ck-radar-security' ) );
		}
		return $user;
	}

	/* ===================== TOTP / 2FA ===================== */

	/**
	 * Bir kullanıcı için 2FA etkin mi?
	 */
	public static function kullanici_2fa_aktif( $user_id ) {
		return '1' === (string) get_user_meta( $user_id, self::META_AKTIF, true )
			&& '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * Giriş sırasında TOTP kodunu doğrula.
	 */
	public function iki_faktor_dogrula( $user, $username = '', $password = '' ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['giris_2fa'] ) ) {
			return $user;
		}
		// Parola aşaması başarısızsa karışma.
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		if ( ! self::kullanici_2fa_aktif( $user->ID ) ) {
			return $user; // Bu kullanıcı 2FA kurmamış.
		}

		$kod = isset( $_POST['wpgk_2fa_kod'] ) ? preg_replace( '/\D/', '', wp_unslash( $_POST['wpgk_2fa_kod'] ) ) : '';
		if ( '' === $kod ) {
			return new WP_Error( 'wpgk_2fa_gerekli', __( '<strong>Doğrulama gerekli:</strong> Lütfen 2FA uygulamanızdaki 6 haneli kodu girin.', 'ck-radar-security' ) );
		}
		$secret = (string) get_user_meta( $user->ID, self::META_SECRET, true );
		if ( ! self::totp_dogrula( $secret, $kod ) ) {
			WPGK_Logger::kaydet( 'giris', '2fa_basarisiz', 'Hatalı 2FA kodu: ' . $user->user_login, 'uyari' );
			return new WP_Error( 'wpgk_2fa_hata', __( '<strong>Hata:</strong> Doğrulama kodu geçersiz.', 'ck-radar-security' ) );
		}
		return $user;
	}

	/**
	 * Base32 (RFC 4648) çözücü.
	 */
	protected static function base32_coz( $b32 ) {
		$abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$b32 = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $b32 ) );
		$bit = '';
		for ( $i = 0; $i < strlen( $b32 ); $i++ ) {
			$pos = strpos( $abc, $b32[ $i ] );
			if ( false === $pos ) {
				continue;
			}
			$bit .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$cikti = '';
		for ( $i = 0; $i + 8 <= strlen( $bit ); $i += 8 ) {
			$cikti .= chr( bindec( substr( $bit, $i, 8 ) ) );
		}
		return $cikti;
	}

	/**
	 * Rastgele Base32 gizli anahtar üretir (160 bit).
	 */
	public static function secret_uret() {
		$abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$s   = '';
		for ( $i = 0; $i < 32; $i++ ) {
			$s .= $abc[ wp_rand( 0, 31 ) ];
		}
		return $s;
	}

	/**
	 * Belirli bir zaman adımı için HOTP/TOTP kodu hesaplar.
	 */
	protected static function totp_kod( $secret, $zaman_adimi ) {
		$key = self::base32_coz( $secret );
		if ( '' === $key ) {
			return '';
		}
		$bin = pack( 'N*', 0 ) . pack( 'N*', $zaman_adimi ); // 64-bit big-endian sayaç.
		$hash = hash_hmac( 'sha1', $bin, $key, true );
		$ofset = ord( substr( $hash, -1 ) ) & 0x0F;
		$parca = substr( $hash, $ofset, 4 );
		$deger = ( ( ord( $parca[0] ) & 0x7F ) << 24 )
			| ( ( ord( $parca[1] ) & 0xFF ) << 16 )
			| ( ( ord( $parca[2] ) & 0xFF ) << 8 )
			| ( ord( $parca[3] ) & 0xFF );
		return str_pad( (string) ( $deger % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	/**
	 * TOTP kodunu ±1 zaman penceresiyle (saat kayması toleransı) doğrular.
	 */
	public static function totp_dogrula( $secret, $kod ) {
		$kod = preg_replace( '/\D/', '', (string) $kod );
		if ( 6 !== strlen( $kod ) || '' === $secret ) {
			return false;
		}
		$adim = (int) floor( time() / 30 );
		for ( $d = -1; $d <= 1; $d++ ) {
			if ( hash_equals( self::totp_kod( $secret, $adim + $d ), $kod ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Authenticator uygulamalarının okuduğu otpauth:// URI'sini üretir.
	 */
	public static function otpauth_uri( $secret, $user ) {
		$etiket = rawurlencode( get_bloginfo( 'name' ) . ':' . $user->user_login );
		$issuer = rawurlencode( get_bloginfo( 'name' ) );
		return sprintf( 'otpauth://totp/%s?secret=%s&issuer=%s&digits=6&period=30', $etiket, $secret, $issuer );
	}

	/**
	 * 2FA kurulum formunu işler (etkinleştir / devre dışı bırak).
	 */
	public function iki_faktor_form_isle() {
		if ( ! isset( $_POST['wpgk_2fa_nonce'] ) || ! current_user_can( 'read' ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_2fa_nonce'] ) ), 'wpgk_2fa_kur' ) ) {
			return;
		}
		$uid = get_current_user_id();

		// Devre dışı bırak.
		if ( isset( $_POST['wpgk_2fa_kapat'] ) ) {
			delete_user_meta( $uid, self::META_AKTIF );
			delete_user_meta( $uid, self::META_SECRET );
			set_transient( 'wpgk_2fa_mesaj_' . $uid, 'kapatildi', 30 );
			wp_safe_redirect( admin_url( 'admin.php?page=wpgk-2fa' ) );
			exit;
		}

		// Etkinleştirmeyi onayla: bekleyen gizli anahtarı doğrulama koduyla aktive et.
		$secret = isset( $_POST['wpgk_2fa_secret'] ) ? preg_replace( '/[^A-Z2-7]/', '', strtoupper( wp_unslash( $_POST['wpgk_2fa_secret'] ) ) ) : '';
		$kod    = isset( $_POST['wpgk_2fa_dogrula'] ) ? wp_unslash( $_POST['wpgk_2fa_dogrula'] ) : '';
		if ( $secret && self::totp_dogrula( $secret, $kod ) ) {
			update_user_meta( $uid, self::META_SECRET, $secret );
			update_user_meta( $uid, self::META_AKTIF, '1' );
			set_transient( 'wpgk_2fa_mesaj_' . $uid, 'aktif', 30 );
		} else {
			set_transient( 'wpgk_2fa_mesaj_' . $uid, 'hata', 30 );
			set_transient( 'wpgk_2fa_bekleyen_' . $uid, $secret, 10 * MINUTE_IN_SECONDS );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=wpgk-2fa' ) );
		exit;
	}

	/**
	 * 2FA kurulum sayfasını çizer (CK Radar Security alt menüsü).
	 */
	public function sayfa_render() {
		$uid    = get_current_user_id();
		$user   = wp_get_current_user();
		$aktif  = self::kullanici_2fa_aktif( $uid );
		$mesaj  = get_transient( 'wpgk_2fa_mesaj_' . $uid );
		if ( $mesaj ) {
			delete_transient( 'wpgk_2fa_mesaj_' . $uid );
		}
		// Etkin değilse: kurulum için (bekleyen ya da yeni) gizli anahtar hazırla.
		$secret = '';
		if ( ! $aktif ) {
			$secret = get_transient( 'wpgk_2fa_bekleyen_' . $uid );
			if ( ! $secret ) {
				$secret = self::secret_uret();
				set_transient( 'wpgk_2fa_bekleyen_' . $uid, $secret, 10 * MINUTE_IN_SECONDS );
			}
		}
		?>
		<div class="wrap">
			<h1>İki Faktörlü Doğrulama (2FA)</h1>
			<?php if ( 'aktif' === $mesaj ) : ?>
				<div class="notice notice-success is-dismissible"><p>2FA etkinleştirildi. Bundan sonra girişte doğrulama kodu istenecek.</p></div>
			<?php elseif ( 'kapatildi' === $mesaj ) : ?>
				<div class="notice notice-warning is-dismissible"><p>2FA devre dışı bırakıldı.</p></div>
			<?php elseif ( 'hata' === $mesaj ) : ?>
				<div class="notice notice-error is-dismissible"><p>Doğrulama kodu hatalı. Uygulamanızdaki güncel kodu girdiğinizden ve telefon saatinin doğru olduğundan emin olun.</p></div>
			<?php endif; ?>

			<?php
			$genel = get_option( 'wpgk_ayarlar', array() );
			if ( empty( $genel['giris_2fa'] ) ) {
				echo '<div class="notice notice-info"><p>2FA modülü şu an <strong>kapalı</strong>. CK Radar Security ayarlarından "Giriş güvenliği → 2FA" seçeneğini açın; aksi halde kurduğunuz 2FA girişte istenmez.</p></div>';
			}
			?>

			<?php if ( $aktif ) : ?>
				<p><strong><?php echo esc_html( $user->user_login ); ?></strong> hesabı için iki faktörlü doğrulama <span style="color:#00782b;font-weight:600;">etkin</span>.</p>
				<form method="post">
					<?php wp_nonce_field( 'wpgk_2fa_kur', 'wpgk_2fa_nonce' ); ?>
					<?php submit_button( '2FA\'yı Devre Dışı Bırak', 'delete', 'wpgk_2fa_kapat', false ); ?>
				</form>
			<?php else : ?>
				<ol style="max-width:760px;">
					<li>Telefonunuza bir authenticator uygulaması kurun (Google Authenticator, Microsoft Authenticator, Authy …).</li>
					<li>Uygulamada "hesap ekle → kurulum anahtarını gir" deyip aşağıdaki anahtarı yazın:
						<p><code style="font-size:16px;letter-spacing:2px;background:#f6f7f7;padding:8px 12px;display:inline-block;"><?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?></code></p>
						<p class="description">Gelişmiş kurulum bağlantısı (otpauth): <code><?php echo esc_html( self::otpauth_uri( $secret, $user ) ); ?></code></p>
					</li>
					<li>Uygulamanın ürettiği 6 haneli kodu girip onaylayın:
						<form method="post" style="margin-top:8px;">
							<?php wp_nonce_field( 'wpgk_2fa_kur', 'wpgk_2fa_nonce' ); ?>
							<input type="hidden" name="wpgk_2fa_secret" value="<?php echo esc_attr( $secret ); ?>" />
							<input type="text" name="wpgk_2fa_dogrula" inputmode="numeric" autocomplete="one-time-code" placeholder="6 haneli kod" class="regular-text" style="max-width:160px;" />
							<?php submit_button( 'Etkinleştir', 'primary', 'wpgk_2fa_etkinlestir', false ); ?>
						</form>
					</li>
				</ol>
				<p class="description" style="max-width:760px;">Güvenlik: Kurtarma için bir yedek admin hesabınız olduğundan emin olun. Telefonunuzu kaybederseniz, sunucuya (hPanel/FTP) erişerek bu kullanıcının <code>wpgk_2fa_aktif</code> meta değerini silerek 2FA'yı kapatabilirsiniz.</p>
			<?php endif; ?>
		</div>
		<?php
	}
}
