<?php
/**
 * Dosya koruması: root klasöre/uploads'a kötü amaçlı dosya yazılmasını engeller,
 * dosya bütünlüğünü izler ve dosya düzenleyiciyi kapatır.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_File_Guard {

	const BASELINE_OPSIYON = 'wpgk_dosya_baseline';

	/** Web shell / gizlenmiş kod imzaları. */
	const SHELL_IMZA = '/<\?php|<\?=|eval\s*\(\s*\$|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|gzuncompress\s*\(|assert\s*\(\s*\$|system\s*\(|shell_exec\s*\(|passthru\s*\(|preg_replace\s*\(\s*["\'].*\/e|create_function\s*\(/i';

	/** Tehlikeli kabul edilen uzantılar. */
	protected static $yasak_uzantilar = array(
		'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht', 'phar',
		'shtml', 'cgi', 'pl', 'asp', 'aspx', 'jsp', 'htaccess',
	);

	public function __construct() {
		// Medya/yükleme sırasında tehlikeli dosyaları engelle.
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'yukleme_on_denetimi' ), 1, 1 );
		add_filter( 'wp_check_filetype_and_ext', array( $this, 'tip_dogrula' ), 10, 4 );

		// Dosya editörlerini ve eklenti/tema kurulumunu (ayara göre) kilitle.
		add_action( 'init', array( $this, 'dosya_duzenleme_kilitle' ) );

		// Günlük bütünlük + uploads içi shell taraması.
		add_action( 'wpgk_gunluk_tarama', array( $this, 'uploads_shell_tara' ) );
		add_action( 'wpgk_gunluk_tarama', array( $this, 'butunluk_kontrol' ) );

		// Kök klasör spam koruması: saatlik + günlük + admin girişinde (kısıtlı).
		add_action( 'wpgk_saatlik_tarama', array( __CLASS__, 'kok_klasor_tara' ) );
		add_action( 'wpgk_gunluk_tarama', array( __CLASS__, 'kok_klasor_tara' ) );
		add_action( 'admin_init', array( $this, 'admin_kok_tara' ) );

		// WordPress klasör yapısı koruması.
		add_action( 'wpgk_gunluk_tarama', array( $this, 'yapi_kontrol' ) );

		// Çekirdek dosya bütünlüğü (WordPress.org checksums).
		add_action( 'wpgk_gunluk_tarama', array( $this, 'cekirdek_butunluk_kontrol' ) );
	}

	/**
	 * Yönetici panel yüklemesinde kök klasörü tara (10 dakikada bir, performans için).
	 */
	public function admin_kok_tara() {
		if ( get_transient( 'wpgk_kok_tara_kilit' ) ) {
			return;
		}
		set_transient( 'wpgk_kok_tara_kilit', 1, 10 * MINUTE_IN_SECONDS );
		self::kok_klasor_tara();
	}

	/**
	 * Yükleme öncesi: yasak uzantı ve çift uzantı (shell.php.jpg) denetimi.
	 */
	public function yukleme_on_denetimi( $file ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['dosya_korumasi'] ) ) {
			return $file;
		}

		$ad     = isset( $file['name'] ) ? strtolower( $file['name'] ) : '';
		$parcalar = explode( '.', $ad );

		// Tüm uzantı bileşenlerini kontrol et (çift uzantı saldırısı).
		foreach ( $parcalar as $p ) {
			if ( in_array( $p, self::$yasak_uzantilar, true ) ) {
				WPGK_Logger::kaydet( 'dosya', 'tehlikeli_yukleme', 'Engellenen dosya yükleme: ' . $ad, 'kritik' );
				$file['error'] = 'Güvenlik nedeniyle bu dosya türünün yüklenmesine izin verilmiyor.';
				return $file;
			}
		}

		// İçerik imzası: PHP açılış etiketi taşıyan dosyaları reddet.
		if ( ! empty( $file['tmp_name'] ) && is_readable( $file['tmp_name'] ) ) {
			$ornek = file_get_contents( $file['tmp_name'], false, null, 0, 8192 );
			if ( false !== $ornek && preg_match( '/<\?php|<\?=|eval\s*\(|base64_decode\s*\(/i', $ornek ) ) {
				WPGK_Logger::kaydet( 'dosya', 'gizli_php_yukleme', 'PHP kodu içeren dosya yükleme engellendi: ' . $ad, 'kritik' );
				$file['error'] = 'Dosya içeriği güvenlik taramasından geçemedi.';
			}
		}

		return $file;
	}

	/**
	 * Uzantı/MIME doğrulaması: WordPress'in izin verdiği türlerle sınırla.
	 */
	public function tip_dogrula( $data, $file, $filename, $mimes ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['dosya_korumasi'] ) ) {
			return $data;
		}

		$uzanti = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		if ( in_array( $uzanti, self::$yasak_uzantilar, true ) ) {
			$data['ext']             = false;
			$data['type']            = false;
			$data['proper_filename'] = false;
			WPGK_Logger::kaydet( 'dosya', 'tip_reddi', 'Reddedilen uzantı: ' . $filename, 'kritik' );
		}
		return $data;
	}

	/**
	 * wp-config sabitleriyle dosya düzenlemeyi kapat.
	 */
	public function dosya_duzenleme_kilitle() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['dosya_duzenleme_kapat'] ) ) {
			return;
		}
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
	}

	/**
	 * uploads klasöründe PHP çalıştırmayı .htaccess ile engelle (Apache).
	 */
	public static function uploads_htaccess_sertlestir() {
		$upload = wp_get_upload_dir();
		if ( empty( $upload['basedir'] ) || ! is_dir( $upload['basedir'] ) || ! is_writable( $upload['basedir'] ) ) {
			return;
		}
		$yol = trailingslashit( $upload['basedir'] ) . '.htaccess';
		$kural = "# WP Radar - uploads içinde script çalıştırma engeli\n"
			. "<FilesMatch \"\\.(php|php3|php4|php5|php7|phtml|pht|phar|cgi|pl|asp|aspx|jsp)$\">\n"
			. "    Require all denied\n"
			. "</FilesMatch>\n";

		$mevcut = is_readable( $yol ) ? file_get_contents( $yol ) : '';
		if ( false === strpos( (string) $mevcut, 'WP Radar' ) ) {
			file_put_contents( $yol, $kural . "\n" . $mevcut );
		}
	}

	/**
	 * Etkinleştirmede çekirdek dizinlerin bütünlük temelini (hash) kaydet.
	 */
	public static function baseline_olustur() {
		self::uploads_htaccess_sertlestir();

		$hedefler = array(
			ABSPATH . 'wp-config.php',
			ABSPATH . 'index.php',
			ABSPATH . '.htaccess',
		);

		$baseline = array();
		foreach ( $hedefler as $yol ) {
			if ( is_readable( $yol ) ) {
				$baseline[ $yol ] = md5_file( $yol );
			}
		}
		update_option( self::BASELINE_OPSIYON, $baseline );
	}

	/**
	 * Kritik dosyalarda değişiklik / yeni .php dosyası tespiti.
	 */
	public function butunluk_kontrol() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['dosya_korumasi'] ) ) {
			return;
		}

		$baseline = get_option( self::BASELINE_OPSIYON, array() );
		foreach ( $baseline as $yol => $eski_hash ) {
			if ( ! is_readable( $yol ) ) {
				WPGK_Logger::kaydet( 'dosya', 'kritik_dosya_silindi', 'Kritik dosya kayıp: ' . $yol, 'kritik' );
				continue;
			}
			$yeni = md5_file( $yol );
			if ( $yeni !== $eski_hash ) {
				WPGK_Logger::kaydet( 'dosya', 'kritik_dosya_degisti', 'Kritik dosya değiştirildi: ' . $yol, 'kritik' );
			}
		}

		// Root dizininde beklenmeyen yeni .php dosyaları (sızma kalıcılığı).
		$beklenen_root = array( 'index.php', 'wp-config.php', 'wp-load.php', 'wp-blog-header.php', 'wp-cron.php', 'wp-settings.php', 'wp-login.php', 'wp-links-opml.php', 'wp-comments-post.php', 'wp-signup.php', 'wp-activate.php', 'wp-trackback.php', 'wp-mail.php', 'xmlrpc.php', 'wp-config-sample.php' );
		$root_dosyalar = glob( ABSPATH . '*.php' );
		foreach ( (array) $root_dosyalar as $dosya ) {
			$ad = basename( $dosya );
			if ( ! in_array( $ad, $beklenen_root, true ) ) {
				WPGK_Logger::kaydet( 'dosya', 'supheli_root_php', 'Root dizininde beklenmeyen PHP dosyası: ' . $ad, 'kritik' );
			}
		}
	}

	/**
	 * uploads klasöründe web shell / php dosyası taraması.
	 */
	public function uploads_shell_tara() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['dosya_korumasi'] ) ) {
			return;
		}

		$upload = wp_get_upload_dir();
		if ( empty( $upload['basedir'] ) || ! is_dir( $upload['basedir'] ) ) {
			return;
		}

		$iter = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $upload['basedir'], FilesystemIterator::SKIP_DOTS )
		);

		// Gerçekten sunucuda çalıştırılabilen script uzantıları (.htaccess HARİÇ; o bir yapılandırma dosyasıdır).
		$script_uzantilari = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht', 'phar', 'shtml', 'cgi', 'pl', 'asp', 'aspx', 'jsp' );

		// Metin dosyaları için geniş shell imzası.
		$imza_metin = '/<\?php|<\?=|eval\s*\(\s*\$|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|assert\s*\(\s*\$|system\s*\(|shell_exec\s*\(/i';
		// İkili/görsel dosyalar için yalnızca gerçek PHP açılış etiketi (polyglot). İkili veride tesadüfen oluşmaz.
		$imza_ikili = '/<\?php|<\?=/';
		// Metin sayılan uzantılar (geniş imza güvenle uygulanabilir).
		$metin_uzantilari = array( 'txt', 'html', 'htm', 'xml', 'js', 'css', 'svg', 'json', 'csv', 'md', 'ini', 'log', 'xhtml' );

		foreach ( $iter as $dosya ) {
			if ( ! $dosya->isFile() ) {
				continue;
			}
			$uzanti = strtolower( $dosya->getExtension() );
			$ad     = strtolower( $dosya->getFilename() );
			$yol    = $dosya->getPathname();

			// 0) Meşru koruma/guard dosyalarını atla: boş "silence" index.php.
			if ( self::guvenli_koruma_dosyasi( $dosya, $uzanti, $ad ) ) {
				continue;
			}

			// 1) Gerçek script uzantıları → çalıştırılabilir dosya (kritik).
			if ( in_array( $uzanti, $script_uzantilari, true ) ) {
				WPGK_Logger::kaydet( 'dosya', 'uploads_php_tespit', 'uploads içinde çalıştırılabilir dosya: ' . $yol, 'kritik' );
				continue;
			}

			// 2) .htaccess: yalnızca PHP çalıştırmayı YENİDEN ETKİNLEŞTİREN direktif içeriyorsa tehlikeli.
			//    Aksi halde (deny/koruma kuralları) bu bir güvenlik dosyasıdır, atlanır.
			if ( 'htaccess' === $uzanti || '.htaccess' === $ad ) {
				$icerik = @file_get_contents( $yol, false, null, 0, 8192 );
				if ( false !== $icerik && preg_match( '/(AddHandler|SetHandler|AddType)[^\r\n]*(php|x-httpd)|php_(value|flag|admin_value|admin_flag)|application\/x-httpd-php|RemoveHandler[^\r\n]*php/i', $icerik ) ) {
					WPGK_Logger::kaydet( 'dosya', 'uploads_htaccess_tehlikeli', 'uploads içinde PHP çalıştırmayı etkinleştiren .htaccess: ' . $yol, 'kritik' );
				}
				continue;
			}

			// 3) Diğer dosyalar (görsel/medya/metin): içerik imzası taraması.
			if ( $dosya->getSize() > 0 && $dosya->getSize() < 2097152 ) {
				$ornek = file_get_contents( $yol, false, null, 0, 8192 );
				if ( false !== $ornek ) {
					$regex = in_array( $uzanti, $metin_uzantilari, true ) ? $imza_metin : $imza_ikili;
					if ( preg_match( $regex, $ornek ) ) {
						WPGK_Logger::kaydet( 'dosya', 'uploads_shell_imza', 'uploads içinde şüpheli kod imzası: ' . $yol, 'kritik' );
					}
				}
			}
		}
	}

	/**
	 * Meşru "silence is golden" guard dosyalarını (boş/önemsiz index.php) tanır.
	 * Birçok eklenti uploads alt klasörlerine dizin listelemeyi engellemek için
	 * boş bir index.php koyar; bunlar tehdit değildir.
	 *
	 * @return bool Dosya benign bir koruma dosyasıysa true.
	 */
	protected static function guvenli_koruma_dosyasi( $dosya, $uzanti, $ad ) {
		if ( 'php' === $uzanti && 'index.php' === $ad && $dosya->getSize() <= 256 ) {
			$icerik = @file_get_contents( $dosya->getPathname(), false, null, 0, 256 );
			if ( false !== $icerik
				&& ! preg_match( '/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|assert\s*\(|\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', $icerik ) ) {
				return true; // İçinde tehlikeli kod yok → boş guard dosyası.
			}
		}
		return false;
	}

	/**
	 * Kök dizinde bulunmasına izin verilen klasör adları.
	 *
	 * Normal bir WordPress kurulumunda kök dizinde yalnızca çekirdek klasörler
	 * fiziksel olarak bulunur. "category", "tag", "2024", "portfolio" gibi
	 * kalıcı bağlantı (permalink) adlarını taşıyan FİZİKSEL klasörler WordPress
	 * tarafından OLUŞTURULMAZ; bunlar tipik SEO spam / doorway saldırısıdır.
	 */
	public static function izinli_kok_klasorler() {
		$varsayilan = array(
			'wp-admin', 'wp-content', 'wp-includes',
			'cgi-bin', 'cgi-sys',          // hosting
			'.well-known',                 // SSL/ACME doğrulaması
		);

		// Kullanıcının panelden eklediği izinli klasörler.
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( ! empty( $ayarlar['kok_izinli'] ) ) {
			$ekstra = preg_split( '/[\r\n,]+/', (string) $ayarlar['kok_izinli'] );
			foreach ( $ekstra as $e ) {
				$e = trim( $e );
				if ( '' !== $e ) {
					$varsayilan[] = $e;
				}
			}
		}

		/**
		 * İzinli kök klasör listesini filtrelemeye izin ver.
		 */
		return array_unique( apply_filters( 'wpgk_izinli_kok_klasorler', $varsayilan ) );
	}

	/**
	 * Kök dizini ÖNCE tarar (içerik analizi), SONRA yalnızca zararlı kanıtı
	 * bulunan klasörleri (ayar açıksa) siler. Kanıt yoksa yalnızca raporlar.
	 *
	 * Bu sıralama, meşru ama izin listesinde olmayan bir klasörün yanlışlıkla
	 * silinmesini önler.
	 *
	 * @return array Bulgular listesi (rapor amaçlı).
	 */
	public static function kok_klasor_tara() {
		$bulgular = array();
		$ayarlar  = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['kok_klasor_korumasi'] ) ) {
			return $bulgular;
		}

		$kok = untrailingslashit( ABSPATH );
		if ( ! is_dir( $kok ) ) {
			return $bulgular;
		}

		$izinli   = self::izinli_kok_klasorler();
		$otomatik = ! empty( $ayarlar['kok_klasor_otomatik_sil'] );
		$girisler = @scandir( $kok );
		if ( false === $girisler ) {
			return $bulgular;
		}

		foreach ( $girisler as $ad ) {
			if ( '.' === $ad || '..' === $ad || '.' === $ad[0] ) {
				continue; // . .. ve gizli sistem klasörlerini atla.
			}
			$tam = $kok . DIRECTORY_SEPARATOR . $ad;
			if ( ! is_dir( $tam ) || in_array( $ad, $izinli, true ) ) {
				continue;
			}

			// 1) ADIM: TARA — klasör içeriğini analiz et.
			$analiz = self::klasor_zararli_mi( $tam, $ad );

			if ( $analiz['zararli'] ) {
				// 2) ADIM: ENGELLE — yalnızca kanıtlı zararlı klasörü sil.
				if ( $otomatik && self::klasor_sil( $tam ) ) {
					WPGK_Logger::kaydet( 'dosya', 'kok_spam_klasor_silindi', sprintf( 'Zararlı kök klasör silindi: /%s — %s', $ad, $analiz['neden'] ), 'kritik' );
					$bulgular[] = array( 'klasor' => $ad, 'durum' => 'silindi', 'neden' => $analiz['neden'] );
				} else {
					WPGK_Logger::kaydet( 'dosya', 'kok_spam_klasor_tespit', sprintf( 'Zararlı kök klasör tespit edildi: /%s — %s', $ad, $analiz['neden'] ), 'kritik' );
					$bulgular[] = array( 'klasor' => $ad, 'durum' => 'tespit', 'neden' => $analiz['neden'] );
				}
			} else {
				// Kanıt yok: silme, yalnızca incelenmek üzere bildir.
				WPGK_Logger::kaydet( 'dosya', 'kok_bilinmeyen_klasor', sprintf( 'İzin listesinde olmayan kök klasör (zararlı kanıtı yok): /%s. Meşruysa izin listesine ekleyin.', $ad ), 'uyari' );
				$bulgular[] = array( 'klasor' => $ad, 'durum' => 'supheli', 'neden' => 'İzin listesinde değil, zararlı kanıtı bulunamadı' );
			}
		}

		return $bulgular;
	}

	/**
	 * Bir kök klasörün içeriğini tarayarak zararlı olup olmadığına karar verir.
	 *
	 * Zararlı kanıtı: web shell imzası, yoğun spam anahtar kelimesi + dış bağlantı
	 * (SEO doorway), ya da kalıcı bağlantı taklidi adı + statik index dosyası.
	 *
	 * @return array array('zararli' => bool, 'neden' => string)
	 */
	protected static function klasor_zararli_mi( $dir, $ad ) {
		// WordPress'in fiziksel olarak ASLA oluşturmadığı, kalıcı bağlantı/arşiv
		// adlarını taklit eden klasörler isimleriyle güçlü kanıt sayılır.
		if ( preg_match( '/^(\d{4}|category|tag|author|page|feed|embed|comments|trackback|portfolio|portfolio-tag|product-tag|amp)$/i', $ad ) ) {
			return array( 'zararli' => true, 'neden' => 'WordPress tarafından oluşturulmayan permalink-taklidi kök klasör' );
		}
		$permalink_taklit = true; // İçerikte çalıştırılabilir dosya da güçlü işarettir.

		$dosya_sayisi = 0;
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
			);
		} catch ( Exception $e ) {
			return array( 'zararli' => false, 'neden' => '' );
		}

		foreach ( $iter as $dosya ) {
			if ( ! $dosya->isFile() || $dosya_sayisi >= 60 ) {
				if ( $dosya_sayisi >= 60 ) {
					break;
				}
				continue;
			}
			$dosya_sayisi++;
			$uzanti = strtolower( $dosya->getExtension() );

			// Çalıştırılabilir dosya barındıran kök klasör güçlü zararlı işareti.
			if ( in_array( $uzanti, self::$yasak_uzantilar, true ) && $permalink_taklit ) {
				return array( 'zararli' => true, 'neden' => 'permalink taklidi klasörde çalıştırılabilir dosya: ' . $dosya->getFilename() );
			}

			if ( ! in_array( $uzanti, array( 'php', 'phtml', 'html', 'htm', 'txt', 'xml' ), true ) ) {
				continue;
			}
			if ( $dosya->getSize() <= 0 || $dosya->getSize() > 3145728 ) {
				continue;
			}

			$icerik = @file_get_contents( $dosya->getPathname(), false, null, 0, 32768 );
			if ( false === $icerik ) {
				continue;
			}

			// Web shell / gizlenmiş kod.
			if ( preg_match( self::SHELL_IMZA, $icerik ) && in_array( $uzanti, array( 'php', 'phtml', 'html', 'htm', 'txt', 'xml' ), true ) && 'php' !== $uzanti ) {
				return array( 'zararli' => true, 'neden' => 'gizlenmiş kod imzası: ' . $dosya->getFilename() );
			}
			if ( 'php' === $uzanti && preg_match( '/eval\s*\(\s*\$|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\(|system\s*\(/i', $icerik ) ) {
				return array( 'zararli' => true, 'neden' => 'şüpheli PHP kodu: ' . $dosya->getFilename() );
			}

			// SEO spam doorway: spam anahtar kelime + dış bağlantı.
			$dis_link = (bool) preg_match( '/href\s*=\s*["\']?https?:\/\//i', $icerik );
			if ( $dis_link && class_exists( 'WPGK_Content_Guard' ) && WPGK_Content_Guard::metinde_spam_var_mi( $icerik ) ) {
				return array( 'zararli' => true, 'neden' => 'SEO spam doorway (spam anahtar kelime + dış bağlantı): ' . $dosya->getFilename() );
			}
		}

		return array( 'zararli' => false, 'neden' => '' );
	}

	/**
	 * WordPress.org resmi checksum'larıyla çekirdek dosyaları karşılaştırır.
	 * Değiştirilmiş/enjekte edilmiş çekirdek dosyalarını tespit eder.
	 */
	public function cekirdek_butunluk_kontrol() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['cekirdek_butunluk'] ) ) {
			return;
		}

		global $wp_version;
		if ( empty( $wp_version ) ) {
			return;
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$locale    = get_locale();
		$checksums = get_core_checksums( $wp_version, empty( $locale ) ? 'en_US' : $locale );
		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return; // API erişilemedi; sessizce çık.
		}

		$degisen = 0;
		$limit   = 30;
		foreach ( $checksums as $dosya => $hash ) {
			// Kullanıcıya ait wp-content'i atla (tema/eklenti/upload meşru değişir).
			if ( 0 === strpos( $dosya, 'wp-content/' ) ) {
				continue;
			}
			$yol = ABSPATH . $dosya;
			if ( ! file_exists( $yol ) ) {
				continue; // Eksik isteğe bağlı dosyalar (ör. dil) için gürültü yapma.
			}
			if ( md5_file( $yol ) !== $hash ) {
				if ( $degisen < $limit ) {
					WPGK_Logger::kaydet( 'dosya', 'cekirdek_dosya_degisti', 'Çekirdek dosya resmi sürümden farklı (enjeksiyon şüphesi): ' . $dosya, 'kritik' );
				}
				$degisen++;
			}
		}

		if ( $degisen > $limit ) {
			WPGK_Logger::kaydet( 'dosya', 'cekirdek_butunluk_ozet', sprintf( 'Toplam %d çekirdek dosya resmi sürümden farklı. Çekirdeği yeniden yüklemeniz önerilir.', $degisen ), 'kritik' );
		} elseif ( 0 === $degisen ) {
			WPGK_Logger::kaydet( 'dosya', 'cekirdek_butunluk_temiz', 'Çekirdek dosya bütünlüğü doğrulandı (değişiklik yok).', 'bilgi' );
		}
	}

	/**
	 * WordPress çekirdek klasör yapısını doğrular (yapı koruması).
	 */
	public function yapi_kontrol() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['yapi_korumasi'] ) ) {
			return;
		}

		$cekirdek = array( 'wp-admin', 'wp-includes', WP_CONTENT_DIR );
		$kok      = untrailingslashit( ABSPATH );

		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			if ( ! is_dir( $kok . DIRECTORY_SEPARATOR . $dir ) ) {
				WPGK_Logger::kaydet( 'dosya', 'yapi_bozuk', 'Çekirdek WordPress klasörü eksik/bozuk: ' . $dir, 'kritik' );
			}
		}
		if ( ! is_dir( WP_CONTENT_DIR ) ) {
			WPGK_Logger::kaydet( 'dosya', 'yapi_bozuk', 'wp-content klasörü bulunamadı.', 'kritik' );
		}
	}

	/**
	 * Bir klasörü güvenli biçimde (yalnızca ABSPATH altında ve doğrudan alt
	 * klasör ise) özyinelemeli olarak siler.
	 *
	 * @return bool Başarılıysa true.
	 */
	protected static function klasor_sil( $hedef ) {
		$kok       = realpath( untrailingslashit( ABSPATH ) );
		$gercek    = realpath( $hedef );

		// Güvenlik: hedef çözülebilmeli, bir klasör olmalı ve ABSPATH'in
		// DOĞRUDAN alt klasörü olmalı (symlink/üst dizin kaçışı engellenir).
		if ( false === $kok || false === $gercek || ! is_dir( $gercek ) ) {
			return false;
		}
		if ( dirname( $gercek ) !== $kok ) {
			return false;
		}
		// Çekirdek klasörleri asla silme (ekstra güvenlik kemeri).
		$korunan = array( 'wp-admin', 'wp-content', 'wp-includes' );
		if ( in_array( basename( $gercek ), $korunan, true ) ) {
			return false;
		}

		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $gercek, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $iter as $oge ) {
				if ( $oge->isDir() ) {
					@rmdir( $oge->getPathname() );
				} else {
					@unlink( $oge->getPathname() );
				}
			}
		} catch ( Exception $e ) {
			return false;
		}

		return @rmdir( $gercek );
	}
}
