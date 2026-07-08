<?php
/**
 * İçerik koruması: yazı, yorum ve seçeneklere enjekte edilen
 * porno / kumar / oyun / SEO spam linklerini engeller ve temizler.
 *
 * Yanlış pozitifleri azaltmak için:
 *  - Anahtar kelimeler Unicode kelime sınırlarıyla eşleştirilir
 *    ("bet" → "Betül" veya "sex" → "Essex" eşleşmez).
 *  - İçerik/yorum otomatik engelleme yalnızca "spam kelime + link" birlikte
 *    bulunduğunda veya gizli link enjeksiyonu varsa tetiklenir; tek başına
 *    anahtar kelime yalnızca loglanır.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Content_Guard {

	/** Derlenmiş anahtar kelime regex'i (istek başına bir kez). */
	protected static $regex = null;

	/**
	 * Yasaklı anahtar kelime ve ifadeler.
	 */
	protected static function yasakli_kaliplar() {
		$varsayilan = array(
			// Kumar / bahis
			'casino', 'kumar', 'bahis', 'bet', 'betting', 'slot', 'rulet', 'poker',
			'iddaa', 'jackpot', 'gambling', 'deneme bonusu', 'bonus veren',
			'guvenilir bahis', 'canli casino', 'bahis siteleri', 'sweet bonanza',
			// Yetişkin / porno
			'porno', 'porn', 'sex', 'seks', 'xxx', 'escort', 'hentai',
			'viagra', 'cialis', 'erotik', 'sikis', 'adult',
			// Yasa dışı / korsan oyun & yazılım
			'bedava oyun', 'hile apk', 'mod apk', 'crack indir', 'serial key',
			'free robux', 'free vbucks', 'cheat engine', 'aimbot', 'oyun hilesi',
			// Yaygın spam
			'replica watch', 'rolex replica', 'payday loan',
		);

		/**
		 * Yasaklı kalıpları filtrelemeye izin ver.
		 */
		return apply_filters( 'wpgk_yasakli_kaliplar', $varsayilan );
	}

	public function __construct() {
		// Yazı/sayfa kaydında içerik denetimi.
		add_filter( 'wp_insert_post_data', array( $this, 'yazi_denetle' ), 10, 2 );

		// Yorum spam koruması.
		add_filter( 'preprocess_comment', array( $this, 'yorum_denetle' ), 1, 1 );

		// Seçenek enjeksiyonu (ör. blogname, blogdescription).
		add_filter( 'pre_update_option_blogname', array( $this, 'secenek_denetle' ), 10, 2 );
		add_filter( 'pre_update_option_blogdescription', array( $this, 'secenek_denetle' ), 10, 2 );

		// Sızıntı sonrası gizli/spam link enjeksiyonu için günlük tarama.
		add_action( 'wpgk_gunluk_tarama', array( $this, 'gizli_link_tara' ) );

		// Render anında zararlı link otomatik engelleme (DB'de zaten enjekte
		// edilmiş linkler ön yüzde gösterilmez).
		add_filter( 'the_content', array( $this, 'render_link_temizle' ), 99 );
		add_filter( 'the_excerpt', array( $this, 'render_link_temizle' ), 99 );
		add_filter( 'comment_text', array( $this, 'render_link_temizle' ), 99 );
		add_filter( 'widget_text', array( $this, 'render_link_temizle' ), 99 );
		add_filter( 'widget_block_content', array( $this, 'render_link_temizle' ), 99 );
	}

	/**
	 * Dışarıdan kullanım için: metinde spam anahtar kelimesi var mı?
	 */
	public static function metinde_spam_var_mi( $metin, &$eslesme = '' ) {
		$regex = self::regex();
		if ( false === $regex ) {
			return false;
		}
		if ( preg_match( $regex, wp_strip_all_tags( (string) $metin ), $m ) ) {
			$eslesme = isset( $m[1] ) ? $m[1] : '';
			return true;
		}
		return false;
	}

	/**
	 * Kullanıcının tanımladığı zararlı domain listesi (alt alana izin verir).
	 */
	protected function zararli_domainler() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		$liste   = array();
		if ( ! empty( $ayarlar['zararli_domainler'] ) ) {
			foreach ( preg_split( '/[\r\n,\s]+/', (string) $ayarlar['zararli_domainler'] ) as $d ) {
				$d = strtolower( trim( $d ) );
				$d = preg_replace( '#^https?://#', '', $d );
				$d = trim( $d, '/' );
				if ( '' !== $d ) {
					$liste[] = $d;
				}
			}
		}
		return apply_filters( 'wpgk_zararli_domainler', $liste );
	}

	/**
	 * Tek bir <a> etiketinin zararlı olup olmadığına karar verir.
	 */
	protected function link_zararli_mi( $tam_etiket, $href, $ic_metin ) {
		// 1) Gizli link stili.
		if ( $this->gizli_link_iceriyor_mu( $tam_etiket ) ) {
			return true;
		}
		// 2) Spam anahtar kelimesi (href veya bağlantı metni).
		if ( self::metinde_spam_var_mi( $href . ' ' . $ic_metin ) ) {
			return true;
		}
		// 3) Kara liste domain.
		$host = strtolower( (string) wp_parse_url( $href, PHP_URL_HOST ) );
		if ( '' !== $host ) {
			foreach ( $this->zararli_domainler() as $kotu ) {
				if ( $host === $kotu || substr( $host, -strlen( $kotu ) - 1 ) === '.' . $kotu ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Render anında zararlı <a> bağlantılarını çıkarır (metni korur).
	 */
	public function render_link_temizle( $html ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['link_korumasi'] ) || '' === trim( (string) $html ) ) {
			return $html;
		}
		if ( false === stripos( $html, '<a' ) ) {
			return $html; // Bağlantı yok.
		}

		$temiz = preg_replace_callback(
			'/<a\b([^>]*)>(.*?)<\/a>/is',
			function ( $m ) {
				$nitelik  = $m[1];
				$ic_metin = $m[2];
				$href     = '';
				if ( preg_match( '/href\s*=\s*("|\')(.*?)\1/i', $nitelik, $h ) ) {
					$href = $h[2];
				}
				if ( $this->link_zararli_mi( $m[0], $href, $ic_metin ) ) {
					// Log taşmasını önlemek için saatte bir kez kaydet.
					if ( ! get_transient( 'wpgk_render_link_kilit' ) ) {
						set_transient( 'wpgk_render_link_kilit', 1, HOUR_IN_SECONDS );
						WPGK_Logger::kaydet( 'icerik', 'render_zararli_link', 'Ön yüzde zararlı bağlantı temizlendi: ' . WPGK_Util::kes( $href, 0, 150 ), 'uyari' );
					}
					return $ic_metin; // Bağlantıyı kaldır, görünen metni koru.
				}
				return $m[0];
			},
			$html
		);

		return ( null === $temiz ) ? $html : $temiz;
	}

	/**
	 * Anahtar kelime regex'ini (Unicode sınırlı) derler ve önbelleğe alır.
	 */
	protected static function regex() {
		if ( null !== self::$regex ) {
			return self::$regex;
		}
		$parcalar = array();
		foreach ( self::yasakli_kaliplar() as $kalip ) {
			$kalip = trim( (string) $kalip );
			if ( '' !== $kalip ) {
				$parcalar[] = preg_quote( $kalip, '/' );
			}
		}
		if ( empty( $parcalar ) ) {
			self::$regex = false;
			return false;
		}
		// Her iki yanında harf/rakam OLMAYAN konumda eşleştir (kelime sınırı).
		self::$regex = '/(?<![\p{L}\p{N}])(' . implode( '|', $parcalar ) . ')(?![\p{L}\p{N}])/iu';
		return self::$regex;
	}

	/**
	 * Metinde yasaklı kalıp var mı? Eşleşeni $eslesme'ye yazar.
	 */
	protected function spam_iceriyor_mu( $metin, &$eslesme = '' ) {
		$regex = self::regex();
		if ( false === $regex ) {
			return false;
		}
		$metin = wp_strip_all_tags( (string) $metin );
		if ( preg_match( $regex, $metin, $m ) ) {
			$eslesme = isset( $m[1] ) ? $m[1] : '';
			return true;
		}
		return false;
	}

	/**
	 * Metin bir bağlantı içeriyor mu? (http(s):// veya <a href)
	 */
	protected function link_iceriyor_mu( $metin ) {
		return (bool) preg_match( '/(https?:\/\/|<a\s[^>]*href\s*=)/i', (string) $metin );
	}

	/**
	 * Gizli/spam link enjeksiyonunu (display:none, position:absolute vb.) yakala.
	 */
	protected function gizli_link_iceriyor_mu( $html ) {
		return (bool) preg_match(
			'/<a[^>]+style\s*=\s*["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute|text-indent\s*:\s*-?\d{3,}|font-size\s*:\s*0)/i',
			(string) $html
		);
	}

	/**
	 * Mevcut kullanıcının güvenilir admin olup olmadığı.
	 */
	protected function guvenilir_admin_mi() {
		return current_user_can( 'manage_options' )
			&& in_array( (int) get_current_user_id(), WPGK_User_Guard::guvenilir_adminler(), true );
	}

	/**
	 * Yazı kaydından önce spam/porno/kumar/oyun link enjeksiyonunu denetle.
	 */
	public function yazi_denetle( $data, $postarr ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['icerik_korumasi'] ) ) {
			return $data;
		}

		// Revizyon ve otomatik kayıtları atla.
		$tur = isset( $data['post_type'] ) ? $data['post_type'] : '';
		if ( 'revision' === $tur || ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) ) {
			return $data;
		}

		$icerik   = isset( $data['post_content'] ) ? $data['post_content'] : '';
		$baslik   = isset( $data['post_title'] ) ? $data['post_title'] : '';
		$birlesik = $baslik . ' ' . $icerik;

		$eslesme = '';
		$spam    = $this->spam_iceriyor_mu( $birlesik, $eslesme );
		$link    = $this->link_iceriyor_mu( $icerik );
		$gizli   = $this->gizli_link_iceriyor_mu( $icerik );

		// Engelleme koşulu: spam kelime + bağlantı birlikte, ya da gizli link.
		$engelle = ( $spam && $link ) || $gizli;

		if ( ! $spam && ! $gizli ) {
			return $data; // Temiz.
		}

		// Güvenilir admin: asla engelleme, yalnızca bilgilendir.
		if ( $this->guvenilir_admin_mi() ) {
			WPGK_Logger::kaydet( 'icerik', 'admin_icerik_uyari', 'Yöneticinin içeriğinde şüpheli kalıp: ' . ( $gizli ? 'gizli link' : $eslesme ), 'uyari' );
			return $data;
		}

		if ( $engelle ) {
			$data['post_status'] = 'draft';
			WPGK_Logger::kaydet(
				'icerik',
				'spam_enjeksiyon_engellendi',
				sprintf( 'Şüpheli içerik taslağa alındı ("%s"). Kalıp: %s', $baslik, $gizli ? 'gizli link' : $eslesme ),
				'kritik'
			);
		} else {
			// Link yok, sadece kelime: engelleme, kaydet.
			WPGK_Logger::kaydet( 'icerik', 'icerik_kelime_uyari', 'İçerikte spam anahtar kelimesi (link yok): ' . $eslesme, 'uyari' );
		}

		return $data;
	}

	/**
	 * Yorumlarda spam/porno/kumar link engelleme.
	 */
	public function yorum_denetle( $commentdata ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['icerik_korumasi'] ) ) {
			return $commentdata;
		}

		// Güvenilir admin yorumlarına dokunma.
		if ( $this->guvenilir_admin_mi() ) {
			return $commentdata;
		}

		$icerik = isset( $commentdata['comment_content'] ) ? $commentdata['comment_content'] : '';
		$yazar  = isset( $commentdata['comment_author_url'] ) ? $commentdata['comment_author_url'] : '';

		$eslesme = '';
		$spam    = $this->spam_iceriyor_mu( $icerik . ' ' . $yazar, $eslesme );
		$link    = $this->link_iceriyor_mu( $icerik ) || ( '' !== trim( (string) $yazar ) );
		$gizli   = $this->gizli_link_iceriyor_mu( $icerik );

		if ( ( $spam && $link ) || $gizli ) {
			WPGK_Logger::kaydet( 'icerik', 'spam_yorum_engellendi', 'Spam yorum engellendi. Kalıp: ' . ( $gizli ? 'gizli link' : $eslesme ), 'uyari' );
			wp_die(
				esc_html__( 'Yorumunuz güvenlik filtresine takıldı.', 'ck-radar-security' ),
				esc_html__( 'Engellendi', 'ck-radar-security' ),
				array( 'response' => 403 )
			);
		}

		return $commentdata;
	}

	/**
	 * Site başlığı/açıklaması gibi seçeneklere spam enjeksiyonunu engelle.
	 */
	public function secenek_denetle( $yeni, $eski ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['icerik_korumasi'] ) ) {
			return $yeni;
		}

		// Güvenilir admin değişikliklerine izin ver.
		if ( $this->guvenilir_admin_mi() ) {
			return $yeni;
		}

		$eslesme = '';
		if ( $this->spam_iceriyor_mu( $yeni, $eslesme ) ) {
			WPGK_Logger::kaydet( 'icerik', 'secenek_spam_engellendi', 'Seçenek değişikliği reddedildi. Kalıp: ' . $eslesme, 'kritik' );
			return $eski; // Eski değeri koru.
		}
		return $yeni;
	}

	/**
	 * Yayınlanmış içerikte gizli/spam linklerini tara (sızma sonrası tespit).
	 */
	public function gizli_link_tara() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['icerik_korumasi'] ) ) {
			return;
		}

		$yazilar = get_posts( array(
			'post_type'      => array( 'post', 'page' ),
			'post_status'    => 'publish',
			'posts_per_page' => 200,
			'orderby'        => 'modified',
			'order'          => 'DESC',
		) );

		foreach ( $yazilar as $yazi ) {
			$eslesme = '';
			$spam    = $this->spam_iceriyor_mu( $yazi->post_content, $eslesme );
			$link    = $this->link_iceriyor_mu( $yazi->post_content );
			$gizli   = $this->gizli_link_iceriyor_mu( $yazi->post_content );

			if ( ( $spam && $link ) || $gizli ) {
				WPGK_Logger::kaydet(
					'icerik',
					'yayinda_spam_tespit',
					sprintf( 'Yayındaki içerikte spam link tespit edildi: "%s" (ID %d). Kalıp: %s', $yazi->post_title, $yazi->ID, $gizli ? 'gizli link' : $eslesme ),
					'kritik'
				);
			}
		}
	}
}
