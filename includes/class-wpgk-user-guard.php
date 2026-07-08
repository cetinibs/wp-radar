<?php
/**
 * Kullanıcı koruması: yetkisiz kullanıcı oluşturma ve rol yükseltme engelleme.
 *
 * Eklenti/tema açıklarından kaynaklanan tipik saldırı, saldırgan bir
 * "administrator" hesabı oluşturup kalıcılık sağlamaktır. Bu modül,
 * etkinleştirme anında kaydedilen güvenilir yönetici listesi dışında
 * yeni yönetici oluşturulmasını/atanmasını engeller.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_User_Guard {

	public function __construct() {
		// Yeni kullanıcı oluşturma denetimi (form + programatik).
		add_action( 'user_register', array( $this, 'kayit_sonrasi_denetle' ), 1, 1 );

		// Rol yükseltme / yönetici atama denetimi.
		add_action( 'set_user_role', array( $this, 'rol_degisimi_denetle' ), 1, 3 );
		add_filter( 'can_add_user_to_blog', array( $this, 'blog_ekleme_denetle' ), 1, 4 );

		// Profil güncellemede admin rolüne sızmayı engelle.
		add_action( 'profile_update', array( $this, 'profil_guncelleme_denetle' ), 1, 2 );

		// Günlük: sahte/şüpheli admin tespiti.
		add_action( 'wpgk_gunluk_tarama', array( $this, 'sahte_admin_tara' ) );
	}

	/**
	 * Güvenilir yönetici ID listesi.
	 */
	public static function guvenilir_adminler() {
		$liste = get_option( 'wpgk_guvenilir_adminler', array() );
		return is_array( $liste ) ? array_map( 'intval', $liste ) : array();
	}

	/**
	 * Bir kullanıcının (varsa) rol atamasını okur.
	 */
	protected function roller_administrator_mi( $roller ) {
		if ( empty( $roller ) ) {
			return false;
		}
		$roller = (array) $roller;
		return in_array( 'administrator', $roller, true );
	}

	/**
	 * Yeni kullanıcı kaydında: yönetici rolüyle oluşturulan ve güvenilir
	 * listede olmayan hesapları geri al.
	 */
	public function kayit_sonrasi_denetle( $user_id ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['kullanici_korumasi'] ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		// Yönetici olmayan normal kayıtlara dokunma (ayarlanan açık kayıt vb.).
		if ( ! $this->roller_administrator_mi( $user->roles ) ) {
			return;
		}

		// Güvenilir listede olan bir admin ise (ör. yeniden senkron) izin ver.
		if ( in_array( (int) $user_id, self::guvenilir_adminler(), true ) ) {
			return;
		}

		// Eylemi gerçekleştiren oturum güvenilir bir admin mi?
		if ( $this->mevcut_kullanici_guvenilir_admin() ) {
			// Meşru bir admin yeni admin ekliyorsa: listeye dahil et, izin ver.
			$this->guvenilir_listeye_ekle( $user_id );
			WPGK_Logger::kaydet( 'kullanici', 'yeni_admin_onayli', 'Güvenilir yönetici tarafından yeni admin eklendi: ' . $user->user_login, 'bilgi' );
			return;
		}

		// Aksi halde: yetkisiz admin oluşturma → hesabı kaldır.
		WPGK_Logger::kaydet(
			'kullanici',
			'yetkisiz_admin_olusturma',
			sprintf( 'Yetkisiz yönetici hesabı engellendi ve silindi: %s (ID %d)', $user->user_login, $user_id ),
			'kritik'
		);

		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $user_id );
	}

	/**
	 * Rol değişiminde administrator atamasını denetle.
	 */
	public function rol_degisimi_denetle( $user_id, $role, $old_roles ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['kullanici_korumasi'] ) ) {
			return;
		}

		if ( 'administrator' !== $role ) {
			return;
		}

		// Zaten güvenilir admin ise sorun yok.
		if ( in_array( (int) $user_id, self::guvenilir_adminler(), true ) ) {
			return;
		}

		// Eylemi yapan güvenilir admin ise onayla ve listeye ekle.
		if ( $this->mevcut_kullanici_guvenilir_admin() ) {
			$this->guvenilir_listeye_ekle( $user_id );
			WPGK_Logger::kaydet( 'kullanici', 'rol_yukseltme_onayli', 'Güvenilir admin tarafından admin rolü verildi: ID ' . $user_id, 'bilgi' );
			return;
		}

		// Yetkisiz yükseltme → eski rolüne geri al.
		$user = get_userdata( $user_id );
		if ( $user ) {
			$geri_rol = ! empty( $old_roles ) ? reset( $old_roles ) : 'subscriber';
			// set_user_role içinde döngüye girmemek için doğrudan ata.
			remove_action( 'set_user_role', array( $this, 'rol_degisimi_denetle' ), 1 );
			$user->set_role( $geri_rol );
			add_action( 'set_user_role', array( $this, 'rol_degisimi_denetle' ), 1, 3 );

			WPGK_Logger::kaydet(
				'kullanici',
				'yetkisiz_rol_yukseltme',
				sprintf( 'Yetkisiz yönetici yükseltmesi geri alındı: %s → %s', $user->user_login, $geri_rol ),
				'kritik'
			);
		}
	}

	/**
	 * Multisite blog ekleme sırasında admin atamasını denetle.
	 *
	 * @param bool|WP_Error $can_add Eklenebilir mi.
	 * @param int           $user_id Kullanıcı ID.
	 * @param string        $role    Atanan rol.
	 * @param int           $blog_id Blog ID.
	 */
	public function blog_ekleme_denetle( $can_add, $user_id, $role, $blog_id ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['kullanici_korumasi'] ) ) {
			return $can_add;
		}
		if ( 'administrator' === $role
			&& ! in_array( (int) $user_id, self::guvenilir_adminler(), true )
			&& ! $this->mevcut_kullanici_guvenilir_admin() ) {
			WPGK_Logger::kaydet( 'kullanici', 'yetkisiz_blog_admin', 'Blog admin atama engellendi: ID ' . $user_id, 'kritik' );
			return new WP_Error( 'wpgk_engellendi', 'Yetkisiz yönetici ataması engellendi.' );
		}
		return $can_add;
	}

	/**
	 * Profil güncellemede gizlice admin rolüne geçişi engelle.
	 */
	public function profil_guncelleme_denetle( $user_id, $old_user_data ) {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['kullanici_korumasi'] ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user || ! $this->roller_administrator_mi( $user->roles ) ) {
			return;
		}

		$eski_admin = in_array( 'administrator', (array) $old_user_data->roles, true );
		if ( $eski_admin || in_array( (int) $user_id, self::guvenilir_adminler(), true ) ) {
			return; // Zaten admindi.
		}

		if ( $this->mevcut_kullanici_guvenilir_admin() ) {
			$this->guvenilir_listeye_ekle( $user_id );
			return;
		}

		// Profil güncellemesiyle yeni admin oluşmuş → geri al.
		remove_action( 'profile_update', array( $this, 'profil_guncelleme_denetle' ), 1 );
		$user->set_role( 'subscriber' );
		add_action( 'profile_update', array( $this, 'profil_guncelleme_denetle' ), 1, 2 );

		WPGK_Logger::kaydet( 'kullanici', 'profil_admin_sizma', 'Profil güncellemeyle admin sızması engellendi: ' . $user->user_login, 'kritik' );
	}

	/**
	 * Günlük tarama: güvenilir listede olmayan administrator hesaplarını yakalar.
	 * (Doğrudan SQL ile DB'ye eklenen sahte adminler dahil.)
	 */
	public function sahte_admin_tara() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		if ( empty( $ayarlar['kullanici_korumasi'] ) ) {
			return;
		}

		$adminler  = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login' ) ) );
		$guvenilir = self::guvenilir_adminler();
		$otomatik  = ! empty( $ayarlar['sahte_admin_otomatik'] );

		// Güvenlik kilidi: listede HÂLÂ en az bir güvenilir admin mevcut olmalı ki
		// otomatik düşürme meşru yöneticileri kilitlemesin. Aksi halde yalnızca raporla.
		$mevcut_guvenilir = 0;
		foreach ( $adminler as $a ) {
			if ( in_array( (int) $a->ID, $guvenilir, true ) ) {
				$mevcut_guvenilir++;
			}
		}

		foreach ( $adminler as $admin ) {
			if ( in_array( (int) $admin->ID, $guvenilir, true ) ) {
				continue;
			}

			if ( $otomatik && $mevcut_guvenilir > 0 ) {
				$this->admin_etkisizlestir( (int) $admin->ID );
				WPGK_Logger::kaydet(
					'kullanici',
					'sahte_admin_etkisizlestirildi',
					sprintf( 'Yetkisiz yönetici etkisizleştirildi (subscriber\'a düşürüldü + tüm oturumları sonlandırıldı): %s (ID %d).', $admin->user_login, $admin->ID ),
					'kritik'
				);
			} else {
				WPGK_Logger::kaydet(
					'kullanici',
					'tespit_sahte_admin',
					sprintf( 'Güvenilir listede olmayan yönetici tespit edildi: %s (ID %d). Lütfen inceleyin.', $admin->user_login, $admin->ID ),
					'kritik'
				);
			}
		}
	}

	/**
	 * Bir kullanıcıyı etkisizleştirir: rolünü subscriber'a düşürür ve tüm oturum
	 * jetonlarını yok eder; böylece saldırganın açık oturumu anında geçersiz olur.
	 */
	protected function admin_etkisizlestir( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		// 'subscriber' administrator olmadığından set_user_role kancasında döngü oluşmaz.
		$user->set_role( 'subscriber' );
		if ( class_exists( 'WP_Session_Tokens' ) ) {
			$oturumlar = WP_Session_Tokens::get_instance( $user_id );
			if ( $oturumlar ) {
				$oturumlar->destroy_all();
			}
		}
	}

	/**
	 * Eylemi yapan kişinin güvenilir bir admin oturumu mu olduğunu kontrol et.
	 */
	protected function mevcut_kullanici_guvenilir_admin() {
		// WP-CLI bağlamı shell erişimi gerektirir; güvenilir kabul edilir.
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		$cur = get_current_user_id();
		if ( ! $cur ) {
			return false;
		}
		return in_array( (int) $cur, self::guvenilir_adminler(), true )
			&& user_can( $cur, 'manage_options' );
	}

	/**
	 * Güvenilir admin listesine bir kullanıcı ekle.
	 */
	protected function guvenilir_listeye_ekle( $user_id ) {
		$liste = self::guvenilir_adminler();
		if ( ! in_array( (int) $user_id, $liste, true ) ) {
			$liste[] = (int) $user_id;
			update_option( 'wpgk_guvenilir_adminler', $liste );
		}
	}
}
