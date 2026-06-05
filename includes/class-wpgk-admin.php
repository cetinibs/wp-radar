<?php
/**
 * Yönetim paneli: ayarlar, güvenilir admin yönetimi ve olay günlüğü görünümü.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Admin {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'menu_ekle' ) );
		add_action( 'admin_init', array( $this, 'ayarlari_kaydet' ) );
		add_action( 'admin_init', array( $this, 'taramayi_calistir' ) );
		add_action( 'admin_init', array( $this, 'test_eposta_gonder' ) );
		add_action( 'admin_notices', array( $this, 'kritik_uyari_goster' ) );
		add_action( 'admin_notices', array( $this, 'tarama_sonucu_goster' ) );
		add_action( 'admin_notices', array( $this, 'test_eposta_sonucu_goster' ) );
	}

	/**
	 * Birden çok e-posta adresini (virgül/satır ayrımlı) doğrulayıp normalize eder.
	 */
	protected static function epostalari_temizle( $ham ) {
		$temiz = array();
		foreach ( preg_split( '/[\r\n,;]+/', (string) $ham ) as $e ) {
			$e = sanitize_email( trim( $e ) );
			if ( $e && is_email( $e ) ) {
				$temiz[] = $e;
			}
		}
		$temiz = array_values( array_unique( $temiz ) );
		return empty( $temiz ) ? get_option( 'admin_email' ) : implode( "\n", $temiz );
	}

	/**
	 * "Test e-postası gönder" butonu: kayıtlı alıcılara test bildirimi yollar.
	 */
	public function test_eposta_gonder() {
		if ( ! isset( $_POST['wpgk_test_mail_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_test_mail_nonce'] ) ), 'wpgk_test_mail' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$ok = WPGK_Logger::test_bildirimi_gonder();
		set_transient( 'wpgk_test_mail_sonuc', $ok ? 'ok' : 'hata', 30 );
		wp_safe_redirect( admin_url( 'admin.php?page=wpgk-panel&wpgk_test_mail=1' ) );
		exit;
	}

	/**
	 * Test e-postası sonucunu bildirim olarak göster.
	 */
	public function test_eposta_sonucu_goster() {
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['wpgk_test_mail'] ) ) {
			return;
		}
		$sonuc = get_transient( 'wpgk_test_mail_sonuc' );
		if ( ! $sonuc ) {
			return;
		}
		if ( 'ok' === $sonuc ) {
			echo '<div class="notice notice-success is-dismissible"><p><strong>Test e-postası gönderildi.</strong> Gelen kutunuzu (ve spam klasörünü) kontrol edin. E-posta gelmediyse Hostinger\'da SMTP eklentisi yapılandırmanız gerekebilir.</p></div>';
		} else {
			echo '<div class="notice notice-error is-dismissible"><p><strong>Test e-postası gönderilemedi.</strong> Geçerli bir alıcı adresi girip kaydettiğinizden emin olun; sorun sürerse bir SMTP eklentisi kurun.</p></div>';
		}
	}

	/**
	 * "Şimdi Tara" butonu: tüm tarayıcıları senkron çalıştırır.
	 */
	public function taramayi_calistir() {
		if ( ! isset( $_POST['wpgk_tara_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_tara_nonce'] ) ), 'wpgk_tarama' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		@set_time_limit( 0 );

		// 1) ÖNCE TARA: kök klasör analizi (bulguları döndürür).
		$kok_bulgular = WPGK_File_Guard::kok_klasor_tara();

		// 2) Diğer tarayıcıları çalıştır (uploads shell, bütünlük, yapı, sahte admin, içerik).
		do_action( 'wpgk_gunluk_tarama' );

		$silinen = 0;
		$tespit  = 0;
		foreach ( (array) $kok_bulgular as $b ) {
			if ( 'silindi' === $b['durum'] ) {
				$silinen++;
			} elseif ( 'tespit' === $b['durum'] || 'supheli' === $b['durum'] ) {
				$tespit++;
			}
		}

		set_transient(
			'wpgk_tarama_sonuc',
			array( 'silinen' => $silinen, 'tespit' => $tespit, 'zaman' => current_time( 'mysql' ) ),
			60
		);

		wp_safe_redirect( admin_url( 'admin.php?page=wpgk-panel&wpgk_tarandi=1' ) );
		exit;
	}

	/**
	 * Tarama sonucunu bildirim olarak göster.
	 */
	public function tarama_sonucu_goster() {
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['wpgk_tarandi'] ) ) {
			return;
		}
		$sonuc = get_transient( 'wpgk_tarama_sonuc' );
		if ( ! $sonuc ) {
			return;
		}
		printf(
			'<div class="notice notice-info is-dismissible"><p><strong>Tarama tamamlandı.</strong> Silinen zararlı kök klasör: %d, incelenmesi gereken bulgu: %d. Ayrıntılar için <a href="%s">Olay Günlüğü</a>.</p></div>',
			(int) $sonuc['silinen'],
			(int) $sonuc['tespit'],
			esc_url( admin_url( 'admin.php?page=wpgk-gunluk' ) )
		);
	}

	public function menu_ekle() {
		add_menu_page(
			'WP Radar',
			'WP Radar',
			'manage_options',
			'wpgk-panel',
			array( $this, 'panel_render' ),
			'dashicons-shield',
			80
		);
		add_submenu_page( 'wpgk-panel', 'Olay Günlüğü', 'Olay Günlüğü', 'manage_options', 'wpgk-gunluk', array( $this, 'gunluk_render' ) );
	}

	/**
	 * Ayar formunu işle.
	 */
	public function ayarlari_kaydet() {
		if ( ! isset( $_POST['wpgk_ayar_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpgk_ayar_nonce'] ) ), 'wpgk_ayar_kaydet' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$ayarlar = array(
			'kullanici_korumasi'    => isset( $_POST['kullanici_korumasi'] ) ? 1 : 0,
			'dosya_korumasi'        => isset( $_POST['dosya_korumasi'] ) ? 1 : 0,
			'icerik_korumasi'       => isset( $_POST['icerik_korumasi'] ) ? 1 : 0,
			'exploit_korumasi'      => isset( $_POST['exploit_korumasi'] ) ? 1 : 0,
			'dosya_duzenleme_kapat' => isset( $_POST['dosya_duzenleme_kapat'] ) ? 1 : 0,
			'xmlrpc_kapat'          => isset( $_POST['xmlrpc_kapat'] ) ? 1 : 0,
			'xmlrpc_tam_engel'      => isset( $_POST['xmlrpc_tam_engel'] ) ? 1 : 0,
			'pingback_kapat'        => isset( $_POST['pingback_kapat'] ) ? 1 : 0,
			'sitemap_kullanici_gizle' => isset( $_POST['sitemap_kullanici_gizle'] ) ? 1 : 0,
			'kok_klasor_korumasi'   => isset( $_POST['kok_klasor_korumasi'] ) ? 1 : 0,
			'kok_klasor_otomatik_sil' => isset( $_POST['kok_klasor_otomatik_sil'] ) ? 1 : 0,
			'kok_izinli'            => isset( $_POST['kok_izinli'] ) ? sanitize_textarea_field( wp_unslash( $_POST['kok_izinli'] ) ) : '',
			'yapi_korumasi'         => isset( $_POST['yapi_korumasi'] ) ? 1 : 0,
			'cekirdek_butunluk'     => isset( $_POST['cekirdek_butunluk'] ) ? 1 : 0,
			'link_korumasi'         => isset( $_POST['link_korumasi'] ) ? 1 : 0,
			'zararli_domainler'     => isset( $_POST['zararli_domainler'] ) ? sanitize_textarea_field( wp_unslash( $_POST['zararli_domainler'] ) ) : '',
			// Giriş / brute-force
			'giris_korumasi'        => isset( $_POST['giris_korumasi'] ) ? 1 : 0,
			'giris_jenerik_hata'    => isset( $_POST['giris_jenerik_hata'] ) ? 1 : 0,
			'giris_max_deneme'      => isset( $_POST['giris_max_deneme'] ) ? max( 1, min( 50, (int) $_POST['giris_max_deneme'] ) ) : 5,
			'giris_kilit_dk'        => isset( $_POST['giris_kilit_dk'] ) ? max( 1, min( 1440, (int) $_POST['giris_kilit_dk'] ) ) : 15,
			// Sertleştirme
			'guvenlik_basliklari'   => isset( $_POST['guvenlik_basliklari'] ) ? 1 : 0,
			'hsts'                  => isset( $_POST['hsts'] ) ? 1 : 0,
			'hsts_preload'          => isset( $_POST['hsts_preload'] ) ? 1 : 0,
			'surum_gizle'           => isset( $_POST['surum_gizle'] ) ? 1 : 0,
			'dizin_listeleme_kapat' => isset( $_POST['dizin_listeleme_kapat'] ) ? 1 : 0,
			'hassas_dosya_koru'     => isset( $_POST['hassas_dosya_koru'] ) ? 1 : 0,
			'kotu_bot_engelle'      => isset( $_POST['kotu_bot_engelle'] ) ? 1 : 0,
			'eposta_bildirimi'      => isset( $_POST['eposta_bildirimi'] ) ? 1 : 0,
			'bildirim_eposta'       => isset( $_POST['bildirim_eposta'] ) ? self::epostalari_temizle( wp_unslash( $_POST['bildirim_eposta'] ) ) : get_option( 'admin_email' ),
			'bildirim_throttle_dk'  => isset( $_POST['bildirim_throttle_dk'] ) ? max( 0, min( 1440, (int) $_POST['bildirim_throttle_dk'] ) ) : 60,
		);
		update_option( 'wpgk_ayarlar', $ayarlar );

		// Sertleştirme ayarları .htaccess'i etkilediği için yeniden yaz.
		WPGK_Hardening::htaccess_yaz();

		// Güvenilir admin listesini yeniden senkronla isteği.
		if ( isset( $_POST['wpgk_admin_senkron'] ) ) {
			$adminler = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) );
			update_option( 'wpgk_guvenilir_adminler', array_map( 'intval', wp_list_pluck( $adminler, 'ID' ) ) );
		}

		add_settings_error( 'wpgk', 'kaydedildi', 'Ayarlar kaydedildi.', 'updated' );
	}

	public function panel_render() {
		$ayarlar = get_option( 'wpgk_ayarlar', array() );
		settings_errors( 'wpgk' );

		$secenekler = array(
			'kullanici_korumasi'    => 'Kullanıcı koruması (yetkisiz admin oluşturma/rol yükseltme engelle)',
			'dosya_korumasi'        => 'Dosya koruması (root/uploads içine shell & PHP yazımını engelle)',
			'icerik_korumasi'       => 'İçerik koruması (porno/kumar/oyun spam linklerini engelle)',
			'exploit_korumasi'      => 'Exploit koruması (zafiyetli istek ve sızma denemelerini engelle)',
			'kotu_bot_engelle'      => 'Kötü bot / tarama aracı engelleme (sqlmap, nikto, wpscan vb.)',
			'giris_korumasi'        => 'Giriş koruması (brute-force / IP bazlı kilitleme)',
			'giris_jenerik_hata'    => 'Jenerik giriş hatası (kullanıcı adı sızdırmaz)',
			'guvenlik_basliklari'   => 'Güvenlik HTTP başlıkları (clickjacking/MIME-sniffing koruması)',
			'hsts'                  => 'HSTS başlığı (yalnızca tam HTTPS sitelerde açın)',
			'hsts_preload'          => 'HSTS preload (yalnızca tüm alt alan adları HTTPS ise; geri alması zordur)',
			'surum_gizle'           => 'WordPress sürümünü gizle (bilgi ifşasını azaltır)',
			'dizin_listeleme_kapat' => 'Dizin listelemeyi kapat (.htaccess)',
			'hassas_dosya_koru'     => 'Hassas dosyaları koru (wp-config, .htaccess, debug.log …)',
			'dosya_duzenleme_kapat' => 'Panel içi dosya düzenleyiciyi kapat (DISALLOW_FILE_EDIT)',
			'xmlrpc_kapat'          => 'XML-RPC arayüzünü kapat (brute-force/pingback istismarını azaltır)',
			'xmlrpc_tam_engel'      => 'XML-RPC tam engel (xmlrpc.php\'yi 403 ile tamamen kapat; Jetpack/mobil uygulama kullanıyorsanız kapalı tutun)',
			'pingback_kapat'        => 'Pingback & X-Pingback kaldır (pingback.ping / system.multicall DDoS-SSRF amplifikasyonunu engeller)',
			'sitemap_kullanici_gizle' => 'XML sitemap kullanıcı listesini gizle (/wp-sitemap-users-1.xml ile kullanıcı adı sızıntısını engeller)',
			'kok_klasor_korumasi'   => 'Kök klasör koruması (izinsiz klasör/SEO spam doorway tespiti)',
			'kok_klasor_otomatik_sil' => 'Zararlı kök klasörleri otomatik sil (önce tarar, kanıt bulursa siler)',
			'yapi_korumasi'         => 'WordPress klasör yapısı koruması (çekirdek dizin bütünlüğü)',
			'cekirdek_butunluk'     => 'Çekirdek dosya bütünlüğü (WordPress.org checksums ile doğrula)',
			'link_korumasi'         => 'Zararlı link koruması (ön yüzde spam linklerini otomatik temizle)',
			'eposta_bildirimi'      => 'Kritik olaylarda e-posta bildirimi gönder',
		);
		?>
		<div class="wrap">
			<h1>WP Radar</h1>
			<p>Kapsamlı WordPress güvenlik radarı: brute-force, sızma, zararlı dosya/klasör ve spam link koruması.</p>

			<form method="post" style="margin-bottom:16px;">
				<?php wp_nonce_field( 'wpgk_tarama', 'wpgk_tara_nonce' ); ?>
				<?php submit_button( 'Şimdi Tara', 'primary', 'wpgk_tara_simdi', false ); ?>
				<span class="description" style="margin-left:8px;">Önce tarar, ardından kanıtlı zararlıları engeller.</span>
			</form>

			<form method="post">
				<?php wp_nonce_field( 'wpgk_ayar_kaydet', 'wpgk_ayar_nonce' ); ?>
				<table class="form-table">
					<?php foreach ( $secenekler as $anahtar => $etiket ) : ?>
						<tr>
							<th scope="row"><?php echo esc_html( $etiket ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( $anahtar ); ?>" value="1" <?php checked( ! empty( $ayarlar[ $anahtar ] ) ); ?> />
									Etkin
								</label>
							</td>
						</tr>
					<?php endforeach; ?>
					<tr>
						<th scope="row">Giriş kilidi eşiği</th>
						<td>
							<input type="number" name="giris_max_deneme" min="1" max="50" value="<?php echo esc_attr( isset( $ayarlar['giris_max_deneme'] ) ? $ayarlar['giris_max_deneme'] : 5 ); ?>" class="small-text" /> başarısız denemeden sonra
							<input type="number" name="giris_kilit_dk" min="1" max="1440" value="<?php echo esc_attr( isset( $ayarlar['giris_kilit_dk'] ) ? $ayarlar['giris_kilit_dk'] : 15 ); ?>" class="small-text" /> dakika kilitle.
						</td>
					</tr>
					<tr>
						<th scope="row">İzinli kök klasörler</th>
						<td>
							<textarea name="kok_izinli" rows="3" class="large-text" placeholder="Her satıra bir klasör adı (ör. shop, blog)"><?php echo esc_textarea( isset( $ayarlar['kok_izinli'] ) ? $ayarlar['kok_izinli'] : '' ); ?></textarea>
							<p class="description">wp-admin, wp-content, wp-includes ve sistem klasörleri zaten izinlidir. Kök dizinde meşru özel bir klasörünüz varsa (ör. ayrı bir uygulama), adını buraya ekleyin.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Zararlı domainler (kara liste)</th>
						<td>
							<textarea name="zararli_domainler" rows="3" class="large-text" placeholder="Her satıra bir domain (ör. kotusite.com)"><?php echo esc_textarea( isset( $ayarlar['zararli_domainler'] ) ? $ayarlar['zararli_domainler'] : '' ); ?></textarea>
							<p class="description">Bu domainlere giden bağlantılar ön yüzde otomatik temizlenir (alt alan adları dahil).</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Bildirim e-posta adresleri</th>
						<td>
							<textarea name="bildirim_eposta" rows="3" class="regular-text" placeholder="Her satıra bir e-posta adresi (veya virgülle ayırın)"><?php echo esc_textarea( isset( $ayarlar['bildirim_eposta'] ) ? $ayarlar['bildirim_eposta'] : get_option( 'admin_email' ) ); ?></textarea>
							<p class="description">Kritik güvenlik olaylarında (yetkisiz admin, web shell, çekirdek değişikliği, brute-force vb.) bu adreslere anlık e-posta gönderilir. Birden çok adres ekleyebilirsiniz.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Tekrar-bildirim engeli</th>
						<td>
							Aynı saldırı için
							<input type="number" name="bildirim_throttle_dk" min="0" max="1440" value="<?php echo esc_attr( isset( $ayarlar['bildirim_throttle_dk'] ) ? $ayarlar['bildirim_throttle_dk'] : 60 ); ?>" class="small-text" />
							dakikada bir bildir.
							<p class="description">E-posta yağmurunu önler: bildirimler <strong>olay türü + saldıran IP bloğu (/24)</strong> bazında gruplanır. Aynı IP'den ya da aynı bloktan gelen yüzlerce istek/deneme için yalnızca <strong>tek</strong> e-posta gider; ilk olay anında iletilir, bu süre boyunca tekrarı susturulur. Farklı bir saldırı türü veya farklı bir IP bloğu ayrı bildirim olarak gelir. <strong>0</strong> = her olayda gönder (önerilmez). 1440 = günde bir.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Güvenilir yöneticiler</th>
						<td>
							<?php
							$guvenilir = WPGK_User_Guard::guvenilir_adminler();
							if ( $guvenilir ) {
								$adlar = array();
								foreach ( $guvenilir as $id ) {
									$u = get_userdata( $id );
									if ( $u ) {
										$adlar[] = esc_html( $u->user_login . ' (ID ' . $id . ')' );
									}
								}
								echo wp_kses_post( implode( ', ', $adlar ) );
							} else {
								echo 'Tanımlı değil';
							}
							?>
							<p><label><input type="checkbox" name="wpgk_admin_senkron" value="1" /> Mevcut tüm yöneticileri güvenilir listeyle yeniden senkronla</label></p>
							<p class="description">Dikkat: Senkron, o anda var olan tüm administrator hesaplarını güvenilir kabul eder. Yalnızca hesapların temiz olduğundan eminseniz işaretleyin.</p>
						</td>
					</tr>
				</table>
				<?php submit_button( 'Ayarları Kaydet' ); ?>
			</form>

			<form method="post" style="margin-top:8px;">
				<?php wp_nonce_field( 'wpgk_test_mail', 'wpgk_test_mail_nonce' ); ?>
				<?php submit_button( 'Test E-postası Gönder', 'secondary', 'wpgk_test_mail_gonder', false ); ?>
				<span class="description" style="margin-left:8px;">Kayıtlı alıcılara bir test bildirimi yollar. Önce adresleri kaydedin, sonra test edin.</span>
			</form>
		</div>
		<?php
	}

	public function gunluk_render() {
		$olaylar = WPGK_Logger::son_olaylar( 200 );
		?>
		<div class="wrap">
			<h1>Olay Günlüğü</h1>
			<table class="widefat striped">
				<thead>
					<tr>
						<th>Zaman</th><th>Seviye</th><th>Modül</th><th>Olay</th><th>Mesaj</th><th>IP</th>
					</tr>
				</thead>
				<tbody>
				<?php if ( $olaylar ) : ?>
					<?php foreach ( $olaylar as $o ) : ?>
						<tr>
							<td><?php echo esc_html( $o->zaman ); ?></td>
							<td><?php echo esc_html( $o->seviye ); ?></td>
							<td><?php echo esc_html( $o->modul ); ?></td>
							<td><?php echo esc_html( $o->olay ); ?></td>
							<td><?php echo esc_html( $o->mesaj ); ?></td>
							<td><?php echo esc_html( $o->ip ); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr><td colspan="6">Henüz olay kaydı yok.</td></tr>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * Son 24 saatte kritik olay varsa panelde uyarı göster.
	 */
	public function kritik_uyari_goster() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		global $wpdb;
		$tablo = $wpdb->prefix . WPGK_Logger::TABLO;
		$sayi  = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$tablo} WHERE seviye = %s AND zaman >= %s",
				'kritik',
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
			)
		);
		if ( $sayi > 0 ) {
			printf(
				'<div class="notice notice-error"><p><strong>WP Radar:</strong> Son 24 saatte %d kritik güvenlik olayı tespit edildi. <a href="%s">Olay günlüğünü inceleyin</a>.</p></div>',
				esc_html( $sayi ),
				esc_url( admin_url( 'admin.php?page=wpgk-gunluk' ) )
			);
		}
	}
}
