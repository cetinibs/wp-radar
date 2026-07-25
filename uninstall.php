<?php
/**
 * Eklenti kaldırıldığında çalışır: tüm veri ve ayarları temizler.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

/**
 * Tek bir site için eklentiye ait tüm verileri siler.
 */
function wpgk_kaldir_site_verisi() {
	global $wpdb;

	delete_option( 'wpgk_ayarlar' );
	delete_option( 'wpgk_guvenilir_adminler' );
	delete_option( 'wpgk_dosya_baseline' );
	delete_option( 'wpgk_son_tarama' );
	delete_option( 'wpgk_surum' );

	foreach ( array( 'wpgk_olaylar', 'wpgk_sayaclar' ) as $ad ) {
		$tablo = $wpdb->prefix . $ad;
		$wpdb->query( "DROP TABLE IF EXISTS {$tablo}" );
	}
}

if ( is_multisite() ) {
	$site_idler = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );
	foreach ( (array) $site_idler as $site_id ) {
		switch_to_blog( $site_id );
		wpgk_kaldir_site_verisi();
		restore_current_blog();
	}
} else {
	wpgk_kaldir_site_verisi();
}

// 2FA kullanıcı verilerini (gizli anahtar dahil) tüm kullanıcılardan sil.
// TOTP gizli anahtarları eklenti kaldırıldıktan sonra veritabanında kalmamalıdır.
foreach ( array( 'wpgk_2fa_secret', 'wpgk_2fa_aktif', 'wpgk_2fa_son_adim' ) as $meta ) {
	delete_metadata( 'user', 0, $meta, '', true );
}

// Geçici verileri temizle (kilitler, engeller, sayaçlar, 2FA mesajları).
delete_transient( 'wpgk_kok_tara_kilit' );
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\_transient\_wpgk\_%'
	    OR option_name LIKE '\_transient\_timeout\_wpgk\_%'"
);

// Zamanlanmış görevleri temizle.
foreach ( array( 'wpgk_gunluk_tarama', 'wpgk_saatlik_tarama' ) as $kanca ) {
	$zaman = wp_next_scheduled( $kanca );
	if ( $zaman ) {
		wp_unschedule_event( $zaman, $kanca );
	}
}
