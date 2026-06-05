<?php
/**
 * Eklenti kaldırıldığında çalışır: tüm veri ve ayarları temizler.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Seçenekleri sil.
delete_option( 'wpgk_ayarlar' );
delete_option( 'wpgk_guvenilir_adminler' );
delete_option( 'wpgk_dosya_baseline' );

// Multisite kurulumlarda site bazlı seçenekleri de temizle.
if ( is_multisite() ) {
	$site_idler = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );
	foreach ( (array) $site_idler as $site_id ) {
		switch_to_blog( $site_id );
		delete_option( 'wpgk_ayarlar' );
		delete_option( 'wpgk_guvenilir_adminler' );
		delete_option( 'wpgk_dosya_baseline' );
		$tablo = $wpdb->prefix . 'wpgk_olaylar';
		$wpdb->query( "DROP TABLE IF EXISTS {$tablo}" );
		restore_current_blog();
	}
} else {
	$tablo = $wpdb->prefix . 'wpgk_olaylar';
	$wpdb->query( "DROP TABLE IF EXISTS {$tablo}" );
}

// Geçici verileri temizle.
delete_transient( 'wpgk_kok_tara_kilit' );

// Zamanlanmış görevleri temizle.
foreach ( array( 'wpgk_gunluk_tarama', 'wpgk_saatlik_tarama' ) as $kanca ) {
	$zaman = wp_next_scheduled( $kanca );
	if ( $zaman ) {
		wp_unschedule_event( $zaman, $kanca );
	}
}
