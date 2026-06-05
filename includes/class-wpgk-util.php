<?php
/**
 * Yardımcı fonksiyonlar.
 *
 * mbstring eklentisi her sunucuda bulunmayabilir; bu sınıf varsa mb_*
 * fonksiyonlarını, yoksa ASCII karşılıklarını kullanarak her PHP
 * sürümünde/ortamında çalışacak güvenli sarmalayıcılar sağlar.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPGK_Util {

	/** mbstring kullanılabilir mi? (bir kez hesaplanır) */
	protected static $mb = null;

	protected static function mb_var() {
		if ( null === self::$mb ) {
			self::$mb = function_exists( 'mb_strtolower' )
				&& function_exists( 'mb_strpos' )
				&& function_exists( 'mb_substr' );
		}
		return self::$mb;
	}

	/**
	 * Güvenli küçük harfe çevirme.
	 */
	public static function kucuk_harf( $metin ) {
		$metin = (string) $metin;
		if ( self::mb_var() ) {
			return mb_strtolower( $metin, 'UTF-8' );
		}
		return strtolower( $metin );
	}

	/**
	 * $samanlik içinde $igne geçiyor mu? (büyük/küçük harf duyarsız değil;
	 * çağıran taraf gerekiyorsa kucuk_harf ile normalize eder)
	 */
	public static function icerir( $samanlik, $igne ) {
		$samanlik = (string) $samanlik;
		$igne     = (string) $igne;
		if ( '' === $igne ) {
			return false;
		}
		if ( self::mb_var() ) {
			return false !== mb_strpos( $samanlik, $igne );
		}
		return false !== strpos( $samanlik, $igne );
	}

	/**
	 * Güvenli alt dize.
	 */
	public static function kes( $metin, $baslangic, $uzunluk = null ) {
		$metin = (string) $metin;
		if ( self::mb_var() ) {
			return mb_substr( $metin, $baslangic, $uzunluk, 'UTF-8' );
		}
		return null === $uzunluk ? substr( $metin, $baslangic ) : substr( $metin, $baslangic, $uzunluk );
	}
}
