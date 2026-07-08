<?php
/**
 * Çekirdek bootstrap: tüm koruma modüllerini başlatır.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPGK_Plugin {

	protected static $instance = null;

	public $user_guard;
	public $file_guard;
	public $content_guard;
	public $exploit_guard;
	public $login_guard;
	public $login_security;
	public $rate_limit;
	public $vuln_scan;
	public $hardening;
	public $admin;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->user_guard    = new WPGK_User_Guard();
		$this->file_guard    = new WPGK_File_Guard();
		$this->content_guard = new WPGK_Content_Guard();
		$this->exploit_guard  = new WPGK_Exploit_Guard();
		$this->login_guard    = new WPGK_Login_Guard();
		$this->login_security = new WPGK_Login_Security();
		$this->rate_limit     = new WPGK_Rate_Limit();
		$this->vuln_scan      = new WPGK_Vuln_Scan();
		$this->hardening      = new WPGK_Hardening();

		if ( is_admin() ) {
			$this->admin = new WPGK_Admin();
		}

		// Günlük bakım: log tablosunu buda.
		add_action( 'wpgk_gunluk_tarama', array( 'WPGK_Logger', 'buda' ) );

		load_plugin_textdomain( 'ck-radar-security', false, dirname( WPGK_BASENAME ) . '/languages' );
	}

	private function __clone() {}
	public function __wakeup() {}
}
