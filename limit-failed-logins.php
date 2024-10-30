<?php
/*
Plugin Name: Limit Failed Logins
Plugin URI: https://wordpress.org/plugins/limit-failed-logins/
Description: Limit the rate of login attempts for each IP address.
Author: Evincedev
Author URI: https://evincedev.com/
Text Domain: limit-failed-login
Version: 1.0
License: GPL-3.0+
License URI: http://www.gnu.org/licenses/gpl-3.0.txt
*/

/***************************************************************************************
 * Constants
 **************************************************************************************/
define( 'LFL_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'LFL_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'LFL_PLUGIN_FILE', __FILE__ );
define( 'LFL_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/***************************************************************************************
 * Different ways to get remote address: direct & behind proxy
 **************************************************************************************/
define( 'LFL_DIRECT_ADDR', 'REMOTE_ADDR' );
define( 'LFL_PROXY_ADDR', 'HTTP_X_FORWARDED_FOR' );

/* Notify value checked against these in limit_login_sanitize_variables() */
define( 'LFL_LOCKOUT_NOTIFY_ALLOWED', 'log,email' );

$limit_failed_login_my_error_shown = false; /* have we shown our stuff? */
$limit_failed_login_just_lockedout = false; /* started this pageload??? */
$limit_failed_login_nonempty_credentials = false; /* user and pwd nonempty */

/***************************************************************************************
 * Include files
 **************************************************************************************/
require_once( LFL_PLUGIN_DIR . '/lib/CidrCheck.php' );
require_once( LFL_PLUGIN_DIR . '/core/Shortcodes.php' );
require_once( LFL_PLUGIN_DIR . '/core/Helpers.php' );
require_once( LFL_PLUGIN_DIR . '/core/App.php' );
require_once( LFL_PLUGIN_DIR . '/core/LimitFailedlogins.php' );

$limit_failed_login_attempts_obj = new Limit_Failed_Login();