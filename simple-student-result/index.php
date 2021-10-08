<?php
 /*
Plugin Name: Student Result or Employee Database
Plugin URI: https://wordpress.org/plugins/simple-student-result/
Description: Ajax supported simple student result input and display. And Employee database system ,  apply [ssr_results] shortcode in a post/page for show results  , <a href="http://ssr.saadamin.com" target="_blank">Click here for demo</a>
Author: Saad Amin
Version: 1.7.2
Author URI: http://www.saadamin.com
License: GPL2
*/
define('SSR_ROOT_FILE', __FILE__);
define('SSR_ROOT_PATH', dirname(__FILE__));
define('SSR_TABLE', 'ssr_studentinfo');
define('SSR_VERSION', '1.7.2');
define('SSR_VERSION_B', '172');
define( 'SSR_REQUIRED_WP_VERSION', '4.9' );
define( 'SSR_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'SSR_PLUGIN_NAME', 'Student Result or Employee Database' );
define( 'SSR_PLUGIN_DIR', untrailingslashit( dirname( __FILE__ ) ) );
define( 'SSR_PLUGIN_URL', untrailingslashit( plugins_url( '', __FILE__ ) ) );
	// Back-end only
	if(is_admin()) {
		include SSR_ROOT_PATH.'/activation.php';
		include SSR_ROOT_PATH.'/menus.php';
		include SSR_ROOT_PATH.'/functions.php';
	}
	include SSR_ROOT_PATH.'/ad_scripts.php';
	include SSR_ROOT_PATH.'/views/ssr_shortcode.php';
	if (!function_exists('SSR_plugin_path')) {
			function SSR_plugin_path( $path = '' ) {
		return path_join( SSR_PLUGIN_DIR, trim( $path, '/' ) );
		}
	}
if (!function_exists('SSR_plugin_url')) {
	function SSR_plugin_url( $path = '' ) {
		$url = untrailingslashit( SSR_PLUGIN_URL );
		if ( ! empty( $path ) && is_string( $path ) && false === strpos( $path, '..' ) )
			$url .= '/' . ltrim( $path, '/' );
		return $url;
	}
}
//Provide a Shortcut to Your Settings Page with Plugin Action Links
add_filter('plugin_action_links', 'ssr_plugin_action_links', 10, 2);
if (!function_exists('ssr_plugin_action_links')) {
	function ssr_plugin_action_links($links, $file) {
		static $this_plugin;
		if (!$this_plugin) {
			$this_plugin = plugin_basename(__FILE__);
		}
		if ($file == $this_plugin) {
			$settings_link = '<a href="' . get_bloginfo('wpurl') . '/wp-admin/admin.php?page=ssr_settings">Settings</a>';
			array_unshift($links, $settings_link);
		}
		return $links;
	}
}
//Rest API
add_action( 'rest_api_init', function () {
	register_rest_route( 'v2', '/ssr_find_all/', array(
		'methods' => WP_REST_Server::ALLMETHODS,
		'callback' => 'ssr_api_ssr_find_all',
        'permission_callback' => function(){return true;},
	) );
} );
function ssr_api_ssr_find_all( $request_data ) {
	// if ( !is_user_logged_in() ) {return array( 'success' => false,'message' => 'Authentication ERROR','code' => 404 );}
	$parameters = $request_data->get_params();
	
	if( !isset( $parameters['postID'] ) || empty( $parameters['postID'] )  || strlen($parameters['postID']) == 0) return array( 'success' => false,'message' => 'registration id not found','code' => 404 );
	
	global $wpdb;
	$student_count =$wpdb->get_var($wpdb->prepare( "SELECT COUNT(*) FROM ".$wpdb->prefix.SSR_TABLE." where rid=%s", $parameters['postID'] ));
	if( intval($student_count) > 0 ){
		$sql="SELECT * FROM ".$wpdb->prefix.SSR_TABLE." Where rid = %s";
		$p = $wpdb->get_results($wpdb->prepare($sql,$parameters['postID']));
		return $p ? array( 'success' => true , 0 => $p[0],'code' => 101 ) : array( 'success' => false , 'message' => 'No data','code' => 405 );
	}
	return  array( 'success' => false , 'message' => 'No data','code' => 402 );

}
?>