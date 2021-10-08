<?php
// embed the javascript file that makes the AJAX request
// declare the URL to the file that handles the AJAX request (wp-admin/admin-ajax.php)
function ssr_pw_load_scripts() {
wp_enqueue_script( 'my-ajax-request', plugin_dir_url( __FILE__ ) . 'js/ssr_scripts.js', array( 'jquery' ), SSR_VERSION );
wp_localize_script( 'my-ajax-request', 'SSR_Ajax', array( 'ajaxurl' => admin_url( 'admin-ajax.php' ) ) );
}
add_action('wp_enqueue_scripts', 'ssr_pw_load_scripts');
add_action('admin_enqueue_scripts', 'ssr_pw_load_scripts');

// ADMIN SCRIPTS
function ssr_my_add_frontend_scripts() {
        wp_enqueue_script('jquery');
        wp_enqueue_script('jquery-ui-core');
}
add_action('init', 'ssr_my_add_frontend_scripts');
add_action('admin_enqueue_scripts', 'ssr_my_admin_scripts');
 
function ssr_my_admin_scripts() {
	if (isset($_GET['page'])){
		if ($_GET['page'] == 'ssr_add_results' || $_GET['page'] == 'ssr_settings' || $_GET['page'] == 'ssr_all_entires' ) {
			wp_enqueue_media();
			wp_register_script('zebra_dialog_js', SSR_plugin_url( '/js/zebra_dialog.js'), array('jquery'));
			wp_register_script('jquery_ui_shake', SSR_plugin_url( '/js/jquery-ui_shake_pack.min.js'), array('jquery'),'1.11.1');
			wp_enqueue_script('my-admin-js');
			wp_enqueue_script('zebra_dialog_js');
			wp_enqueue_script('jquery_ui_shake');
			//STYLES
			wp_enqueue_style( 'SSR_zebra_dialog_css', SSR_plugin_url( 'css/zebra_dialog.css' ), false, '1.3.8' );
			wp_enqueue_style( 'SSR_admin_css', SSR_plugin_url( 'css/admin-style.css' ), false, SSR_VERSION );
		}
		if ($_GET['page'] == 'SSR') {
			wp_enqueue_style( 'SSR_viewst_css', SSR_plugin_url( 'css/ssr_viewst.css' ), false, SSR_VERSION );
		}
		if ($_GET['page'] == 'ssr_all_entires') {
				wp_register_script('ssr_jquery_ui_column', SSR_plugin_url( '/js/jquery.columns-1.0.min.js'), array('jquery'),'1.11.1');
				wp_enqueue_script('ssr_jquery_ui_column');
		}
		wp_enqueue_style( 'SSR_admin_others_css', SSR_plugin_url( 'css/others.css' ), false, SSR_VERSION );
	}
}
//FRONT END OR VISITORS SCRIPTS
add_action( 'wp_enqueue_scripts', 'ssr_vi_scripts_st' );
function ssr_vi_scripts_st() {
	wp_enqueue_style( 'ssr_v_result_st', SSR_plugin_url( '/css/ssr_style.css'), array(), SSR_VERSION, 'all' );
	do_action( 'ssr_vi_scripts_st' );
	wp_register_script('ssr_front_js', SSR_plugin_url( '/js/ssr_scripts_front.js'), array('jquery'), SSR_VERSION);
    wp_enqueue_script('ssr_front_js');
}

?>