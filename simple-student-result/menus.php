<?php
register_post_type( 'ssr_subjects',
    array(
            'labels' => array(
                    'name' => __( esc_attr( get_option('ssr_settings_ssr_item8') ) ),
                    'singular_name' => __( esc_attr( get_option('ssr_settings_ssr_item8') ) )
            ),
    'public' => true,
	'rewrite' => false,
    'has_archive' => true,
    'show_in_menu' => 'ssr_add_subs'
    )
);
register_post_type( 'ssr_cgpa',
    array(
            'labels' => array(
                    'name' => __( esc_attr( get_option('ssr_settings_ssr_item7') ) ),
                    'singular_name' => __( esc_attr( get_option('ssr_settings_ssr_item7') ) )
            ),
    'public' => true,
	'rewrite' => false,
    'has_archive' => true,
    'show_in_menu' => 'ssr_add_subs'
    )
);
// Register "New" admin menu bar menu
add_action('admin_bar_menu', 'ssr_admin_bar', 999 );
function ssr_admin_bar($wp_admin_bar) {
	$wp_admin_bar->add_node(array(
		'id'    => 'ab-ssr-add-new',
		'title' => 'Simple Student Results',
		'href'  => admin_url('admin.php?page=SSR')
	));
	$wp_admin_bar->add_node(array(
		'parent' => 'ab-ssr-add-new',
		'id'    => 'ab-ssr-add-results',
		'title' => 'Add Student Results',
		'href'  => admin_url('admin.php?page=ssr_add_results')
	));
	$wp_admin_bar->add_node(array(
		'parent' => 'ab-ssr-add-new',
		'id'    => 'ab-ssr-subject',
		'title' => 'View '.esc_attr( get_option('ssr_settings_ssr_item8') ),
		'href'  => admin_url('edit.php?post_type=ssr_subjects')
	));
	$wp_admin_bar->add_node(array(
		'parent' => 'ab-ssr-add-new',
		'id'    => 'ab-ssr-subject-add',
		'title' => 'Add '.esc_attr( get_option('ssr_settings_ssr_item8') ),
		'href'  => admin_url('post-new.php?post_type=ssr_subjects')
	));
	$wp_admin_bar->add_node(array(
		'parent' => 'ab-ssr-add-new',
		'id'    => 'ab-ssr-cgpa',
		'title' => 'View '.esc_attr( get_option('ssr_settings_ssr_item7') ),
		'href'  => admin_url('edit.php?post_type=ssr_cgpa')
	));
	$wp_admin_bar->add_node(array(
		'parent' => 'ab-ssr-add-new',
		'id'    => 'ab-ssr-cgpa-add',
		'title' => 'Add '.esc_attr( get_option('ssr_settings_ssr_item7') ),
		'href'  => admin_url('post-new.php?post_type=ssr_cgpa')
	));
}
//Add Menu
add_action( 'admin_menu', 'ssr_register_custom_menu_page' );
function ssr_register_custom_menu_page(){
	// Menu hook
	global $ssr_hook;
    // Add main page
	$ssr_hook = add_menu_page( esc_attr( get_option('ssr_settings_ssr_item5') ), esc_attr( get_option('ssr_settings_ssr_item5') ), 'publish_pages', 'SSR', 'ssr_router', SSR_plugin_url( 'img/ssr_logo.png'), 6 );
	add_submenu_page('SSR', 'All_Entries', 'All '.esc_attr( get_option('ssr_settings_ssr_item4') ), 'publish_pages', 'ssr_all_entires', 'ssr_router');
	add_submenu_page('SSR', 'Add Student Results', 'Add/Edit '.esc_attr( get_option('ssr_settings_ssr_item4') ), 'publish_pages', 'ssr_add_results', 'ssr_router');
    add_submenu_page('SSR', 'View '.esc_attr( get_option('ssr_settings_ssr_item7') ), 'View '.esc_attr( get_option('ssr_settings_ssr_item7') ), 'publish_pages', 'edit.php?post_type=ssr_cgpa');
    add_submenu_page('SSR', 'Add '.esc_attr( get_option('ssr_settings_ssr_item7') ), 'Add '.esc_attr( get_option('ssr_settings_ssr_item7') ), 'publish_pages', 'post-new.php?post_type=ssr_cgpa');
    add_submenu_page('SSR', 'View '.esc_attr( get_option('ssr_settings_ssr_item8') ), esc_attr( get_option('ssr_settings_ssr_item8') ), 'publish_pages', 'edit.php?post_type=ssr_subjects');
	add_submenu_page('SSR', 'Add '.esc_attr( get_option('ssr_settings_ssr_item8') ), 'Add '.esc_attr( get_option('ssr_settings_ssr_item8') ), 'publish_pages', 'post-new.php?post_type=ssr_subjects');
	add_submenu_page('SSR', 'Settings', 'Settings', 'publish_pages', 'ssr_settings', 'ssr_router');
	
		//call register settings function
		add_action( 'admin_init', 'ss_register_mysettings' );
}
function ssr_router() {

	// Get current screen details
	$screen = get_current_screen();

	if(strpos($screen->base, 'ssr_add_results') !== false) {
		include(SSR_ROOT_PATH.'/views/ssr_add_results.php');
	} elseif  (strpos($screen->base, 'ssr_all_entires') !== false) {
		include(SSR_ROOT_PATH.'/views/all_entries.php');
	}elseif  (strpos($screen->base, 'ssr_settings') !== false) {
		include(SSR_ROOT_PATH.'/views/options.php');
	} else {
		include(SSR_ROOT_PATH.'/views/view_main.php');
	}
}
// ENABLE AJAX :
function ssr_add_ajax()
{
   wp_localize_script(
    'function',
    'ajax_script',
    array( 'ajaxurl' => admin_url( 'admin-ajax.php' ) ) );
}
add_action("wp_ajax_nopriv_function1", "function1"); // function in ajax.php

add_action('template_redirect', 'ssr_add_ajax');

function ssr_add_ajaxurl_cdata_to_front(){ ?>
    <script type="text/javascript"> //<![CDATA[
        ajaxurl = '<?php echo admin_url( 'admin-ajax.php'); ?>';
    //]]> </script>
<?php }
add_action( 'wp_head', 'ssr_add_ajaxurl_cdata_to_front', 1);


function ss_register_mysettings() {
	//register our settings
	register_setting( 'ssr_settings_group', 'ssr_settings_ssr_item2' );
	register_setting( 'ssr_settings_group', 'some_other_option' );
	register_setting( 'ssr_settings_group', 'option_etc' );
}
?>