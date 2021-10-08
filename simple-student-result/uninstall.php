<?php
		register_uninstall_hook(SSR_ROOT_FILE,'ssr_unins');
		function ssr_unins(){
	            global $wpdb;
			$table = $wpdb->prefix.SSR_TABLE;
			delete_option('ssr_settings_ssr_item1');delete_option('ssr_settings_ssr_item2');delete_option('ssr_settings_ssr_item3');delete_option('ssr_settings_ssr_item4');delete_option('ssr_settings_ssr_item5');delete_option('ssr_settings_ssr_item6');delete_option('ssr_settings_ssr_item7');delete_option('ssr_settings_ssr_item8');delete_option('ssr_settings_ssr_item9');delete_option('ssr_settings_ssr_item10');delete_option('ssr_settings_ssr_item11');delete_option('ssr_settings_ssr_item12');delete_option('ssr_settings_ssr_item13');delete_option('ssr_settings_ssr_item14');
			$wpdb->query("DROP TABLE IF EXISTS $table");
			$url=get_site_url();$message='Uninstalled, Simple Student Results is uninstalled on url :'.$url.' version: '.SSR_VERSION;$message=wordwrap($message,70,"\r\n");wp_mail('saadvi@gmail.com','SSR Uninstalled url :'.$url.' version: '.SSR_VERSION,$message);
		}
?>