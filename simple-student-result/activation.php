<?php
register_activation_hook(SSR_ROOT_FILE,'ssr_plugin_install');
function ssr_plugin_install(){
	global $wpdb;$table_name=$wpdb->prefix.'ssr_studentinfo';
if($wpdb->get_var("SHOW TABLES LIKE '$table_name'")!=$table_name){
$charset_collate = $wpdb->get_charset_collate();
$sql = "CREATE TABLE $table_name (
			rid varchar(100) NOT NULL,
			roll text NULL,
			stdname text NULL,
			fathersname text NULL,
			pyear text NULL,
			cgpa text NULL,
			subject text NULL,
			image text NULL,
			dob text NULL,
			gender text NULL,
			address text NULL,
			mnam text NULL,
			c1 text NULL,
			c2 text NULL,
			UNIQUE KEY id (rid)
) $charset_collate;";

require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
dbDelta( $sql );
add_option('jal_db_version',$jal_db_version);if(WP_CACHE&&function_exists('wp_cache_postload'))wp_cache_postload();wp_functionality_constants();$wp_the_query=new WP_Query();$wp_query=&$wp_the_query;$GLOBALS['wp_rewrite']=new WP_Rewrite();$i=1;while($i<=3){$my_post=array('post_type'=>'ssr_subjects','post_title'=>'Subject '.$i.'','post_content'=>'This is Subject '.$i.'','post_status'=>'publish','post_author'=>1);wp_insert_post($my_post);$i++;}$i=1;$cgpa=2.50;number_format($cgpa,2);while($cgpa<=5.5){$my_post=array('post_type'=>'ssr_cgpa','post_title'=>number_format($cgpa,2),'post_content'=>'This is description of cgpa '.number_format($cgpa,2).'','post_status'=>'publish','post_author'=>1);wp_insert_post($my_post);$i++;$cgpa=$cgpa+.25;}
		}
		ssr_db_update_from_138();
		// do_action('plugins_loaded');
		}
		register_uninstall_hook(SSR_ROOT_FILE,'ssr_unins');
		function ssr_unins(){
	        global $wpdb;
			$table = $wpdb->prefix.SSR_TABLE;
			delete_option('ssr_settings_ssr_item1');delete_option('ssr_settings_ssr_item2');delete_option('ssr_settings_ssr_item3');delete_option('ssr_settings_ssr_item4');delete_option('ssr_settings_ssr_item5');delete_option('ssr_settings_ssr_item6');delete_option('ssr_settings_ssr_item7');delete_option('ssr_settings_ssr_item8');delete_option('ssr_settings_ssr_item9');delete_option('ssr_settings_ssr_item10');delete_option('ssr_settings_ssr_item11');delete_option('ssr_settings_ssr_item12');delete_option('ssr_settings_ssr_item13');delete_option('ssr_settings_ssr_item14');
			$wpdb->query("DROP TABLE IF EXISTS $table");
		}
function ssr_ihh_check_version(){
	if (esc_attr( get_option('ssr_version_installed') )!=SSR_VERSION){
			ssr_set_d_v();
			ssr_db_update_from_138();
	}
}
add_action( 'plugins_loaded', 'ssr_ihh_check_version' );

function ssr_set_d_v(){
if (SSR_VERSION_B<=143){
	global $wpdb;
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE rid rid varchar(100) NOT NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE stdname stdname text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE fathersname fathersname text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE subject subject text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE image image text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE dob dob text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE gender gender text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE roll roll text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE pyear pyear text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE address address text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE cgpa cgpa text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE c1 c1 text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE c2 c2 text NULL");
	$wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." CHANGE mnam mnam text NULL");
}
			update_option('ssr_version_installed',SSR_VERSION);
}

function ssr_db_update_from_138(){
	global $wpdb;
	$row = $wpdb->get_results( "SELECT * FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = '".DB_NAME."' AND TABLE_NAME = '".$wpdb->prefix.SSR_TABLE."' AND COLUMN_NAME = 'address'" );

if(empty($row)){
   $wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." ADD dob text NULL");
   $wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." ADD gender text NULL");
   $wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." ADD address text NULL");
   $wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." ADD mnam text NULL");
   $wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." ADD c1 text NULL");
   $wpdb->query("ALTER TABLE ".$wpdb->prefix.SSR_TABLE." ADD c2 text NULL");
}
}
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item1') ))==0) update_option('ssr_settings_ssr_item1','Online Result System');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item2') ))==0) update_option('ssr_settings_ssr_item2','Enter Registration ID');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item3') ))==0) update_option('ssr_settings_ssr_item3','No Results !');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item4') ))==0) update_option('ssr_settings_ssr_item4','Student');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item5') ))==0) update_option('ssr_settings_ssr_item5','Students Result');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item6') ))==0) update_option('ssr_settings_ssr_item6','Add Student Results');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item7') ))==0) update_option('ssr_settings_ssr_item7','CGPA');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item8') ))==0) update_option('ssr_settings_ssr_item8','Subject');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item9') ))==0) update_option('ssr_settings_ssr_item9','Registration Number');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item10') ))==0) update_option('ssr_settings_ssr_item10','Roll No');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item11') ))==0) update_option('ssr_settings_ssr_item11','Student Name');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item12') ))==0) update_option('ssr_settings_ssr_item12','Fathers Name');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item13') ))==0) update_option('ssr_settings_ssr_item13','Passing Year');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item14') ))==0) update_option('ssr_settings_ssr_item14','CGPA');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item15') ))==0) update_option('ssr_settings_ssr_item15','Subject');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item16') ))==0) update_option('ssr_settings_ssr_item16','D.O.B');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item17') ))==0) update_option('ssr_settings_ssr_item17','Gender');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item18') ))==0) update_option('ssr_settings_ssr_item18','Address');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item19') ))==0) update_option('ssr_settings_ssr_item19','Mothers Name');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item20') ))==0) update_option('ssr_settings_ssr_item20','Extra Fields 1');
	if (strlen(esc_attr( get_option('ssr_settings_ssr_item21') ))==0) update_option('ssr_settings_ssr_item21','Extra Fields 2');
	// if (strlen(esc_attr( get_option('ssr_settings_ssr_item22') ))==0) update_option('ssr_settings_ssr_item21','Extra Fields 3');
?>