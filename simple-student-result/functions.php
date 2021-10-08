<?php
/*
Respond From Ajax Call
*/
add_action( 'wp_ajax_nopriv_ssr_add_st_submit', 'fn_ssr_add_st_submit' );
add_action( 'wp_ajax_ssr_add_st_submit', 'fn_ssr_add_st_submit' );
function fn_ssr_add_st_submit() {
if (!current_user_can('edit_posts')) return false;
global $wpdb;
    if (isset($_POST['rid'])) {
		$wpdb->delete( $wpdb->prefix.SSR_TABLE, array( 'rid' => $_POST['rid']) );
		$tf='Please fill out this field.';
		if ($_POST['stpy']==$tf) $_POST['stpy']='';if ($_POST['stcgpa']==$tf) $_POST['stcgpa']='';if ($_POST['stsub']==$tf) $_POST['stsub']='';if ($_POST['stpy2']==$tf) $_POST['stpy2']='';if ($_POST['stpy3']==$tf) $_POST['stpy3']='';if ($_POST['stpy4']==$tf) $_POST['stpy4']='';if ($_POST['stpy5']==$tf) $_POST['stpy5']='';if ($_POST['stpy6']==$tf) $_POST['stpy6']='';if ($_POST['stpy7']==$tf) $_POST['stpy7']='';
		$wpdb->query( $wpdb->prepare( 
							"INSERT INTO ".$wpdb->prefix.SSR_TABLE."
								( rid, roll, stdname, fathersname, pyear, cgpa, subject, dob, gender, address, mnam, c1, c2, image  )
								VALUES ( %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s )", 
							array(
							$_POST['rid'],$_POST['rn'],$_POST['stn'],$_POST['stfn'],$_POST['stpy'],$_POST['stcgpa'], $_POST['stsub'] , $_POST['stpy2'] , $_POST['stpy3'] , $_POST['stpy4'] , $_POST['stpy5'] , $_POST['stpy6'] , $_POST['stpy7'] , $_POST['upload_image']
							) 
		) );

    }
$student_count =$wpdb->get_var( "SELECT COUNT(*) FROM ".$wpdb->prefix.SSR_TABLE );
echo $student_count;
	if ($wpdb->last_error) {
  die('error=' . var_dump($wpdb->last_query) . ',' . var_dump($wpdb->error));
}
die();
}
add_action( 'wp_ajax_nopriv_ssr_del_st_submit', 'fn_ssr_del_st_submit' );
add_action( 'wp_ajax_ssr_del_st_submit', 'fn_ssr_del_st_submit' );
function fn_ssr_del_st_submit() {
if (!current_user_can('edit_posts')) return false;
?><script type="text/javascript">console.log(<?php echo 'Deleted ID : '.$_POST['rid']; ?>);</script><?php
global $wpdb;
    if (isset($_POST['rid'])) {
		$student_count =$wpdb->get_var($wpdb->prepare( "SELECT COUNT(*) FROM ".$wpdb->prefix.SSR_TABLE." where rid=%s", $_POST['rid'] ));
    }
if ($student_count>0){
$student_count =$wpdb->prepare( "delete from ".$wpdb->prefix.SSR_TABLE." where rid=%s", $_POST['rid'] );
$wpdb->query($student_count);
$student_count =$wpdb->get_var( "SELECT COUNT(*) FROM ".$wpdb->prefix.SSR_TABLE );
echo $student_count;
}else{echo 'no';}
	if ($wpdb->last_error) {
  die('error=' . var_dump($wpdb->last_query) . ',' . var_dump($wpdb->error));
}
die();
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit', 'ssr_fn_only_view_st_submit' );
add_action( 'wp_ajax_ssr_view_st_submit', 'ssr_fn_only_view_st_submit' );
function ssr_fn_only_view_st_submit() {
global $wpdb;
    if (isset($_POST['postID']) && strlen($_POST['postID'])>0 ) {
		$student_count =$wpdb->get_var($wpdb->prepare( "SELECT COUNT(*) FROM ".$wpdb->prefix.SSR_TABLE." where rid=%s", $_POST['postID'] ));
    }
	if (intval($student_count)>0){
	unset($student_count);
	$results = $wpdb->get_row($wpdb->prepare("SELECT * FROM ".$wpdb->prefix.SSR_TABLE." where rid=%s", $_POST['postID']));
	$data='RID:XS'.$results->rid;
	$data=$data.'Rollg:XS'.$results->roll;
	$data=$data.'Stdge:XS'.$results->stdname;
	$data=$data.'Fxtge:XS'.$results->fathersname;
	$data=$data.'pYear:XS'.$results->pyear;
	$data=$data.'sCGPA:XS'.$results->cgpa;
	$data=$data.'sSjct:XS'.$results->subject;
	$data=$data.'stdob:XS'.$results->dob;
	$data=$data.'stgen:XS'.$results->gender;
	$data=$data.'stadd:XS'.$results->address;
	$data=$data.'stmna:XS'.$results->mnam;
	$data=$data.'stmc1:XS'.$results->c1;
	$data=$data.'stmc2:XS'.$results->c2;
	$data=$data.'stIme:XS'.$results->image;
	echo $data;
	unset($data);
	}else{echo 'no';}
		if ($wpdb->last_error) {
	  die('error=' . var_dump($wpdb->last_query) . ',' . var_dump($wpdb->error));
	}
	unset($results);
	die();
    // IMPORTANT: don't forget to "exit"
    exit;
}
//Items started
add_action( 'wp_ajax_nopriv_ssr_view_st_submit1', 'ssr_fn_only_view_st_submit1' );
add_action( 'wp_ajax_ssr_view_st_submit1', 'ssr_fn_only_view_st_submit1' );
function ssr_fn_only_view_st_submit1() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item1', $_POST['s']);
    }
echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit2', 'ssr_fn_only_view_st_submit2' );
add_action( 'wp_ajax_ssr_view_st_submit2', 'ssr_fn_only_view_st_submit2' );
function ssr_fn_only_view_st_submit2() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item2', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit3', 'ssr_fn_only_view_st_submit3' );
add_action( 'wp_ajax_ssr_view_st_submit3', 'ssr_fn_only_view_st_submit3' );
function ssr_fn_only_view_st_submit3() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item3', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit4', 'ssr_fn_only_view_st_submit4' );
add_action( 'wp_ajax_ssr_view_st_submit4', 'ssr_fn_only_view_st_submit4' );
function ssr_fn_only_view_st_submit4() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item4', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit5', 'ssr_fn_only_view_st_submit5' );
add_action( 'wp_ajax_ssr_view_st_submit5', 'ssr_fn_only_view_st_submit5' );
function ssr_fn_only_view_st_submit5() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item5', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit6', 'ssr_fn_only_view_st_submit6' );
add_action( 'wp_ajax_ssr_view_st_submit6', 'ssr_fn_only_view_st_submit6' );
function ssr_fn_only_view_st_submit6() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item6', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'wp_ajax_nopriv_ssr_view_st_submit7', 'ssr_fn_only_view_st_submit7' );
add_action( 'wp_ajax_ssr_view_st_submit7', 'ssr_fn_only_view_st_submit7' );
function ssr_fn_only_view_st_submit7() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item7', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit8', 'ssr_fn_only_view_st_submit8' );
add_action( 'wp_ajax_ssr_view_st_submit8', 'ssr_fn_only_view_st_submit8' );
function ssr_fn_only_view_st_submit8() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item8', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'wp_ajax_nopriv_ssr_view_st_submit9', 'ssr_fn_only_view_st_submit9' );
add_action( 'wp_ajax_ssr_view_st_submit9', 'ssr_fn_only_view_st_submit9' );
function ssr_fn_only_view_st_submit9() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item9', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'ssr_settings_ssr_item10', 'ssr_fn_only_view_st_submit10' );
add_action( 'wp_ajax_ssr_view_st_submit10', 'ssr_fn_only_view_st_submit10' );
function ssr_fn_only_view_st_submit10() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item10', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'ssr_settings_ssr_item11', 'ssr_fn_only_view_st_submit11' );
add_action( 'wp_ajax_ssr_view_st_submit11', 'ssr_fn_only_view_st_submit11' );
function ssr_fn_only_view_st_submit11() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item11', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'ssr_settings_ssr_item12', 'ssr_fn_only_view_st_submit12' );
add_action( 'wp_ajax_ssr_view_st_submit12', 'ssr_fn_only_view_st_submit12' );
function ssr_fn_only_view_st_submit12() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item12', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'ssr_settings_ssr_item13', 'ssr_fn_only_view_st_submit13' );
add_action( 'wp_ajax_ssr_view_st_submit13', 'ssr_fn_only_view_st_submit13' );
function ssr_fn_only_view_st_submit13() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item13', $_POST['s']);
    }
	echo $_POST['s'];
}
add_action( 'ssr_settings_ssr_item14', 'ssr_fn_only_view_st_submit14' );
add_action( 'wp_ajax_ssr_view_st_submit14', 'ssr_fn_only_view_st_submit14' );
function ssr_fn_only_view_st_submit14() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item14', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item15', 'ssr_fn_only_view_st_submit15' );
add_action( 'wp_ajax_ssr_view_st_submit15', 'ssr_fn_only_view_st_submit15' );
function ssr_fn_only_view_st_submit15() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item15', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item16', 'ssr_fn_only_view_st_submit16' );
add_action( 'wp_ajax_ssr_view_st_submit16', 'ssr_fn_only_view_st_submit16' );
function ssr_fn_only_view_st_submit16() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item16', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item17', 'ssr_fn_only_view_st_submit17' );
add_action( 'wp_ajax_ssr_view_st_submit17', 'ssr_fn_only_view_st_submit17' );
function ssr_fn_only_view_st_submit17() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item17', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item18', 'ssr_fn_only_view_st_submit18' );
add_action( 'wp_ajax_ssr_view_st_submit18', 'ssr_fn_only_view_st_submit18' );
function ssr_fn_only_view_st_submit18() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item18', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item19', 'ssr_fn_only_view_st_submit19' );
add_action( 'wp_ajax_ssr_view_st_submit19', 'ssr_fn_only_view_st_submit19' );
function ssr_fn_only_view_st_submit19() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item19', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item20', 'ssr_fn_only_view_st_submit20' );
add_action( 'wp_ajax_ssr_view_st_submit20', 'ssr_fn_only_view_st_submit20' );
function ssr_fn_only_view_st_submit20() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item20', $_POST['s']);
    }
	echo $_POST['s'];
}

add_action( 'ssr_settings_ssr_item21', 'ssr_fn_only_view_st_submit21' );
add_action( 'wp_ajax_ssr_view_st_submit21', 'ssr_fn_only_view_st_submit21' );
function ssr_fn_only_view_st_submit21() {
    if (isset($_POST['s']) && strlen($_POST['s'])>0 ) {
		update_option('ssr_settings_ssr_item21', $_POST['s']);
    }
	echo $_POST['s'];
}



//Required Fields
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item2', 'ssr_fn_only_view_st_checkedssr_item2' );
add_action( 'wp_ajax_ssr_view_st_ssr_item2', 'ssr_fn_only_view_st_checkedssr_item2' );
function ssr_fn_only_view_st_checkedssr_item2() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item2', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item3', 'ssr_fn_only_view_st_checkedssr_item3' );
add_action( 'wp_ajax_ssr_view_st_ssr_item3', 'ssr_fn_only_view_st_checkedssr_item3' );
function ssr_fn_only_view_st_checkedssr_item3() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item3', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item4', 'ssr_fn_only_view_st_checkedssr_item4' );
add_action( 'wp_ajax_ssr_view_st_ssr_item4', 'ssr_fn_only_view_st_checkedssr_item4' );
function ssr_fn_only_view_st_checkedssr_item4() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item4', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item5', 'ssr_fn_only_view_st_checkedssr_item5' );
add_action( 'wp_ajax_ssr_view_st_ssr_item5', 'ssr_fn_only_view_st_checkedssr_item5' );
function ssr_fn_only_view_st_checkedssr_item5() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item5', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item6', 'ssr_fn_only_view_st_checkedssr_item6' );
add_action( 'wp_ajax_ssr_view_st_ssr_item6', 'ssr_fn_only_view_st_checkedssr_item6' );
function ssr_fn_only_view_st_checkedssr_item6() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item6', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item7', 'ssr_fn_only_view_st_checkedssr_item7' );
add_action( 'wp_ajax_ssr_view_st_ssr_item7', 'ssr_fn_only_view_st_checkedssr_item7' );
function ssr_fn_only_view_st_checkedssr_item7() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item7', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item8', 'ssr_fn_only_view_st_checkedssr_item8' );
add_action( 'wp_ajax_ssr_view_st_ssr_item8', 'ssr_fn_only_view_st_checkedssr_item8' );
function ssr_fn_only_view_st_checkedssr_item8() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item8', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item9', 'ssr_fn_only_view_st_checkedssr_item9' );
add_action( 'wp_ajax_ssr_view_st_ssr_item9', 'ssr_fn_only_view_st_checkedssr_item9' );
function ssr_fn_only_view_st_checkedssr_item9() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item9', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item10', 'ssr_fn_only_view_st_checkedssr_item10' );
add_action( 'wp_ajax_ssr_view_st_ssr_item10', 'ssr_fn_only_view_st_checkedssr_item10' );
function ssr_fn_only_view_st_checkedssr_item10() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item10', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item11', 'ssr_fn_only_view_st_checkedssr_item11' );
add_action( 'wp_ajax_ssr_view_st_ssr_item11', 'ssr_fn_only_view_st_checkedssr_item11' );
function ssr_fn_only_view_st_checkedssr_item11() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item11', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item12', 'ssr_fn_only_view_st_checkedssr_item12' );
add_action( 'wp_ajax_ssr_view_st_ssr_item12', 'ssr_fn_only_view_st_checkedssr_item12' );
function ssr_fn_only_view_st_checkedssr_item12() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item12', $_POST['s']);
    }
}
add_action( 'wp_ajax_nopriv_ssr_view_st_ssr_item13', 'ssr_fn_only_view_st_checkedssr_item13' );
add_action( 'wp_ajax_ssr_view_st_ssr_item13', 'ssr_fn_only_view_st_checkedssr_item13' );
function ssr_fn_only_view_st_checkedssr_item13() {
    if (isset($_POST['s']) ) {
	update_option('checkedssr_item13', $_POST['s']);
    }
}
function ssr_clean($string) {
	return $string;
   // $string = str_replace(' ', '-', $string); // Replaces all spaces with hyphens.

   // return preg_replace('/[^A-Za-z0-9\-]/', '', $string); // Removes special chars.
}
?>