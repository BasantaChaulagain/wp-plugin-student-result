<?php
function ssr_wp_jquery_call_function(){
wp_enqueue_script('jquery');
}
add_action('init', 'ssr_wp_jquery_call_function');
// ShortCode
function ssr_show_results( $atts ) {
	ob_start();
	?> <div class="result_div">
	<div class="reg_box">
		<input type="text" id="rues" name="rue" placeholder="<?php echo esc_attr( get_option('ssr_settings_ssr_item2') ); ?>" maxlength="20">
	</div> <!-- Reg_box -->
	<div id="ssr_msgbox"><?php echo esc_attr( get_option('ssr_settings_ssr_item3') ); ?></div>
	<div class="result_box">		
		<div class="dte">
		<h1 class="ssr_settings_ssr_item1"><?php echo esc_attr( get_option('ssr_settings_ssr_item1') ); ?></h1>
			<div class="image_box">
				<img id="st_img2" src="" alt="" width="200px" height="auto"/>
			</div>
			<div id="ssr_frnt_circle">
				<div class="circle_top"></div>
				<div class="circle"></div>
				<div class="circle1"></div>
			</div>
			<div id="ssr_r_f_1" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item9') ); ?> :</span><input type="text" id="rid2" class="std_input" readonly></div>
			<div id="ssr_r_f_2" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item10') ); ?> : </span><input type="text" id="rn2" class="std_input" readonly></div>
			<div id="ssr_r_f_3" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item11') ); ?> :</span><input type="text" id="stn2" class="std_input" readonly></div>
			<div id="ssr_r_f_4" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item12') ); ?> :</span><input type="text" id="stfn2" class="std_input" readonly></div>
			<div id="ssr_r_f_5" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item13') ); ?> :</span><input type="text" id="stpy2" class="std_input" readonly></div>
			<div id="ssr_r_f_6" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item14') ); ?> :</span><input type="text" id="stcgpa2" class="std_input" readonly></div>
			<div id="ssr_r_f_7" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item15') ); ?> :</span><input type="text" id="stsub2" class="std_input" readonly></div>
			<div id="ssr_r_f_8" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item16') ); ?> :</span><input type="text" id="stsub3" class="std_input" readonly></div>
			<div id="ssr_r_f_9" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item17') ); ?> :</span><input type="text" id="stsub4" class="std_input" readonly></div>
			<div id="ssr_r_f_10" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item18') ); ?> :</span><input type="text" id="stsub5" class="std_input" readonly></div>
			<div id="ssr_r_f_11" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item19') ); ?> :</span><input type="text" id="stsub6" class="std_input" readonly></div>
			<div id="ssr_r_f_12" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item20') ); ?> :</span><input type="text" id="stsub7" class="std_input" readonly></div>
			<div id="ssr_r_f_13" class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item21') ); ?> :</span><input type="text" id="stsub8" class="std_input" readonly></div>
		</div><!-- text boxs DTE -->
	</div><!-- Result Box -->
</div><!-- result_div -->

<?PHP
	return ob_get_clean();
}
add_shortcode('ssr_results', 'ssr_show_results');

?>