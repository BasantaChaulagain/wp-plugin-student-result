<?php
global $wpdb;
$student_count =$wpdb->get_var("SELECT COUNT(*) FROM ".$wpdb->prefix.SSR_TABLE );
echo '<div id="dbinfo" class="arial_fonts">';
if ($student_count>1) {echo "{$student_count} ".esc_attr( get_option('ssr_settings_ssr_item4') )."s are in Database";}else{if ($student_count>0){echo "{$student_count} ".esc_attr( get_option('ssr_settings_ssr_item4') )." is in Database";}else{echo "No ".esc_attr( get_option('ssr_settings_ssr_item4') )." is in Database";}}
echo '</div>';
?>
<div class="tutorial">
<h2>Need some tutorial in this page?</h2>
<span class="b">Insert a record : <a href="https://www.youtube.com/watch?v=C8QjxJUKRMU" target="_blank">Tutorial</a></span>
<span class="b">Delete a record : <a href="https://www.youtube.com/watch?v=NoVvsJoKWPU" target="_blank">Tutorial</a></span>
<span class="b">Edit a record : <a href="https://www.youtube.com/watch?v=uJxLTSmGHkk" target="_blank">Tutorial</a></span>
</div>
<div class="result_box">
	<div class="dte">
	<div style="width: 100%;height: 20px;"></div>
	<div class="seps"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item9') ); ?> :</span><input type="text" id="rid" name="rids" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {{this.value='';jQuery('#rid').removeClass('needsfilled');}jQuery('#rid').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item10') ); ?> : </span><input type="text" name="rns" id="rn" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#rn').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item11') ); ?> :</span><input type="text" id="stn" name="stns" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stn').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item12') ); ?> :</span><input maxlength="500" type="text" id="stfn" name="stfns" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stfn').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item13') ); ?> :</span><input type="text" id="stpy" name="stnsx" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item14') ); ?> :</span><select id="stcgpa" class="std_input std_input_item" onfocus="jQuery('#stcgpa').removeClass('needsfilled');"><option value="Please fill out this field." selected>Please fill out this field.</option>
				<?php $args = array(
				'post_type' => array( 'ssr_cgpa' ),
				'posts_per_page' => -1,
				'showposts' => -1
			);
			$wp_query = new WP_Query( $args );
			if ( $wp_query->have_posts() ) {
				while ( $wp_query->have_posts() ) { $wp_query->the_post();
				$course_name = json_encode(get_the_title()) ; ?>
	   <option value="<?php the_title(); ?>"><?php the_title(); ?></option>
			   <?php }
			}
			// Reset Query
			wp_reset_query();wp_reset_postdata();
			?>	
	</select></Div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item15') ); ?> :</span><select id="stsub" class="std_input std_input_item" onfocus="jQuery('#stsub').removeClass('needsfilled');"><option value="Please fill out this field." selected>Please fill out this field.</option>
	<?php
				$args = array(
				'post_type' => array( 'ssr_subjects' ),
				'posts_per_page' => -1,
				'showposts' => -1
			);
			$wp_query = new WP_Query( $args );
			if ( $wp_query->have_posts() ) {
				while ( $wp_query->have_posts() ) { $wp_query->the_post();
				$course_name = json_encode(get_the_title()) ; ?>
	   <option value="<?php the_title(); ?>"><?php the_title(); ?></option>
	   <?php }
	}
	// Reset Query
	wp_reset_query();wp_reset_postdata();
	?>

	</select></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item16') ); ?> :</span><input type="text" id="stpy2" name="stnsx2" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy2').removeClass('needsfilled');}" maxlength="50" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item17') ); ?> :</span><input type="text" id="stpy3" name="stnsx3" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy3').removeClass('needsfilled');}" maxlength="10" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item18') ); ?> :</span><input type="text" id="stpy4" name="stnsx4" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy4').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item19') ); ?> :</span><input type="text" id="stpy5" name="stnsx5" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy5').removeClass('needsfilled');}" maxlength="100" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item20') ); ?> :</span><input type="text" id="stpy6" name="stnsx6" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy6').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	<div class="sep"><span class="std_title"><?php echo esc_attr( get_option('ssr_settings_ssr_item21') ); ?> :</span><input type="text" id="stpy7" name="stnsx7" class="std_input std_input_item" onfocus="if(this.value=='Please fill out this field.') {this.value='';jQuery('#stpy7').removeClass('needsfilled');}" maxlength="500" placeholder="Please fill out this field."></div>
	
	
	
	<div class="seps">
	<label for="upload_image" style="width: 100%">
		<input id="upload_image" class="std_input std_input_item" type="text" size="36" name="ad_image" value="" readonly="readonly" />
		<input id="upload_image_button" class="button std_title" type="button" value="Upload Image" />
	</label>
	</div>
		<div class="buttons">
			<a id="btn_save" href="#" class="ssr_btn ssr_btn_save">Save</a>
			<a id="btn_delete" href="#" class="ssr_btn ssr_btn_delete">Delete</a>
		</div>
	</div><!-- text boxs DTE -->
	<div class="image_box">
		<img id="st_img" src="" alt="" width="200px" height="auto"/>
	</div>
</div><!-- Result Box -->


<script>
jQuery(document).ready(function(e) {
function s(){for(vx=0,i=0;i<required.length;i++){var e=jQuery("#"+required[i]);(""==e.val()||e.val()==emptyerror||0==e.length)&&vx++}vx>0?jQuery("#btn_save").addClass("disable"):jQuery("#btn_save").removeClass("disable")}function r(){for(vx=0,i=0;i<required.length;i++){var e=jQuery("#"+required[i]);""==e.val()||e.val()==emptyerror||0==e.length?vx++:e.removeClass("needsfilled")}}function t(){for(i=0;i<required.length;i++){var r=jQuery("#"+required[i]);r.val(emptyerror)}e("#st_img").attr("src","")}function a(){for(i=1;i<required.length;i++){var r=jQuery("#"+required[i]);r.val(emptyerror)}e("#st_img").attr("src","")}
    required = ["rid" <?php if (esc_attr( get_option('checkedssr_item2') )>0) {echo ',"rn"';} if (esc_attr( get_option('checkedssr_item3') )>0) {echo ',"stn"';} if (esc_attr( get_option('checkedssr_item4') )>0) {echo ',"stfn"';} if (esc_attr( get_option('checkedssr_item5') )>0) {echo ',"stpy"';} if (esc_attr( get_option('checkedssr_item6') )>0) {echo ',"stcgpa"';} if (esc_attr( get_option('checkedssr_item7') )>0) {echo ',"stsub"';} if (esc_attr( get_option('checkedssr_item8') )>0) {echo ',"stpy2"';} if (esc_attr( get_option('checkedssr_item9') )>0) {echo ',"stpy3"';} if (esc_attr( get_option('checkedssr_item10') )>0) {echo ',"stpy4"';} if (esc_attr( get_option('checkedssr_item11') )>0) {echo ',"stpy5"';} if (esc_attr( get_option('checkedssr_item12') )>0) {echo ',"stpy6"';} if (esc_attr( get_option('checkedssr_item13') )>0) {echo ',"stpy7"';} ?>], emptyerror = "Please fill out this field.";
var u;
e("#upload_image_button").click(function (s) {
    return (
        s.preventDefault(),
        u
            ? void u.open()
            : ((u = wp.media.frames.file_frame = wp.media({ title: "Choose Image", button: { text: "Choose Image" }, multiple: !1 })),
              u.on("select", function () {
                  (attachment = u.state().get("selection").first().toJSON()), e("#upload_image").val(attachment.url), e("#st_img").attr("src", attachment.url);
              }),
              void u.open())
    );
}),
    e("#upload_image").click(function () {
        e("#upload_image_button").click();
    }),
    jQuery(document.body).click(function () {
        jQuery(".std_input").each(function () {
            s();
        });
    }),
    jQuery("#btn_save").click(function () {
        for (vx = 0, i = 0; i < required.length; i++) {
            var s = jQuery("#" + required[i]);
            "" == s.val() || s.val() == emptyerror || 0 == s.length ? (s.addClass("needsfilled"), s.effect("shake"), s.val(emptyerror), vx++) : s.removeClass("needsfilled");
        }
        vx > 0 ? jQuery("#btn_save").addClass("disable") : jQuery("#btn_save").removeClass("disable"),
            jQuery("#btn_save").hasClass("disable") ||
                jQuery.post(
                    SSR_Ajax.ajaxurl,
                    {
                        action: "ssr_add_st_submit",
                        rid: jQuery.trim(jQuery("#rid").val()),
                        rn: jQuery("#rn").val(),
                        stn: jQuery("#stn").val(),
                        stfn: jQuery("#stfn").val(),
                        stpy: jQuery("#stpy").val(),
                        stcgpa: jQuery("#stcgpa").val(),
                        stsub: jQuery("#stsub").val(),
                        stpy2: jQuery("#stpy2").val(),
                        stpy3: jQuery("#stpy3").val(),
                        stpy4: jQuery("#stpy4").val(),
                        stpy5: jQuery("#stpy5").val(),
                        stpy6: jQuery("#stpy6").val(),
                        stpy7: jQuery("#stpy7").val(),
                        upload_image: jQuery("#upload_image").val(),
                    },
                    function (s) {
                        t(),
                            jQuery("#btn_delete").css({ opacity: 0.1, cursor: "no-drop" }),
                            jQuery("#btn_save").addClass("ssr_btn_save"),
                            jQuery("#btn_save").removeClass("ssr_btn_update"),
                            e("#btn_save").html("Save"),
                            jQuery("#dbinfo").html(s > 1 ? s + " Students are in Database" : s + " Student is in Database"),
                            new jQuery.Zebra_Dialog("This Student Has Been Saved successfully", { buttons: !1, type: "confirmation", title: "Confirmation", modal: !1, auto_close: 2e3 });
                    }
                ),
            jQuery("div.sep input").val(""),
            jQuery("div.sep select").val("Please fill out this field.");
    });
	last_SSR_id=0;
    jQuery(document).on('keyup', '#rid', function(){
        if(jQuery("#rid").val().length > 0 ){
				if(last_SSR_id !== jQuery("#rid").val()){
					last_SSR_id=jQuery("#rid").val();
					jQuery.ajax({
					url: "<?php echo get_rest_url(); ?>v2/ssr_find_all",
					method: "POST",
					data: {postID: jQuery.trim(jQuery("#rid").val())},
					success: function (s) {
						if (s.success==true){
							console.log(s);
							jQuery("#rn").val(s[0].roll);
							jQuery("#stn").val(s[0].stdname);
							jQuery("#stfn").val(s[0].fathersname);
							jQuery("#stpy").val(s[0].pyear);
							jQuery("#stcgpa").val(s[0].cgpa);
							jQuery("#stsub").val(s[0].subject);
							jQuery("#stpy2").val(s[0].dob);
							jQuery("#stpy3").val(s[0].gender);
							jQuery("#stpy4").val(s[0].address);
							jQuery("#stpy5").val(s[0].mnam);
							jQuery("#stpy6").val(s[0].c1);
							jQuery("#stpy7").val(s[0].c2);
							jQuery("#ssr_upload_txt_1").val(s[0].image);
							jQuery("#st_img").attr("src", s[0].image),
							jQuery("#btn_delete").css({ opacity: 1, cursor: "pointer" }),
							jQuery("#btn_save").removeClass("disable"),
							jQuery("#btn_save").removeClass("ssr_btn_save"),
							jQuery("#btn_save").addClass("ssr_btn_update"),
							e("#btn_save").html("Update"),
							r(),
							jQuery("div.sep input").css({ opacity: 1, cursor: "inherit" }), jQuery("div.sep select").css({ opacity: 1, cursor: "inherit" });
						} else {
							console.log("Not found");console.log(s);jQuery(".std_input:not(#rid):not(img)").val("");
							a(), jQuery("#btn_delete").css({ opacity: 0.1, cursor: "no-drop" }), jQuery("#btn_save").css({ opacity: 1, cursor: "pointer" });
							jQuery("#btn_save").addClass("ssr_btn_save"), jQuery("#btn_save").removeClass("ssr_btn_update"), e("#btn_save").html("Save");
							jQuery("div.sep input").css({ opacity: 1, cursor: "inherit" }), jQuery("div.sep select").css({ opacity: 1, cursor: "inherit" });
						}
					}
					})
			}
		}else{
			last_SSR_id=0;
			  jQuery("#btn_delete").css({ opacity: 0.1, cursor: "no-drop" }),
              jQuery("#btn_save").css({ opacity: 0.1, cursor: "no-drop" }),
              jQuery("div.sep input").css({ opacity: 0.1, cursor: "no-drop" }),
              jQuery("div.sep select").css({ opacity: 0.1, cursor: "no-drop" }),
              jQuery("div.sep input").val(""),
              jQuery("div.sep select").val("Please fill out this field."),
              jQuery("#btn_save").addClass("ssr_btn_save"),
              jQuery("#btn_save").removeClass("ssr_btn_update"),
              e("#btn_save").html("Save");jQuery("div.sep input").css({ opacity: 0.1, cursor: "inherit" }), jQuery("div.sep select").css({ opacity: 0.1, cursor: "inherit" });
		}
    }),
    jQuery("#btn_delete").click(function () {
        1 == jQuery("#btn_delete").css("opacity") &&
            jQuery.Zebra_Dialog("Are you <strong>Sure</strong>You want to Delete?", {
                type: "question",
                title: "Custom buttons",
                buttons: [
                    {
                        caption: "Yes",
                        callback: function () {
                            jQuery.post(SSR_Ajax.ajaxurl, { action: "ssr_del_st_submit", rid: jQuery.trim(jQuery("#rid").val()) }, function (s) {
                                console.log(s),
                                    jQuery("div.sep input").val(""),
                                    jQuery("div.sep select").val("Please fill out this field."),
                                    t(),
                                    jQuery("#btn_delete").css({ opacity: 0.1, cursor: "no-drop" }),
                                    jQuery("#btn_save").addClass("ssr_btn_save"),
                                    jQuery("#btn_save").removeClass("ssr_btn_update"),
                                    e("#btn_save").html("Save"),
                                    jQuery("#dbinfo").html(s > 1 ? s + " Students are in Database" : s + " Student is in Database"),
                                    new jQuery.Zebra_Dialog("<strong>Deleted </strong> Successfully", { buttons: !1, type: "confirmation", title: "Confirmation", modal: !1, auto_close: 2e3 });
                            });
                        },
                    },
                    { caption: "No", callback: function () {} },
                ],
            });
    }),
    jQuery("#rid").keydown(function (e) {
        return 32 == e.keyCode ? !1 : void 0;
    });

})
</script>