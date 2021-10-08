<?php
// Function to get the client IP address
function SSR_get_client_ip() {
    $ipaddress = '';
    if (getenv('HTTP_CLIENT_IP'))
        $ipaddress = getenv('HTTP_CLIENT_IP');
    else if(getenv('HTTP_X_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
    else if(getenv('HTTP_X_FORWARDED'))
        $ipaddress = getenv('HTTP_X_FORWARDED');
    else if(getenv('HTTP_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_FORWARDED_FOR');
    else if(getenv('HTTP_FORWARDED'))
       $ipaddress = getenv('HTTP_FORWARDED');
    else if(getenv('REMOTE_ADDR'))
        $ipaddress = getenv('REMOTE_ADDR');
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
	/*$str = file_get_contents("http://ip6.me/");
$pattern = "#\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b#";
preg_match($pattern, $str, $matches);
return ($matches[0]);*/
}
if (SSR_get_client_ip()!='127.0.0.1'){
set_error_handler(
    create_function(
        '$severity, $message, $file, $line',
        'throw new ErrorException($message, $severity, $severity, $file, $line);'
    )
);
try {
    $arr = $arr =  @unserialize(file_get_contents('http://ip-api.com/php/'.SSR_get_client_ip()));
} catch (Exception $e) {
    echo '<br>';

}

restore_error_handler();

if (isset($arr)){
define( 'SSR_Visitor_Country',  $arr['country'] );
unset($arr);
}else{define( 'SSR_Visitor_Country',  'unknown');}
}else define( 'SSR_Visitor_Country',  'unknown');

	
if (SSR_Visitor_Country=="Bangladesh"){ ?>
<div class="ssr_info">
<p class="ssr_p_t">আপনাকে অনেক ধন্যবাদ এই প্লাগিন ব্যাবহার করার জন্য</p>
<p class="ssr_p_t"><a href="//ssr.saadamin.com/multimode/"><img src="//ssr.saadamin.com/ssr_add1_bn.jpg" alt="see Demo SSR Multimode bangla" /></a></p>
<p class="ssr_p"><b class="ssr_st_b_h">Shortcode : </b> [ssr_results] </p>
<p class="ssr_p"><b class="ssr_st_b_h">শুধুমাত্র যে user রা এই প্লাগিন এর মাধ্যমে ফলাফল ইনপুট দিতে পারবে :</b>  Author , Administrator , Super Administrator</p>
<p class="ssr_p">এই প্লাগিনের প্রিমিয়াম ভার্সন ও আছে , যাতে আপনি csv থেকে import করতে পারবেন , ৩ টা ছবি এবং ২৫ টা ফিল্ড (ছবি ছাড়া) সাপোর্ট করে ,  তাছাড়া স্কুলে যেমন আলাদা ক্লাস,সেকশন,সেমিস্টার এর জন্য আলাদা রেসাল্ট করা হয় বা শিক্ষা বোর্ড যেভাবে রেসাল্ট দেখায় সেভাবে রেসাল্ট দেখাতে পারবেন। একটি আলাদা extension যার মাধ্যমে আপনি আরেকটি একই রকম ডাটাবেস করতে পারেন ( যেমন আপনি student এবং teacher ২ টা database করতে পারেন ), admin আর user আলাদা acess ।  আছে আরও ফিচার।</p>
<p class="ssr_p">প্রিমিয়াম ভার্সন এর admin panel এর ডেমো দেখার জন্য ভিসিট করুন <a target="_blank" href="http://ssr.saadamin.com/login">এখানে</a></p>
<p class="ssr_p">user : test</p>
<p class="ssr_p">pass : test</p>
<p class="ssr_p">প্লাগিন এ  <b class="ssr_st_b_h">ajax</b> ব্যাবহার করা হয়েছে তাই ফলাফল পাবেন তৎক্ষণাৎ পেজ লোড ছাড়াই.</p>
<p class="ssr_p">প্রিমিয়াম ভার্সন বা যে কোন সমস্যার ও সাহায্যের জন্য আমাকে কল করতে পারেন  <b class="ssr_st_b_h">01722889212</b>  নাম্বার এ । বা ইমেইল করতে পারেন <a href="mailto:saadvi@gmail.com">saadvi@gmail.com</a> ঠিকানায়</p>
<p class="ssr_p"> [ssr_results] এই shortcode post/page এ ব্যবহার করুন  ,<a href="http://ssr.saadamin.com" target="_blank">যদি ডেমো দেখতে চান  এখানে ক্লিক করুন </a></p>	
<p class="ssr_p"><b>আপনি paypal এ পেমেন্ট এর মাধ্যমে ও প্রিমিয়াম ভার্সন পেতে পারেন ,  <a href="//ssr.saadamin.com/product/ssr/">এই লিঙ্ক এর মাধ্যমে কিনতে পারবেন</a> , কোন সমস্যার আমাকে কল করতে পারেন 01722889212 নাম্বার এ বা ইমেইল করতে পারেন saadvi@gmail.com এ বা skype : saadbd2003 তে যোগাযোগ করতে পারেন।</b>
 <form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_blank">
<input type="hidden" name="cmd" value="_s-xclick">
<input type="hidden" name="hosted_button_id" value="WTYR7R2HWXWZW">
<input type="image" src="https://www.paypalobjects.com/en_US/i/btn/btn_buynowCC_LG.gif" border="0" name="submit" alt="PayPal - The safer, easier way to pay online!">
<img alt="" border="0" src="https://www.paypalobjects.com/en_US/i/scr/pixel.gif" width="1" height="1">
</form>
</p>
<p class="ssr_p"><b>paypal নেই , ঠিক আছে মাত্র ৮০০ টাকায় আপনি এই প্লাগিনের প্রিমিয়াম ভার্সন পেতে পারেন , বিকাশ করতে পারেন 01722889212 নাম্বার এ </b></p>
<p class="ssr_p">এই tutorial এ আপনি দেখবেন কিভাবে plugin টি install করতে হয়  এবং short code use করতে হয়। </p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/C8QjxJUKRMU" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">রেকর্ড edit করবেন এই ভাবে</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/uJxLTSmGHkk" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">রেকর্ড মুছে ফেলা ও অতি সহজ</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/NoVvsJoKWPU" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">আপনি কি জানেন আপনি চাইলে এই প্লাগিন  employee database or client database হিসাবে ও ব্যাবহার করতে পারেন ? </p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/ntzb7njqd_4" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">এটা একটি প্রিমিয়াম ফিচার , আপনি csv file import ও করতে পারবেন  । </p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/1GfMZhnyCqw" frameborder="0" allowfullscreen></iframe></p>
</div>
<?php }else{
?>
<div class="ssr_info">
<p class="ssr_p_t">Welcome to Simple Student Result / Employee Database</p>
<p class="ssr_p_t"><a href="//ssr.saadamin.com/multimode/"><img src="//ssr.saadamin.com/ssr_add1_en.jpg" alt="see Demo SSR Multimode" /></a></p>
<p class="ssr_p"><b class="ssr_st_b_h">Shortcode : </b> [ssr_results] </p>
<p class="ssr_p"><b class="ssr_st_b_h">who can input results :</b>  Author , Administrator , Super Administrator</p>
<p class="ssr_p">you can have premium version of this plugin , which support 3 images , csv import system, 25 fields (without images), 1 extension ( Suppose you want to add students and teachers both ) , admin and user access , and more features</p>
<p class="ssr_p">for test premium version admin panel demo please visit <a target="_blank" href="http://ssr.saadamin.com/login">Here</a></p>
<p class="ssr_p">user : test</p>
<p class="ssr_p">pass : test</p>
<p class="ssr_p">Please contact with me if you found any bug or need more features <a href="mailto:saadvi@gmail.com">saadvi@gmail.com</a></p>
<p class="ssr_p">Ajax supported simple student result and display. apply [ssr_results] shortcode in a post/page for show results  , <a href="http://ssr.saadamin.com" target="_blank">Click here for demo</a></p>
<p class="ssr_p"><b>Get the premium version now <a href="//ssr.saadamin.com/product/ssr/">from this link</a>, after payment you will get the download link . for any problem you can email me saadvi@gmail.com or skype: saadbd2003 </b></p>
<p class="ssr_p">in this tutorial you will see how to install the plugin , use short code and insert result.</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/C8QjxJUKRMU" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">in this tutorial you will see how to edit records in ssr.</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/uJxLTSmGHkk" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">in this tutorial you will see how to delete a record</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/NoVvsJoKWPU" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">Do you know you can use the plugin for employee database or client database? please see this tutorial to know how you can do it.</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/ntzb7njqd_4" frameborder="0" allowfullscreen></iframe></p>
<p class="ssr_p">This is a premium feature , for premium version of the plugin please contact saadvi@gmail.com. you want to import records from other plugin/mysql database , lets see how you can do it</p>
<p class="ssr_p"><iframe width="532" height="325" src="https://www.youtube.com/embed/1GfMZhnyCqw" frameborder="0" allowfullscreen></iframe></p>
</div>
<?php } ?>