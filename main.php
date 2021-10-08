<?php
/* 
In the db, form_value should be unserialized php array with 'cfdb7_status' as key and "read/unread" as value.
*/

//user input area
$_POST = [
    "rid" => "4",
    "rn" => "21cs45",
    "stn" => "Jill Ma",
    "stfn" => "Peter Ma",
    "stpy" => "2021",
    "stcgpa" => "A+",
    "stsub" => "cs",
    "stpy3" => "Female",
    "stpy4" => "Athens"
];

$_POST['rid'] = "4";


//include fake_wp
include "fake_wp.php";

//include target function
include "./simple-student-result/index.php";

//triger target function
ssr_plugin_install();

fn_ssr_add_st_submit();
fn_ssr_del_st_submit();
