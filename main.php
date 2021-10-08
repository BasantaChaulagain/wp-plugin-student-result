<?php
/* 
In the db, form_value should be unserialized php array with 'cfdb7_status' as key and "read/unread" as value.
*/

//user input area
$_GET['fid'] = 4;
$_GET['ufid'] = 4;

$_REQUEST['action'] = "unread";
$_POST['contact_form'] = ['form_id'=>"4"];

$_REQUEST['fid'] = 0;
$_REQUEST['wpforms-csv'] = "";
$_REQUEST['nonce'] = 'dnonce';

//include fake_wp
include "fake_wp.php";

//include target function
include "./database-for-wpforms/inc/class-form-details.php";

//triger target function
