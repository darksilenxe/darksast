<?php
$input = $_GET['cmd'];
$data = 'secret';
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
eval($input);
md5($data);
