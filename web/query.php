<?php

/*	

Copyright (c) 2017 Angry Eggplant (https://github.com/colental/ae)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. 

    

    ,adPPYYba, 8b,dPPYba,   ,adPPYb,d8 88,dPPYba,   aa       aa
    ""     `Y8 88P'   `"8a a8"    `Y88 88P'   `"8a  88       88
    ,adPPPPP88 88       88 8b       88 88           8b       88
    88,    ,88 88       88 "8a,   ,d88 88           "8a,   ,d88
    `"8bbdP"Y8 88       88  `"YbbdP"Y8 88            `"YbbdP"Y8
                            aa,    ,88               aa,    ,88
                             "Y8bbdP"                 "Y8bbdP'

                                                    88                          ,d
                                                    88                          88
     ,adPPYba,  ,adPPYb,d8  ,adPPYb,d8 8b,dPPYba,   88 ,adPPYYba, 8b,dPPYba,    88
    a8P     88 a8"    `Y88 a8"    `Y88 88P'    "8a  88 ""     `Y8 88P'   `"8a MM88MMM
    8PP8888888 8b       88 8b       88 88       d8  88 ,adPPPPP88 88       88   88
    "8b,   ,aa "8a,   ,d88 "8a,   ,d88 88b,   ,a8"  88 88,    ,88 88       88   88
     `"Ybbd8"'  `"YbbdP"Y8  `"YbbdP"Y8 88`YbbdP"'   88 `"8bbdP"Y8 88       88   88,
                aa,    ,88  aa,    ,88 88                                       "Y888
                 "Y8bbdP"    "Y8bbdP"  88


*/

function deobfuscate_key($data) {
	$prime = array();
	$data = base64_decode($data);
	$hex = '';
	for ($i=2; $i<=strlen($data); $i++) {
		$is_mul = false;
		foreach ($prime as $p) {
			if ($i % $p === 0) {
				$is_mul = true;
				break;
			}
		}
		if ($is_mul === false) {
			array_push($prime, $i);
		}
	}
	foreach ($prime as $p) {
		$hex .= $data[$p];
	}
	if ((strlen($hex) % 2 === 0) === false)  {
		$hex .= hexdec(rand(0,15));
	}
	return hex2bin($hex);
}

function encrypt($text, $dhkey) {
	$aes_key = substr($dhkey, 0, 32);
	$hmac_key = substr($dhkey, 32, 64);
	$block_size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
	$pad = $block_size - (strlen($text) % $block_size);
	$text .= str_repeat(chr('\x00'), $pad);
	$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
	$iv = mcrypt_create_iv($iv_size,MCRYPT_DEV_URANDOM);
	$crypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $aes_key, $text, MCRYPT_MODE_CBC, $iv);
	$hmac = hash_hmac('sha256', $iv.$crypt, $hmac_key, true);
	$output = base64_encode($iv.$crypt.$hmac);
	return $output;
}
 
function decrypt($data, $dhkey) {
	$aes_key = substr($dhkey, 0, 32);
	$hmac_key = substr($dhkey, 32, 64);
	$raw = base64_decode($data);
	$length = strlen($raw);
	$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
	$iv = substr($raw, 0, $iv_size);
	$hmac_size = strlen(hash('sha256', NULL, true));
	$check_hmac = substr($raw, -$hmac_size);
	$crypt = substr($raw, $iv_size, -$hmac_size);
	$calc_hmac = hash_hmac('sha256', $iv.$crypt, $hmac_key, true);
	$text = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $aes_key, $crypt, MCRYPT_MODE_CBC, $iv);
	$output	= rtrim($text);
	if ($check_hmac !== $calc_hmac) {
		file_put_contents('error_log', "HMAC-SHA256 authentication failed: message contains ".bin2hex($check_hmac).", should contain ".bin2hex($calc_hmac)."\n\n");
	}
	return $output;
}	

function diffiehellman($public_b) {
	$generator = gmp_init('0x2');
	$modulus   = gmp_init('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
	$private_a = gmp_init('0x' . bin2hex(openssl_random_pseudo_bytes(32)));
	$public_a  = bcpowmod($generator, $private_a, $modulus);
	echo $public_a;
	$public_b  = gmp_init($public_b);
	$session   = gmp_init(bcpowmod($public_b, $private_a, $modulus));
	return hash('sha256', $session, false);
}

function array2json($row) {
	if (count($row) === 1) {
		foreach($row as $key => $value) {
			$results = $value;
		}
	} else {
		$results = '{';
		foreach ($row as $key => $value) {
			$results .= '"' . $key.'": "'.$value.'",';
		}
	}
	$results = rtrim($results, ",");
	$results .= '}';
	return $results;
}

// main

try {
	if (($_SERVER['REQUEST_METHOD'] == 'POSTGET') || ($_SERVER['REQUEST_METHOD'] == 'POST')) {
		extract($_POST);
		if (isset($query)) {
			$conn = mysqli_connect("server227.web-hosting.com","snappwfm_gmail", "8mtV2tatEf7", "snappwfm_gmail");
			$sql = "SELECT * FROM sessions WHERE id='0000000000000000000000000000000000000000000000000000000000000000'";
			if ($req  = mysqli_query($conn, $sql)) {
				if (mysqli_num_rows($req) > 0) {
					$row = mysqli_fetch_assoc($req);
					$session_key = $row['session_key'];
					$query 	= decrypt($query, $session_key); 
					if ($output = mysqli_query($conn, $query)) {
						if (mysqli_num_rows($output) > 0) {
							$result	= '';
							while ($row = mysqli_fetch_assoc($output)) {
								if (count($row) > 1) {
									$result .= json_encode($row) . "\n";
								}
							}
							echo encrypt($result, $session_key);
						} 
					} 
				} 
			} 
		}
	}
} catch (Exception $e) {
	file_put_contents('error_log', $e);
}
?>
