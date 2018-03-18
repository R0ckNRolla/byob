 <?php

function obfuscate_key($data) {
	$prime = array();
	$block = dechex(rand(0,15)) . dechex(rand(0,15));
	for ($i=2; strlen($data)>0; $i++) {
		$is_mul = false;
		foreach ($prime as $p) {
			if ($i % $p === 0) {
				$is_mul = true;
				$block .= dechex(rand(0,15));
				break;
			}
		}
		if ($is_mul === false) {
			array_push($prime, $i);
			$block .= $data[0];
			$data = substr($data, 1);
		}
	}
	if ((strlen($block) % 2 === 0) === false) {
		$block .= dechex(rand(0,15));
	}
	return base64_encode($block);
}

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
	return $hex;
}

function diffiehellman($public_b) {
	$generator = gmp_init('0x2');
	$modulus   = gmp_init('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
	$private_a = gmp_init('0x' . bin2hex(openssl_random_pseudo_bytes(32)));
	$public_a  = bcpowmod($generator, $private_a, $modulus);
	echo $public_a;
	$public_b  = gmp_init($public_b);
	$session   = gmp_init(bcpowmod($public_b, $private_a, $modulus));
//	echo "DB Private:\n" . $private_a . "\nDB Public:\n" . $public_a . "\nServer Public:\n" . $public_b . "\nShared Secret:\n" . $session;
	return hash('sha256', $session, false);
}


try {
	extract($_POST);
	if (!isset($id)) {
		die("Error: unauthorized request");
	}
	$server		= '0000000000000000000000000000000000000000000000000000000000000000';
	$session_id	= ($id !== $server) ? hash('sha256', $id . $_SERVER['REQUEST_TIME'], false): $id;
	echo $session_id;
	$connection	= mysqli_connect("server227.web-hosting.com","snappwfm_gmail", "8mtV2tatEf7", "snappwfm_gmail");
	if ($connection === false) {
		die("Error: connection failed: " . mysqli_connect_error());
	}
	if ((isset($public_key)) && ($id == $server)) {
		$session_key = diffiehellman($public_key);
	}		
	if ($exists	 = mysqli_query($connection, "SELECT * FROM sessions WHERE client='".$id."'")) {
		$session = 0;
		if (mysqli_num_rows($exists) > 0) {
			while ($row = mysqli_fetch_assoc($exists)) {
				$n = (int) $row['session'];
				if ($n > $session) {
					$session = (int) $row['session'];
				}
			}
			$session = $session + 1;
			if ($id == $server) {
				mysqli_query($connection, "UPDATE sessions SET session=".$session.", session_key='".$session_key."' WHERE client='".$id."'");
			} else {
				mysqli_query($connection, "UPDATE sessions SET id='".$session_id."', session=".$session." WHERE client='".$id."' AND session=0");
			}
		} else {
			$session = $session + 1;
			if ($id == $server) {
				mysqli_query($connection, "INSERT INTO sessions(id, client, session, session_key) VALUES ('".$session_id."', '".$id."', ".$session.", '".$session_key."')");
			} else {
				mysqli_query($connection, "INSERT INTO sessions(id, client, session) VALUES ('".$session_id."', '".$id."', ".$session.")");
			}
		}
	} 
} catch (Exception $e) {
	file_put_contents('error_log', $e);
}

?>
