<?php 
$log_file_path = './log.txt';
$blackIp = ['127.0.0.1'];
/**
 * [access 日志记录模块]
 * @return [type] [description]
 */
function access(){
	global $log_file_path;

	if($_FILES!=[]){
		$tmp = [];
		foreach ($_FILES as $key => $value) {
			array_push($tmp,["filename"=>$_FILES[$key]["name"],"contents"=>base64_encode(file_get_contents($_FILES[$key]["tmp_name"]))]);
		}
		$flow = array(
		'Userip'=>$_SERVER['REMOTE_ADDR'],
		'Path' =>'http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"],
		'Post'=>$_POST,
		"File"=>$tmp,
		'Cookie'=>$_COOKIE,
		'Time'=> date('Y-m-s h:i:s',time())
		);
	}else{
		$flow = array(
		'Userip'=>$_SERVER['REMOTE_ADDR'],
		'Path' =>'http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"],
		'Post'=>$_POST,
		'Cookie'=>$_COOKIE,
		'Time'=> date('Y-m-s h:i:s',time())
		);
	}
	$log_path = $log_file_path;
	$f = fopen($log_path,'a');
	fwrite($f,"\n".json_encode($flow,true));
	fclose($f);
}
/**
 * [banIP IP封禁模块]
 * @return [type] [description]
 */
function banIP(){
	global $blackIp;
	if(is_file('black.txt')){
		$blackIp = array_filter(explode("\n",file_get_contents('black.txt')));
	}
	$userIP = $_SERVER['REMOTE_ADDR'];
	$_not_found = <<<END
<!DOCTYPE html PUBLIC '-//IETF//DTD HTML 2.0//EN'>
<html><head>
<meta http-equiv='content-type' content='text/html; charset=windows-1252'>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL / was not found on this server.</p>
</body>
</html>
END;
	if(in_array($userIP,$blackIp)){
		$staus_code = "HTTP/1.1 404 Not Found";
		header($staus_code);
		die($_not_found);
	}
}
access();
banIP();

?>