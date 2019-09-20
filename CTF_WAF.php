<?php
/**CTF—**/
error_reporting(0);
class CTF_WAF{
	public $getfilter;
	public $postfilter;
	public $cookiefilter;
	public $orther;
	public $url;
	public $dir;
	public $ip;
	public $Waf_switch;
	public $resultPage;
	public function __construct() {
		 $this->getfilter = "\\<.+javascript:window\\[.{1}\\\\x|<.*=(&#\\d+?;?)+?>|<.*(data|src)=data:text\\/html.*>|\\b(alert\\(|confirm\\(|expression\\(|prompt\\(|benchmark\s*?\(.*\)|sleep\s*?\(.*\)|\\b(group_)?concat[\\s\\/\\*]*?\\([^\\)]+?\\)|\bcase[\s\/\*]*?when[\s\/\*]*?\([^\)]+?\)|load_file\s*?\\()|<[a-z]+?\\b[^>]*?\\bon([a-z]{4,})\s*?=|^\\+\\/v(8|9)|\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.*\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT\s*(\(.+\)\s*|@{1,2}.+?\s*|\s+?.+?|(`|'|\").*?(`|'|\")\s*)|UPDATE\s*(\(.+\)\s*|@{1,2}.+?\s*|\s+?.+?|(`|'|\").*?(`|'|\")\s*)SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE)@{0,2}(\\(.+\\)|\\s+?.+?\\s+?|(`|'|\").*?(`|'|\"))FROM(\\(.+\\)|\\s+?.+?|(`|'|\").*?(`|'|\"))|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|<.*(iframe|frame|style|embed|object|frameset|meta|xml|a|img)|hacker";
		//post拦截规则
		$this->postfilter = "<.*=(&#\\d+?;?)+?>|<.*data=data:text\\/html.*>|\\b(alert\\(|confirm\\(|expression\\(|prompt\\(|benchmark\s*?\(.*\)|sleep\s*?\(.*\)|\\b(group_)?concat[\\s\\/\\*]*?\\([^\\)]+?\\)|\bcase[\s\/\*]*?when[\s\/\*]*?\([^\)]+?\)|load_file\s*?\\()|<[^>]*?\\b(onerror|onmousemove|onload|onclick|onmouseover)\\b|\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.*\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT\s*(\(.+\)\s*|@{1,2}.+?\s*|\s+?.+?|(`|'|\").*?(`|'|\")\s*)|UPDATE\s*(\(.+\)\s*|@{1,2}.+?\s*|\s+?.+?|(`|'|\").*?(`|'|\")\s*)SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE)(\\(.+\\)|\\s+?.+?\\s+?|(`|'|\").*?(`|'|\"))FROM(\\(.+\\)|\\s+?.+?|(`|'|\").*?(`|'|\"))|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|<.*(iframe|frame|style|embed|object|frameset|meta|xml|a|img)|hacker";
		//cookie拦截规则
		$this->cookiefilter = "benchmark\s*?\(.*\)|sleep\s*?\(.*\)|load_file\s*?\\(|\\b(and|or)\\b\\s*?([\\(\\)'\"\\d]+?=[\\(\\)'\"\\d]+?|[\\(\\)'\"a-zA-Z]+?=[\\(\\)'\"a-zA-Z]+?|>|<|\s+?[\\w]+?\\s+?\\bin\\b\\s*?\(|\\blike\\b\\s+?[\"'])|\\/\\*.*\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT\s*(\(.+\)\s*|@{1,2}.+?\s*|\s+?.+?|(`|'|\").*?(`|'|\")\s*)|UPDATE\s*(\(.+\)\s*|@{1,2}.+?\s*|\s+?.+?|(`|'|\").*?(`|'|\")\s*)SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE)@{0,2}(\\(.+\\)|\\s+?.+?\\s+?|(`|'|\").*?(`|'|\"))FROM(\\(.+\\)|\\s+?.+?|(`|'|\").*?(`|'|\"))|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)";
		//其他拦截规则
		$this->orther ="eval\(.*\)|phpinfo\(\)|assert\(.*\)|\`|\~|\^|<\?php|[oc]:\d+:|pcntl_alarm|pcntl_fork|pcntl_waitpid|pcntl_wait|pcntl_wifexited|pcntl_wifstopped|pcntl_wifsignaled|pcntl_wifcontinued|pcntl_wexitstatus|pcntl_wtermsig|pcntl_wstopsig|pcntl_signal|pcntl_signal_get_handler|pcntl_signal_dispatch|pcntl_get_last_error|pcntl_strerror|pcntl_sigprocmask|pcntl_sigwaitinfo|pcntl_sigtimedwait|pcntl_exec|pcntl_getpriority|pcntl_setpriority|pcntl_async_signals|system\(.*\)|exec\(.*\)|shell_exec\(.*\)|popen\(.*\)|proc_open\(.*\)|passthru\(.*\)|symlink\(.*\)|link\(.*\)|syslog\(.*\)|imap_open\(.*\)|flag|cat\s|etc\spasswd|IFS|display_errors|catch|ini_set|set_time_limit(0)";

		$this->url = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
		$this->dir = $_SERVER['DOCUMENT_ROOT'].'/'.'waflog/';
		$this->ip = [];
		$this->read_ip();
		$this->resultPage="http://127.0.0.1/";//返回页面
		$this->Waf_switch=0;//WAF开关1开启，0关闭

	}

	public function Flux($Value,$style){
				switch ($style) {
					case 'post':
						if(is_array($Value)){
							$Value = http_build_query($Value);
						}
						$this->data_to_file("{\"url\":\"".$this->url."\",\"value\":"."\"".$Value."\",\"style\":\"Post\",\"time\":\"".time()."\"}\r\n","logs.txt",'post');
						$this->Check_Flux($Value, $this->postfilter);
						$this->Check_Flux($Value, $this->orther);
						break;
					case 'get':
						if(is_array($Value)){
							$Value =  http_build_query($Value);
						}
						$this->data_to_file("{\"url\":\"".$this->url."\",\"value\":"."\"".$Value."\",\"style\":\"Get\",\"time\":\"".time()."\"}\r\n","logs.txt",'get');
						$this->Check_Flux($Value, $this->getfilter);
						$this->Check_Flux($Value, $this->orther);
						break;
					default:
						if(is_array($Value)){
							$Value = http_build_query($Value);
						}
						$this->data_to_file("{\"url\":\"".$this->url."\",\"value\":"."\"".$Value."\",\"style\":\"Cookie\",\"time\":\"".time()."\"}\r\n","logs.txt",'cookie');
						$this->Check_Flux($Value, $this->cookiefilter);
						$this->Check_Flux($Value, $this->orther);
						break;
				}			
			}
	public function read_ip(){
		if(!file_exists($this->dir."ip.txt")){
			file_put_contents($this->dir."ip.txt", "");
		}
		$file = fopen($this->dir."ip.txt", "r") or exit("");
		while(!feof($file))
		{
		 array_push($this->ip, trim(fgets($file)));
		}
		fclose($file);
	}	

	public function Check_Flux($Value,$ArrFiltReq){

		if($this->Waf_switch==1){
			if(is_array($Value)){
			$Value=implode($Value);
			}
			$Value=urldecode($Value);	
			if (preg_match("/".$ArrFiltReq."/is",$Value)==1){
			die(file_get_contents($this->resultPage));
			}

		}
		}

	public function Request_Post($data,$url){
		if(is_array($data)){
				$query = http_build_query($data); //使用给出的关联（或下标）数组生成一个经过 URL-encode 的请求字符串。
			}else{
				$query = $data;
			}
		$options['http'] = array(
	     'timeout'=>60,
	     'method' => 'POST',
	     'header' => 'Content-type:application/x-www-form-urlencoded',
	     'content' => $query
	    );//构造一个post包
		//vardump($options['http'] );_
		$context = stream_context_create($options);//创建并返回一个资源流上下文
		$result = file_get_contents($url, false, $context);
		return $result; 
	}

	public function Request_Get($url){
		$result=[];
		$result['content'] = file_get_contents($url);
		preg_match_all('/\/\/(.*?)\//', $url, $ip);
		$result['ip'] = $ip[1][0];
		return $result; 
	}

	public function Get_Flag($result){
		//var_dump($result);
		if(stristr($result['content'],'flag')){
		   preg_match_all('/flag{(.*?)}/', $result['content'],$flag);
		   if(!empty($flag[0][0])){
		   	  $this->data_to_file("{$result['ip']}\t| ".$flag[0][0]."\r\n","flag.txt",'flag');
		   }
		  
		}
	}

	public function data_to_file($data,$filename,$style=''){
		if(is_array($data)){
			$data = implode($data);
		}
		switch ($style) {
			case 'post':
				if(!stristr(file_get_contents($this->dir.$filename),$data)){
					
					if(file_exists($this->dir.$filename)){
						file_put_contents($this->dir.$filename,"".$data,FILE_APPEND);	
					}else{
						file_put_contents($this->dir.$filename,$data,FILE_APPEND);
					}
					for($i=0;$i<count($this->ip);$i++){
						$this->Get_Flag($this->Request_Post(json_decode(str_replace("\r\n","",$data),true)['value'],'http://'.$this->ip[$i].'/'));
					}
				}
				break;
			case 'get':
			 $js_data = $data;
				if(!stristr(file_get_contents($this->dir.$filename),str_replace('http://'.$_SERVER['HTTP_HOST'], '', $data))){
					file_put_contents($this->dir.$filename, $js_data ,FILE_APPEND);
					for($i=0;$i<count($this->ip);$i++){
						 $data=str_replace($_SERVER['HTTP_HOST'],$this->ip[$i],json_decode(str_replace("\r\n","",$data),true)['url']);
						$this->Get_Flag($this->Request_Get($data));
						$data=$js_data ;
					}
				}
				break;
			case 'cookie':
				if(!stristr(file_get_contents($this->dir.$filename),$data)){
					if(file_exists($this->dir.$filename)){
						file_put_contents($this->dir.$filename,"".$data,FILE_APPEND);	
					}else{
						file_put_contents($this->dir.$filename,$data,FILE_APPEND);
					}
				}
				break;
			case 'flag':
				if(!stristr(file_get_contents($this->dir.$filename),$data)){
					file_put_contents($this->dir.$filename,$data,FILE_APPEND);
				}
				break;
		}
	}
}


/*******************************/
/*         调用WAF            */

$waf = new  CTF_WAF();

if(isset($_GET)){
	$waf->Flux($_GET,'get');
}

if(isset($_POST)){
	$waf->Flux($_POST,'post');
}

if(isset($_COOKIE)){
	$waf->Flux($_COOKIE,'cookie');
}