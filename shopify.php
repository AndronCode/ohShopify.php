<?php
class ShopifyClient {
	public $shop_domain;
	public $token;
	private $api_key;
	private $secret;
	private $last_response_headers = null;
	public  $debug;

	public function __construct($shop_domain, $api_key,  $secret, $token = null) {
		$this->name = "ShopifyClient";

		// make simple check ;
		$this->shop_domain = $shop_domain;
		$this->token = $token;
		$this->api_key = $api_key;
		$this->secret = $secret;
		$this->debug  = false;
	}

	// Get the URL required to request authorization
	public function getAuthorizeUrl($scope, $redirect_url='') {
		$url = "https://{$this->shop_domain}/admin/oauth/authorize?client_id={$this->api_key}&scope=" . urlencode($scope); 
		if ($redirect_url != '')
		{
			$url .= "&redirect_uri=" . urlencode($redirect_url);
		}
		return $url;
	}

	// Once the User has authorized the app, call this with the code to get the access token
	public function getAccessToken($code) {
		// POST to  POST https://SHOP_NAME.myshopify.com/admin/oauth/access_token
		$url = "https://{$this->shop_domain}/admin/oauth/access_token";
		$payload = "client_id={$this->api_key}&client_secret={$this->secret}&code={$code}";
		echo "Payload :". $payload;  // New
		$response = $this->curlHttpApiRequest('POST', $url, '', $payload, array());
		$response = json_decode($response, true);
		echo "<p>Accees Token fron Shopify client:" . var_dump($response). "</p>";
		if (isset($response['access_token']))
			return $response['access_token'];
		return '';
	}

	public function callsMade()
	{
		return $this->shopApiCallLimitParam(0);
	}

	public function callLimit()
	{
		return $this->shopApiCallLimitParam(1);
	}

	public function callsLeft()
	{
		return $this->callLimit() - $this->callsMade();
	}

	// NEW!! $params is json format;
	/**
	 * 
	 * return Associiated array
	 */
	public function call($method, $path, $params="")
	{
		$baseurl = "https://{$this->shop_domain}/";
	
		$url = $baseurl.ltrim($path, '/');
		$query = in_array($method, array('GET','DELETE')) ? $params : "";
		$payload = in_array($method, array('POST','PUT')) ? $params : "";
		$request_headers = in_array($method, array('POST','PUT')) ? array("Content-Type: application/json; charset=utf-8", 'Expect: application/json') : array();

		// add auth headers
		$request_headers[] = 'X-Shopify-Access-Token: ' . $this->token;

		if($this->debug)
			{
				echo "<h5> Payload: ". $payload. " and query: ".$query ."</h5>";
				foreach($request_headers as $header)
					{
						echo "<h5> Header is: ".$header . " </h5>";
					}
			}

		$response = $this->curlHttpApiRequest($method, $url, $query, $payload, $request_headers);
		$response = json_decode($response, true);

		if (isset($response['errors']) or ($this->last_response_headers['http_status_code'] >= 400))
			throw new ShopifyApiException($method, $path, $params, $this->last_response_headers, $response);

		return (is_array($response) and (count($response) > 0)) ? array_shift($response) : $response;
	}

	// New method to cal GraphQL (October 2019)

	


	public function validateSignature($query)
	{
		if(!is_array($query) || empty($query['hmac']) || !is_string($query['hmac']))
			return false;

		$dataString = array();
		foreach ($query as $key => $value) {
			if(!in_array($key, array('shop', 'timestamp', 'code'))) continue;

			$key = str_replace('=', '%3D', $key);
			$key = str_replace('&', '%26', $key);
			$key = str_replace('%', '%25', $key);

			$value = str_replace('&', '%26', $value);
			$value = str_replace('%', '%25', $value);

			$dataString[] = $key . '=' . $value;
		}
		sort($dataString);
		
		$string = implode("&", $dataString);

		$signatureBin = mhash(MHASH_SHA256, $string, $this->secret);
		$signature = bin2hex($signatureBin);
		
		return $query['hmac'] == $signature;
	}

	private function curlHttpApiRequest($method, $url, $query='', $payload='', $request_headers=array())
	{
		$url = $this->curlAppendQuery($url, $query);
		if ($this->debug)
			echo "</br> URL is : ". $url;
		$ch = curl_init($url);
		$this->curlSetopts($ch, $method, $payload, $request_headers);
		$response = curl_exec($ch);
		// new to get array of info ;
		if ($this->debug)
		{
			foreach (curl_getinfo($ch)  as $k => $value)
				{
					echo "<p> ". $k ." value is ". $value. "</p>";
				}
		}
			
		$errno = curl_errno($ch);
		$error = curl_error($ch);
		curl_close($ch);

		if ($errno) throw new ShopifyCurlException($error, $errno);
		list($message_headers, $message_body) = preg_split("/\r\n\r\n|\n\n|\r\r/", $response, 2);
		$this->last_response_headers = $this->curlParseHeaders($message_headers);

		return $message_body;
	}

	private function curlAppendQuery($url, $query)
	{
		if (empty($query)) return $url;
		if (is_array($query)) return "$url?".http_build_query($query);
		else return "$url?$query";
	}

	private function curlSetopts($ch, $method, $payload, $request_headers)
	{
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // Modifed to not get issue certificate;
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);  // was 2 -  check the existence of a common name and also verify that it matches the hostname provided
		curl_setopt($ch, CURLOPT_USERAGENT, 'ohShopify-php-api-client');
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($ch, CURLOPT_TIMEOUT, 30);

		curl_setopt ($ch, CURLOPT_CUSTOMREQUEST, $method);
		if (!empty($request_headers)) curl_setopt($ch, CURLOPT_HTTPHEADER, $request_headers);
		
		if ($method != 'GET' && !empty($payload))
		{
			if (is_array($payload))
			 $payload = http_build_query($payload);
			echo "Payload from Shopify client: ";
			var_dump($payload);
			curl_setopt ($ch, CURLOPT_POSTFIELDS, $payload);
		}
	}

	private function curlParseHeaders($message_headers)
	{
		$header_lines = preg_split("/\r\n|\n|\r/", $message_headers);
		$headers = array();
		list(, $headers['http_status_code'], $headers['http_status_message']) = explode(' ', trim(array_shift($header_lines)), 3);
		foreach ($header_lines as $header_line)
		{
			list($name, $value) = explode(':', $header_line, 2);
			$name = strtolower($name);
			$headers[$name] = trim($value);
		}

		return $headers;
	}
	
	private function shopApiCallLimitParam($index)
	{
		if ($this->last_response_headers == null)
		{
			throw new Exception('Cannot be called before an API call.');
		}
		$params = explode('/', $this->last_response_headers['http_x_shopify_shop_api_call_limit']);
		return (int) $params[$index];
	}	
}

class ShopifyCurlException extends Exception { }
class ShopifyApiException extends Exception
{
	protected $method;
	protected $path;
	protected $params;
	protected $response_headers;
	protected $response;
	
	function __construct($method, $path, $params, $response_headers, $response)
	{
		$this->method = $method;
		$this->path = $path;
		$this->params = $params;
		$this->response_headers = $response_headers;
		$this->response = $response;
		
		parent::__construct($response_headers['http_status_message'], $response_headers['http_status_code']);
	}

	function getMethod() { return $this->method; }
	function getPath() { return $this->path; }
	function getParams() { return $this->params; }
	function getResponseHeaders() { return $this->response_headers; }
	function getResponse() { return $this->response; }
}
?>
