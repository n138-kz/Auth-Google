<?php session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
	'name' 	          => 'AUTHNKEY',
]);
header('Content-Type: text/plain');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PATCH, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Disposition, Content-Type, Content-Length, Accept-Encoding, Origin, Accept, Access-Control-Allow-Headers, Authorization, X-Requested-With");

$config = dirname(__FILE__) . '/' . '.env';
$config_loaded = false;
if ( file_exists($config) && filesize($config) > 0 ) {
	try {
		$config = json_decode(file_get_contents($config), true);
		$config_loaded = true;
	} catch (\Exception $e) {
		unset($config);
		$config_loaded = false;
	}
}

function is_empty($arg) {
	return ( !isset($arg) || empty($arg) );
}
function push2discord($endpoint, $content_author='Webhooks', $content_author_avatar='https://www.google.com/s2/favicons?size=256&domain=https://discord.com/', $content_color=0, $content_body=''){
	if ( is_empty( $endpoint ) ) { return false; }
	$content_color = is_numeric($content_color) ? $content_color : 0;
	$content_color = $content_color > 0 ? $content_color : 0;

	$payload = [];
	$payload += [
		'payload_json' => [
			'username' => $content_author,
			'content' => null,
			'avatar_url' => $content_author_avatar,
			'embeds' => [],
		]
	];
	$payload['payload_json']['embeds'] += [
		[
			'color' => $content_color,
			'timestamp' => date('c'),
			'footer' => [
				'text' => ''
			],
			'fields' => [
				'inline' => false,
				'name' => '',
				'value' => $content_body
			]
		]
	];
	$payload_encoded = json_encode($payload);
	$curl_req = curl_init($endpoint);
	curl_setopt($curl_req,CURLOPT_POST, TRUE);
	curl_setopt($curl_req,CURLOPT_POSTFIELDS, $payload_encoded);
	curl_setopt($curl_req,CURLOPT_SSL_VERIFYPEER, TRUE);
	curl_setopt($curl_req,CURLOPT_SSL_VERIFYHOST, TRUE);
	curl_setopt($curl_req,CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($curl_req,CURLOPT_FOLLOWLOCATION, TRUE);
	$curl_res=curl_exec($curl_req);
	$curl_res=json_decode($curl_res, TRUE);
	return $curl_res;
}
push2discord(
	$config['external']['discord']['uri'],
	$config['external']['discord']['color'],
	$config['external']['discord']['author'],
	'init',
);

$_SESSION = [];
$request = [];
$result = [];
$result['remote'] = $_SERVER['REMOTE_ADDR'] . ':' . $_SERVER['REMOTE_PORT'];
$result['client'] = [
	'address' => $_SERVER['REMOTE_ADDR'],
	'port' => $_SERVER['REMOTE_PORT'],
	'user' => ( isset($_SERVER['REMOTE_USER']) ? $_SERVER['REMOTE_USER'] : null ),
	'user_authed' => ( isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : null ),
	'user_redirected' => ( isset($_SERVER['REDIRECT_REMOTE_USER']) ? $_SERVER['REDIRECT_REMOTE_USER'] : null ),
	'content_type' => ( isset($_SERVER['CONTENT_TYPE']) ? explode(';', trim(strtolower($_SERVER['CONTENT_TYPE'])))[0] : null ),
	'user_agent' => $_SERVER['HTTP_USER_AGENT'],
];
$result['issue_at'] = microtime(TRUE);
$result['error']['code'] = 0;
$result['http']['code'] = http_response_code();
$result['http']['text'] = get_message_with_http_response_code($result['http']['code']);
$result['last_checkpoint'] = __LINE__;
$result['google'] = [
	'user' => [
		'userid' => '',
		'name' => '',
		'icon' => '',
	],
	'session' => [
		'iat' => 0,
		'exp' => 0,
	],
];
$result['authn'] = [
	'sessions' => [
		'id' => '',
		'name' => '',
	],
];

function get_message_with_http_response_code ($http) {
	switch ($http) {
		case 100: return '100 Continue';break;
		case 101: return '101 Switching Protocols';break;
		case 102: return '102 Processing';break;
		case 103: return '103 Early Hints';break;
		case 200: return '200 OK';break;
		case 201: return '201 Created';break;
		case 202: return '202 Accepted';break;
		case 203: return '203 Non-Authoritative Information';break;
		case 204: return '204 No Content';break;
		case 205: return '205 Reset Content';break;
		case 206: return '206 Partial Content';break;
		case 207: return '207 Multi-Status';break;
		case 208: return '208 Already Reported';break;
		case 226: return '226 IM Used';break;
		case 300: return '300 Multiple Choice';break;
		case 301: return '301 Moved Permanently';break;
		case 302: return '302 Found';break;
		case 303: return '303 See Other';break;
		case 304: return '304 Not Modified';break;
		case 305: return '305 Use Proxy';break;
		case 306: return '306 unused';break;
		case 307: return '307 Temporary Redirect';break;
		case 308: return '308 Permanent Redirect';break;
		case 400: return '400 Bad Request';break;
		case 401: return '401 Unauthorized';break;
		case 402: return '402 Payment Required Experimental';break;
		case 403: return '403 Forbidden';break;
		case 404: return '404 Not Found';break;
		case 405: return '405 Method Not Allowed';break;
		case 406: return '406 Not Acceptable';break;
		case 407: return '407 Proxy Authentication Required';break;
		case 408: return '408 Request Timeout';break;
		case 409: return '409 Conflict';break;
		case 410: return '410 Gone';break;
		case 411: return '411 Length Required';break;
		case 412: return '412 Precondition Failed';break;
		case 413: return '413 Payload Too Large';break;
		case 414: return '414 URI Too Long';break;
		case 415: return '415 Unsupported Media Type';break;
		case 416: return '416 Range Not Satisfiable';break;
		case 417: return '417 Expectation Failed';break;
		case 418: return '418 I\'m a teapot';break;
		case 421: return '421 Misdirected Request';break;
		case 422: return '422 Unprocessable Entity';break;
		case 423: return '423 Locked';break;
		case 424: return '424 Failed Dependency';break;
		case 425: return '425 Too Early Experimental';break;
		case 426: return '426 Upgrade Required';break;
		case 428: return '428 Precondition Required';break;
		case 429: return '429 Too Many Requests';break;
		case 431: return '431 Request Header Fields Too Large';break;
		case 451: return '451 Unavailable For Legal Reasons';break;
		case 500: return '500 Internal Server Error';break;
		case 501: return '501 Not Implemented';break;
		case 502: return '502 Bad Gateway';break;
		case 503: return '503 Service Unavailable';break;
		case 504: return '504 Gateway Timeout';break;
		case 505: return '505 HTTP Version Not Supported';break;
		case 506: return '506 Variant Also Negotiates';break;
		case 507: return '507 Insufficient Storage';break;
		case 508: return '508 Loop Detected';break;
		case 510: return '510 Not Extended';break;
		case 511: return '511 Network Authentication Required';break;
		default: break;
	}
}

function set_http_response_code ( $http ) {
	http_response_code( $http );
	global $result;
	$result['http']['code'] = $http;
	$result['http']['text'] = $_SERVER['SERVER_PROTOCOL'] . ' ' . get_message_with_http_response_code($http);
}

if( strtolower( $_SERVER['REQUEST_METHOD'] ) == 'options' ) {
	set_http_response_code(200);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(0);
}
if( strtolower( $_SERVER['REQUEST_METHOD'] ) != 'post' ) {
	set_http_response_code(405);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
/*# Is set? #*/
if( !isset( $_POST ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
if( !is_array( $_POST ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
$request = $_POST;
if( $result['client']['content_type'] == 'application/json' ) {
	/*
	 * @refs
	 * - [PHPにPOSTされたJSONをデータとして使用する方法](https://forsmile.jp/development/php/1709/)
	 * - [【PHP】JSONデータのPOST受け取りで application/x-www-form-urlencoded とapplication/json の両方に対応](https://qiita.com/Kunikata/items/2b410f3cc535e4104906)
	 * - [[php js]POST時、php ://inputの値が空文字になる](https://muchilog.com/php-input-json-empty/)
	 * 
	 */
	$request = file_get_contents('php://input');
	$request = json_decode($request, true);
	if( !is_array( $request ) ) {
		set_http_response_code(400);
		$result['issue_at'] = microtime(TRUE);
		$result['last_checkpoint'] = __LINE__;

		echo json_encode( $result );
		exit(1);
	}
}
if( !isset( $request['ts'] ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
if( !isset( $request['credential'] ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
if( !isset( $request['clientId'] ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
/*# Is correct? #*/
if( ( time() - (int)$request['ts'] > 300 ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}

define('CLIENT_ID', $request['clientId']);
define('CLIENT_TOKEN', $request['credential']);

try {
	require_once '../vendor/autoload.php';
	
	$client = new Google_Client(['client_id' => CLIENT_ID]);
	try {
		$payload = $client->verifyIdToken(CLIENT_TOKEN);
		if ($payload) {
			$result['google'] = [
				'user' => [
					'userid' => isset($payload['sub']) ? $payload['sub'] : null,
					'name' => isset($payload['name']) ? $payload['name'] : null,
					'icon' => isset($payload['picture']) ? $payload['picture'] : null,
					'email' => isset($payload['email']) ? $payload['email'] : null,
				],
				'session' => [
					'iat' => isset($payload['iat']) ? $payload['iat'] : 0,
					'exp' => isset($payload['exp']) ? $payload['exp'] : 0,
				],
			];
		}
	} catch (\Exception $th) {
		/* invalid token */
		$payload = false;

		set_http_response_code(401);
		$result['issue_at'] = microtime(TRUE);
		$result['last_checkpoint'] = __LINE__;

		echo json_encode( $result );
		exit(1);
	}

	if ( ( $result['google']['session']['iat'] == 0 ) || ( $result['google']['session']['exp'] == 0 ) ) {
		/* token has expired */
		$payload = false;

		set_http_response_code(401);
		$result['issue_at'] = microtime(TRUE);
		$result['last_checkpoint'] = __LINE__;

		echo json_encode( $result );
		exit(1);
	}

	$result['authn'] = [
		'sessions' => [
			'id' => session_id(),
			'name' => session_name(),
		],
	];
	
	set_http_response_code(200);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	$_SESSION = [ 'authn' => $result ];

	echo json_encode( $result );
	exit(0);
} catch (\Exception $th) {
	set_http_response_code(500);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	$th_json = [
		'code' => $th->getCode(),
		'message' => $th->getMessage(),
		'file' => $th->getFile(),
		'line' => $th->getLine(),
		'trace' => $th->getTrace(),
	];

	$encrypt = [
		'method' => 'AES-256-CBC',
		'iv_length' => 0,
		'iv' => null,
		'option' => 0,
		'encrypted' => null,
		'decrypted' => null,
	];
	$encrypt['iv_length'] = openssl_cipher_iv_length($encrypt['method']);
	$encrypt['iv'] = openssl_random_pseudo_bytes($encrypt['iv_length']);
	$encrypt['option'] = 0;
	$encrypt['encrypted'] = openssl_encrypt( json_encode($th_json), $encrypt['method'], 'passw0rd', $encrypt['option'], $encrypt['iv'] );
	$result['exception_text'] = json_encode($encrypt);
	$encrypt['decrypted'] = openssl_decrypt( $encrypt['encrypted'], $encrypt['method'], 'passw0rd', $encrypt['option'], $encrypt['iv'] );

	error_log($th->getTraceAsString());

	echo json_encode( $result );
	exit(0);
}
