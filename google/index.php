<?php session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
	'name' 	          => 'AUTHNKEY',
]);
date_default_timezone_set('Asia/Tokyo');
header('Content-Type: text/plain');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PATCH, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Disposition, Content-Type, Content-Length, Accept-Encoding, Origin, Accept, Access-Control-Allow-Headers, Authorization, X-Requested-With");
header('X-Powered-By: Hidden');
header_register_callback(function(){ header_remove('X-Powered-By'); });

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
		'username' => $content_author,
		'content' => chr(0),
		'avatar_url' => $content_author_avatar,
		'embeds' => [],
	];
	array_push($payload['embeds'], [
		'color' => $content_color,
		'timestamp' => date('c'),
		'footer' => [
			'text' => 'Auth-Google'
		],
		'fields' => [
			[
				'inline' => false,
				'name' => '',
				'value' => $content_body
			]
		]
	]);
	$payload_encoded = json_encode($payload);
	$curl_req = curl_init($endpoint);
	curl_setopt($curl_req,CURLOPT_POST, TRUE);
	curl_setopt($curl_req,CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
	curl_setopt($curl_req,CURLOPT_POSTFIELDS, $payload_encoded);
	curl_setopt($curl_req,CURLOPT_SSL_VERIFYPEER, TRUE);
	curl_setopt($curl_req,CURLOPT_SSL_VERIFYHOST, 2);
	curl_setopt($curl_req,CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($curl_req,CURLOPT_FOLLOWLOCATION, TRUE);
	$curl_res=curl_exec($curl_req);
	$curl_res=json_decode($curl_res, TRUE);
	return $curl_res;
}

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
	'user_agent' => ( isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '' ),
	'referer' => ( isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '' ),
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

	$_SESSION = [
		'authn' => $result,
		'credential' => [
			'authnaddr' => $result['client']['address'],
			'clientId' => CLIENT_ID,
			'client_id' => CLIENT_ID,
			'client_token' => CLIENT_TOKEN,
			'credential' => CLIENT_TOKEN,
			'credential' => CLIENT_TOKEN,
			'token' => CLIENT_TOKEN,
		],
	];
	$headers_list = [];
	foreach (headers_list() as $key => $val) {
		$split = explode(':', $val, 2);
		$headers_list[trim($split[0])] = trim($split[1]);
	}
	$result['variable'] = [
		'_session' => $_SESSION,
		'_server'  => $_SERVER,
		'_cookie'  => $_COOKIE,
		'_headers' => [
			'request' => apache_request_headers(),
			'response' => $headers_list,
		],
	];
	unset($headers_list);

	if ($config_loaded) {
		if ($config['internal']['databases']['activate'] && $config['internal']['databases']['primary']['activate']) {
			$dsn = [
				'scheme' => $config['internal']['databases']['primary']['scheme'],
				'host' => $config['internal']['databases']['primary']['host'],
				'port' => $config['internal']['databases']['primary']['port'],
				'dbname' => $config['internal']['databases']['primary']['dbname'],
				'username' => $config['internal']['databases']['primary']['username'],
				'password' => $config['internal']['databases']['primary']['password'],
			];
			try {
				$pdo = new \PDO(
					''.$dsn['scheme'].':'.
					'host='.$dsn['host'].';'.
					'port='.$dsn['port'].';'.
					'dbname='.$dsn['dbname'].';'.
					'user='.$dsn['username'].';'.
					'password='.$dsn['password'].''.
					''
				);
				$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				$pdo->setAttribute(PDO::ATTR_TIMEOUT, 10);
				$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

				/* ADD TABLE IF NOT EXISTS */
				foreach ($config['internal']['databases']['tables'] as $scheme_key => $scheme_val) {
					$pdo->beginTransaction();
					foreach ($config['internal']['databases']['tables'][$scheme_key] as $tables_key => $tables_val) {
						$sql = 'CREATE TABLE IF NOT EXISTS ' . $scheme_key . '.' . $tables_key . ' ' . '';
						$sql .= '(';
						foreach ($config['internal']['databases']['tables'][$scheme_key][$tables_key]['column'] as $columns_key => $columns_val) {
							$sql_columns = $columns_key;
							foreach ($config['internal']['databases']['tables'][$scheme_key][$tables_key]['column'][$columns_key] as $attr_key => $attr_val) {
								$sql_columns .= ' ';
								$sql_columns .= $attr_val;
							}
							$sql_columns .= ',';
							$sql .= $sql_columns;
						}
						$sql .= ')';
						$sql = str_replace(',)', ')', $sql);
						$pdo->query($sql);
					}
					$pdo->commit();
				}

				/* ADD VALUE TO TABLE IF NOT EXISTS */
				$sql = 'SELECT COUNT(id) AS COUNT FROM public.authgoogle_userinfo WHERE id=?';
				$pdo_prepare = $pdo->prepare($sql);
				$pdo_result = $pdo_prepare->execute([ $result['google']['user']['userid'] ]);
				$pdo_result = $pdo_prepare->fetch(PDO::FETCH_ASSOC);
				if ($pdo_result['count'] === 0) {
					/* New user */
					$sql = 'INSERT INTO public.authgoogle_userinfo (';
					$sql .= 'id, name, email, icon, regat, regip, reguseragent, lastat, lastip, lastuseragent';
					$sql .= ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_result = $pdo_prepare->execute([
						$result['google']['user']['userid'],
						$result['google']['user']['name'],
						$result['google']['user']['email'],
						$result['google']['user']['icon'],
						time(),
						$result['client']['address'],
						$result['client']['user_agent'],
						time(),
						$result['client']['address'],
						$result['client']['user_agent'],
					]);
					if (!!$pdo_result) {
						if ($config['external']['discord']['activate']['notice']) {
							push2discord(
								$config['external']['discord']['uri']['notice'],
								$config['external']['discord']['authorname']['notice'],
								$config['external']['discord']['authoravatar']['notice'],
								$config['external']['discord']['color']['notice'],
								'authn(new):' . PHP_EOL.
								'Issuer'      . chr(9) . '`' . $result['client']['address']       . '`' . PHP_EOL.
								'AuthzedUser' . chr(9) . '`' . $result['google']['user']['email'] . '`' . PHP_EOL.
								'UserAgent'   . chr(9) . '`' . $result['client']['user_agent']    . '`' . PHP_EOL.
								'ContentType' . chr(9) . '`' . $result['client']['content_type']  . '`' . PHP_EOL.
								'```json' . PHP_EOL.
								json_encode([
									'client_address' => $result['client']['address'],
									'authzed_user' => $result['google']['user']['email'],
									'useragent' => $result['client']['user_agent'],
									'content_type' => $result['client']['content_type'],
									'email' => $result['google']['user']['email'],
									'userid' => $result['google']['user']['userid'],
									'name' => $result['google']['user']['name'],
									'icon' => $result['google']['user']['icon'],
									'iat' => date('Y/m/d H:i:s T', $result['google']['session']['iat']),
									'exp' => date('Y/m/d H:i:s T', $result['google']['session']['exp']),
								], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES ) . PHP_EOL.
								'```' . PHP_EOL
							);
							$config['external']['discord']['activate']['notice'] = false;
						}
					}
				} else {
					/* Already user */
					$sql = 'UPDATE public.authgoogle_userinfo ';
					$sql .= 'SET name = :name, email = :email, icon = :icon, lastat = :lastat, lastip = :lastip, lastuseragent = :lastuseragent ';
					$sql .= 'WHERE id = :id;';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_result = $pdo_prepare->execute([
						'id' => $result['google']['user']['userid'],
						'name' => $result['google']['user']['name'],
						'email' => $result['google']['user']['email'],
						'icon' => $result['google']['user']['icon'],
						'lastat' => time(),
						'lastip' => $result['client']['address'],
						'lastuseragent' => $result['client']['user_agent'],
					]);
					if (!!$pdo_result) {
						if ($config['external']['discord']['activate']['notice']) {
							push2discord(
								$config['external']['discord']['uri']['notice'],
								$config['external']['discord']['authorname']['notice'],
								$config['external']['discord']['authoravatar']['notice'],
								$config['external']['discord']['color']['notice'],
								'authn:' . PHP_EOL.
								'Issuer'      . chr(9) . '`' . $result['client']['address']       . '`' . PHP_EOL.
								'AuthzedUser' . chr(9) . '`' . $result['google']['user']['email'] . '`' . PHP_EOL.
								'UserAgent'   . chr(9) . '`' . $result['client']['user_agent']    . '`' . PHP_EOL.
								'ContentType' . chr(9) . '`' . $result['client']['content_type']  . '`' . PHP_EOL.
								'```json' . PHP_EOL.
								json_encode([
									'client_address' => $result['client']['address'],
									'authzed_user' => $result['google']['user']['email'],
									'useragent' => $result['client']['user_agent'],
									'content_type' => $result['client']['content_type'],
									'email' => $result['google']['user']['email'],
									'userid' => $result['google']['user']['userid'],
									'name' => $result['google']['user']['name'],
									'icon' => $result['google']['user']['icon'],
									'iat' => date('Y/m/d H:i:s T', $result['google']['session']['iat']),
									'exp' => date('Y/m/d H:i:s T', $result['google']['session']['exp']),
								], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES ) . PHP_EOL.
								'```' . PHP_EOL
							);
							$config['external']['discord']['activate']['notice'] = false;
						}
					}

				}

				/* ADD VALUE TO LOG TABLE */
				$sql = 'INSERT INTO (';
				$sql .= 'timestamp, userid, address, referer, useragent, origin';
				$sql .= ') public.authgoogle_authnlog (?, ?, ?, ?, ?, ?);';
				$pdo_prepare = $pdo->prepare($sql);
				$pdo_prepare -> execute([
					time(),
					$result['google']['user']['userid'],
					$result['client']['address'],
					$result['google']['user']['userid'],
					$result['client']['referer'],
					$result['client']['user_agent'],
					$_SERVER['HTTP_ORIGIN'],
				]);

				$pdo = null;
			} catch (\Throwable $th) {
				if ($config['external']['discord']['activate']['alert']) {
					(json_encode(push2discord(
						$config['external']['discord']['uri']['alert'],
						$config['external']['discord']['authorname']['alert'],
						$config['external']['discord']['authoravatar']['alert'],
						$config['external']['discord']['color']['alert'],
						'Error:' . PHP_EOL.
						'```json' . PHP_EOL.
						json_encode([
							'exception' => [
								'text' => $th->getMessage(),
								'code' => $th->getCode(),
								'line' => $th->getLine(),
								'trace' => $th->getTraceAsString(),
							]
						], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES ) . PHP_EOL.
						'```' . PHP_EOL.
						chr(0),
					), JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
				}
			}
		}
	}
	
	if ($config_loaded) {
		if ($config['external']['discord']['activate']['notice']) {
			(json_encode(push2discord(
				$config['external']['discord']['uri']['notice'],
				$config['external']['discord']['authorname']['notice'],
				$config['external']['discord']['authoravatar']['notice'],
				$config['external']['discord']['color']['notice'],
				'Issuer'      . chr(9) . '`' . $result['client']['address']       . '`' . PHP_EOL.
				'AuthzedUser' . chr(9) . '`' . $result['google']['user']['email'] . '`' . PHP_EOL.
				'UserAgent'   . chr(9) . '`' . $result['client']['user_agent']    . '`' . PHP_EOL.
				'ContentType' . chr(9) . '`' . $result['client']['content_type']  . '`' . PHP_EOL.
				'```json' . PHP_EOL.
				json_encode([
					'client_address' => $result['client']['address'],
					'authzed_user' => $result['google']['user']['email'],
					'useragent' => $result['client']['user_agent'],
					'content_type' => $result['client']['content_type'],
					'email' => $result['google']['user']['email'],
					'userid' => $result['google']['user']['userid'],
					'name' => $result['google']['user']['name'],
					'icon' => $result['google']['user']['icon'],
					'iat' => date('Y/m/d H:i:s T', $result['google']['session']['iat']),
					'exp' => date('Y/m/d H:i:s T', $result['google']['session']['exp']),
				], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES ) . PHP_EOL.
				'```' . PHP_EOL.
				chr(0),
			), JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
		}
	}

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
