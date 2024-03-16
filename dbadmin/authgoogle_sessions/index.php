<?php
session_name('AUTHNKEY');
session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
	'name' 	          => 'AUTHNKEY',
]);
date_default_timezone_set('Asia/Tokyo');
header('Content-Type: text/plain; charset=UTF-8');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PATCH, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Disposition, Content-Type, Content-Length, Accept-Encoding, Origin, Accept, Access-Control-Allow-Headers, Authorization, X-Requested-With");
header('X-Powered-By: Hidden');
header_register_callback(function(){ header_remove('X-Powered-By'); });

$config = dirname(__FILE__) . '/../../google/' . '.env';
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



$request = [];
$result = [];
if ($config_loaded) {
	$result = $config['internal']['default']['result'];
}
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
	'origin' => ( isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '' ),
];
$result['issue_at'] = time();
$result['error']['code'] = 0;
$result['http']['code'] = http_response_code();
$result['http']['text'] = get_message_with_http_response_code($result['http']['code']);
$result['last_checkpoint'] = __LINE__;

$request = array_merge($request, $_COOKIE);
$request = array_merge($request, $_SESSION);
$request = array_merge($request, $_REQUEST);
try {
	if ( isset($request[session_name().'_alt']) ) {
		$request = array_merge(
			$request,
			json_decode( base64_decode( $request[session_name().'_alt'] ), TRUE)
		);
	}
} catch (\Exception $e) {
	set_http_response_code(400);
	$result['issue_at'] = time();
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}

if( strtolower( $_SERVER['REQUEST_METHOD'] ) == 'options' ) {
	set_http_response_code(200);
	$result['issue_at'] = time();
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(0);
}

header('Content-Type: text/plain; charset=UTF-8');
header('Content-Type: application/json; charset=UTF-8');
$request['header'] = apache_request_headers();
$request['header']['Authorization'] = isset($request['header']['Authorization']) ? explode(' ', $request['header']['Authorization']) : ['Bearer', null];
$request['header']['Authorization'][$request['header']['Authorization'][0]] = $request['header']['Authorization'][1];

define('CLIENT_ADDR', $request['authnaddr']);
define('CLIENT_ID', $request['clientId']);
define('CLIENT_TOKEN', $request['credential']);

try {
	require_once '../../../../vendor/autoload.php';
	
	if ( $_SERVER['REMOTE_ADDR'] !== CLIENT_ADDR ) {
		set_http_response_code(401);
		$result['issue_at'] = time();
		$result['last_checkpoint'] = __LINE__;

		echo json_encode( $result );
		exit(1);
	}
	
	$client = new Google_Client(['client_id' => CLIENT_ID]);
	try {
		$payload = $client->verifyIdToken(CLIENT_TOKEN);
		if (!$payload) {
			throw new Exception();
		} else {
			$result['google'] = $payload;
		}
	} catch (\Exception $th) {
		/* invalid token */
		$payload = false;

		set_http_response_code(401);
		$result['issue_at'] = time();
		$result['last_checkpoint'] = __LINE__;

		echo json_encode( $result );
		exit(1);
	}

	set_http_response_code(200);
	$result['issue_at'] = time();
	$result['last_checkpoint'] = __LINE__;

	
	$headers_list = [];
	foreach (headers_list() as $key => $val) {
		$split = explode(':', $val, 2);
		$headers_list[trim($split[0])] = trim($split[1]);
	}
	$result['variable'] = [
		'_session' => $_SESSION,
		'_request' => $_REQUEST,
		'_get'     => $_GET,
		'_post'    => $_POST,
		'_server'  => $_SERVER,
		'_cookie'  => $_COOKIE,
		'_headers' => [
			'request' => apache_request_headers(),
			'response' => $headers_list,
		],
		'_roles'   => [],
	];
	unset($headers_list);

	if ($config_loaded) {
		if ($config['internal']['databases']['activate'] && $config['internal']['databases']['primary']['activate']) {
			$result['datastore']['public']['authgoogle_sessions'] = [];
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

				$sql  = 'SELECT * FROM public.authgoogle_role_internal_datastore';
				$sql .= ' INNER JOIN public.authgoogle_userinfo ON public.authgoogle_userinfo.id = public.authgoogle_role_internal_datastore.userid';
				$sql .= ' WHERE public.authgoogle_role_internal_datastore.userid = :userid';
				$pdo_prepare = $pdo->prepare($sql);
				$pdo_result = $pdo_prepare->execute([ 'userid' => $result['google']['sub'] ]);
				$pdo_result = $pdo_prepare->fetch(PDO::FETCH_ASSOC);
				$result['variable']['_roles'] = $pdo_result;
				if ( $pdo_result['superuser'] || ( ( ( $pdo_result['authgoogle_userinfo'] & 4 ) === 4 ) && ( ( $pdo_result['authgoogle_sessions'] & 4 ) === 4 ) ) ) {
					$sql  = 'SELECT public.authgoogle_userinfo.email, public.authgoogle_userinfo.name, public.authgoogle_sessions.iat, public.authgoogle_sessions.exp, public.authgoogle_sessions.token FROM public.authgoogle_sessions';
					$sql .= ' INNER JOIN public.authgoogle_userinfo ON public.authgoogle_userinfo.id = public.authgoogle_sessions.userid';
					$sql .= ' WHERE public.authgoogle_sessions.iat < EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) AND public.authgoogle_sessions.exp > EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)';
					$sql .= ' ORDER BY exp DESC';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_result = $pdo_prepare->execute([]);
					$pdo_result = $pdo_prepare->fetchAll(PDO::FETCH_ASSOC);
					$result['datastore']['public']['authgoogle_sessions'] = $pdo_result;
				}
				if ( !$result['variable']['_roles']['superuser'] ) {
					unset($result['google']);
					unset($result['variable']);
				}

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

	header('Content-Type: application/json; charset=UTF-8');
	echo json_encode( $result, JSON_NUMERIC_CHECK | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_IGNORE);

	exit(0);
} catch (\Exception $th) {
	set_http_response_code(500);
	$result['issue_at'] = time();
	$result['last_checkpoint'] = __LINE__;

	error_log($th->getTraceAsString());

	echo json_encode( $result );
	exit(1);
}
