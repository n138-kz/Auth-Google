<?php session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
	'name' 	          => 'AUTHNKEY',
]);
date_default_timezone_set('Asia/Tokyo');
header('Content-Type: text/html; charset=UTF-8');

$config = dirname(__FILE__) . '/../' . '.env';
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

function set_http_response_code ( $http ) {
	http_response_code( $http );
	global $result;
	$result['http']['code'] = $http;
	$result['http']['text'] = $_SERVER['SERVER_PROTOCOL'] . ' ' . get_message_with_http_response_code($http);
}


try {
	require_once '../../vendor/autoload.php';
	
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
