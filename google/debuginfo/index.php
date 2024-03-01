<?php session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
	'name' 	          => 'AUTHNKEY',
]);
date_default_timezone_set('Asia/Tokyo');
header('Content-Type: text/plain');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Headers: Content-Disposition, Content-Type, Content-Length, Accept-Encoding");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PATCH, PUT, DELETE");

$config = dirname(__FILE__) . '/../' . '.env';
if ( file_exists($config) && filesize($config) > 0 ) {
	try {
		$config = json_decode(file_get_contents($config), true);
	} catch (\Exception $e) {
		unset($config);
	}
}

define('CLIENT_ID', null);
define('CLIENT_TOKEN', null);

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
