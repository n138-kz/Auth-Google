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

require_once('../../usr-lib-bin/autoload.php');

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

define('CLIENT_ID', $_SESSION['clientId']);
define('CLIENT_TOKEN', $_SESSION['credential']);

try {
	require_once '../../vendor/autoload.php';
	
	$client = new Google_Client(['client_id' => CLIENT_ID]);
	try {
		$payload = $client->verifyIdToken(CLIENT_TOKEN);
		if (!$payload) {
			throw new Exception();
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

	set_http_response_code(200);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	exit(0);
} catch (\Exception $th) {
	set_http_response_code(500);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	error_log($th->getTraceAsString());

	echo json_encode( $result );
	exit(0);
}
