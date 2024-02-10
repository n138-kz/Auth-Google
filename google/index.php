<?php session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
]);
header('Content-Type: text/plain');
header('Content-Type: Application/json');
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Disposition, Content-Type, Content-Length, Accept-Encoding");

$_SESSION = [];
$result = [];
$result['remote'] = $_SERVER['REMOTE_ADDR'] . ':' . $_SERVER['REMOTE_PORT'];
$result['issue_at'] = microtime(TRUE);
$result['error']['code'] = 0;
$result['http']['code'] = http_response_code();
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

function set_http_response_code ( $http ) {
	http_response_code( $http );
	$result['http']['code'] = $http;
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
if( !isset( $_POST['ts'] ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
if( !isset( $_POST['credential'] ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
if( !isset( $_POST['clientId'] ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}
/*# Is correct? #*/
if( ( time() - (int)$_POST['ts'] > 300 ) ) {
	set_http_response_code(400);
	$result['issue_at'] = microtime(TRUE);
	$result['last_checkpoint'] = __LINE__;

	echo json_encode( $result );
	exit(1);
}

define('CLIENT_ID', $_POST['clientId']);
define('CLIENT_TOKEN', $_POST['credential']);

require_once '../vendor/autoload.php';

$client = new Google_Client(['client_id' => CLIENT_ID]);
$payload = $client->verifyIdToken(CLIENT_TOKEN);
if ($payload) {
	$result['google'] = [
		'userid' => $payload['sub'],
		'email'  => $payload['email'],
		'name'   => $payload['name'],
		'icon'   => $payload['icon'],
		'iat'    => $payload['iat'],
		'exp'    => $payload['exp'],
	];
}

set_http_response_code(400);
$result['issue_at'] = microtime(TRUE);
$result['last_checkpoint'] = __LINE__;

echo json_encode( $result );
exit(0);

