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

function set_http_response_code ( &$result, $http_response_code, $runner_line ) {
	$result['issue_at'] = microtime(TRUE);
	$result['error']['code'] = 0;
	http_response_code( $http_response_code );
	$result['error']['http']['code'] = $http_response_code;
	$result['last_checkpoint'] = $runner_line;
	$result['google'] = [
		'userid' => '',
		'name' => '',
		'icon' => '',
		'session' => [
			'iat' => 0,
			'exp' => 0,
		],
	];
}

if( strtolower( $_SERVER['REQUEST_METHOD'] ) != 'post' ) {
	setResult( $result, 405, __LINE__ );
	echo json_encode( $result );
	exit(1);
}
/*# Is set? #*/
if( !isset( $_POST ) ) {
	setResult( $result, 400, __LINE__ );
	echo json_encode( $result );
	exit(1);
}
if( !is_array( $_POST ) ) {
	setResult( $result, 400, __LINE__ );
	echo json_encode( $result );
	exit(1);
}
if( !isset( $_POST['ts'] ) ) {
	setResult( $result, 400, __LINE__ );
	echo json_encode( $result );
	exit(1);
}
if( !isset( $_POST['credential'] ) ) {
	setResult( $result, 400, __LINE__ );
	echo json_encode( $result );
	exit(1);
}
if( !isset( $_POST['clientId'] ) ) {
	setResult( $result, 400, __LINE__ );
	echo json_encode( $result );
	exit(1);
}
/*# Is correct? #*/
if( ( time() - (int)$_POST['ts'] > 300 ) ) {
	setResult( $result, 400, __LINE__ );
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

setResult( $result, 200, __LINE__ );
echo json_encode( $result );
exit(0);

