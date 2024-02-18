<?php session_start([
	'cookie_lifetime' => 86400,
	'read_and_close'  => true,
	'name' 	          => 'AUTHNKEY',
]);
header('Content-Type: text/plain');
header('Content-Type: Application/json');
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Disposition, Content-Type, Content-Length, Accept-Encoding");

$config = dirname(__FILE__) . '/' . '.env';
if ( file_exists($config) && filesize($config) > 0 ) {
	try {
		$config = json_decode(file_get_contents($config), true);
	} catch (\Exception $e) {
		unset($config);
	}
}

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
$result['authn'] = [
	'sessions' => [
		'id' => '',
		'name' => '',
	],
];

function set_http_response_code ( $http ) {
	http_response_code( $http );
	global $result;
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

try {
	require_once '../vendor/autoload.php';
	
	$client = new Google_Client(['client_id' => CLIENT_ID]);
	try {
		$payload = $client->verifyIdToken(CLIENT_TOKEN);
		if ($payload) {
			$result['google'] = [
				'user' => [
					'userid' => $payload['sub'],
					'name' => $payload['name'],
					'icon' => $payload['picture'],
					'email' => $payload['email'],
				],
				'session' => [
					'iat' => $payload['iat'],
					'exp' => $payload['exp'],
				],
			];
		}
	} catch (\Exception $th) {
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

	echo json_encode( $result );
	exit(1);
}
