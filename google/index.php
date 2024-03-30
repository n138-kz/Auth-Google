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
$description = [];
$description['http-status-code'] = dirname(__FILE__) . '/' . 'http-status-code.json';
if ( file_exists($description['http-status-code']) && filesize($description['http-status-code']) > 0 ) {
	try {
		$description['http-status-code'] = json_decode(file_get_contents($description['http-status-code']), true);
	} catch (\Exception $e) {
		$description['http-status-code'] = false;
	}
} else {
	$description['http-status-code'] = false;
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
function set_http_response_code ( $http ) {
	http_response_code( $http );
	global $result;
	global $description;
	$result['http']['code'] = $http;
	$result['http']['text'] = $_SERVER['SERVER_PROTOCOL'] . ' ' . $http;
	if (!!$description['http-status-code']) {
		$result['http']['text'] = $_SERVER['SERVER_PROTOCOL'] . ' ' . $description['http-status-code'][$http];
	}
}

$_SESSION = [];
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
$result['issue_at'] = microtime(TRUE);
$result['error']['code'] = 0;
$result['http']['code'] = http_response_code();
if (!!$description['http-status-code']) {
	$http = http_response_code();
	$result['http']['text'] = $_SERVER['SERVER_PROTOCOL'] . ' ' . $description['http-status-code'][$http];
}
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
	if ($config_loaded) {
		$request['clientId'] = $config['external']['google']['authn']['clientId'];
	} else {
		set_http_response_code(400);
		$result['issue_at'] = microtime(TRUE);
		$result['last_checkpoint'] = __LINE__;
	
		echo json_encode( $result );
		exit(1);
	}
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
			'credential' => CLIENT_TOKEN,
		],
	];
	setcookie(
		session_name() . '_alt',
		base64_encode(json_encode([
			'authnaddr' => $result['client']['address'],
			'clientId' => CLIENT_ID,
			'credential' => CLIENT_TOKEN,
			'iat' => time(),
		])),
		$result['google']['session']['exp']
	);
	$headers_list = [];
	foreach (headers_list() as $key => $val) {
		$split = explode(':', $val, 2);
		$headers_list[trim($split[0])] = trim($split[1]);
	}
	$result['variable'] = [
		'_config'  => [
			'loaded' => $config_loaded,
			'body'   => $config,
		],
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
									'iat' => date('Y/m/d H:i:s T', $result['google']['session']['iat']),
									'exp' => date('Y/m/d H:i:s T', $result['google']['session']['exp']),
								], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES ) . PHP_EOL.
								'```' . PHP_EOL
							);
							$config['external']['discord']['activate']['notice'] = false;
						}
					}

				}

				/* ADD VALUE TO TABLE IF NOT EXISTS */
				$sql = 'SELECT COUNT(userid) AS COUNT FROM public.authgoogle_role_internal_datastore WHERE userid=?';
				$pdo_prepare = $pdo->prepare($sql);
				$pdo_result = $pdo_prepare->execute([ $result['google']['user']['userid'] ]);
				$pdo_result = $pdo_prepare->fetch(PDO::FETCH_ASSOC);
				if ($pdo_result['count'] === 0) {
					/* New user */
					$sql = 'INSERT INTO public.authgoogle_role_internal_datastore (userid) VALUES (:userid);';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_result = $pdo_prepare->execute([
						'userid' => $result['google']['user']['userid'],
					]);
				}

				/* ADD VALUE TO LOG TABLE */
				try {
					$sql = 'INSERT INTO public.authgoogle_authnlog (';
					$sql .= 'timestamp, userid, address, referer, useragent, origin, returnval';
					$sql .= ') VALUES (?, ?, ?, ?, ?, ?, ?);';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_prepare -> execute([
						time(),
						$result['google']['user']['userid'],
						$result['client']['address'],
						$result['client']['referer'],
						$result['client']['user_agent'],
						$result['client']['origin'],
						json_encode($result),
					]);
				} catch (\Exception $th) {
					if (FALSE) {
					} elseif ( FALSE ) {
					} elseif ( strpos($th->getMessage(), 'duplicate key value violates unique constraint' ) !== FALSE ) {
					} else {
						error_log( $th->getMessage() . PHP_EOL . '' . __FILE__ . '#' . __LINE__ );
					}
				}

				/* ADD SESSION INFO TO TABLE */
				try {
					$sql = 'SELECT count(exp) FROM public.authgoogle_sessions WHERE userid=? AND token=?;';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_prepare -> execute([
						$result['google']['user']['userid'],
						hash('sha512', CLIENT_TOKEN),
					]);
					$pdo_result = $pdo_prepare->fetch(PDO::FETCH_ASSOC);
					if ( $pdo_result['count'] == 0 ) {
						$sql = 'INSERT INTO public.authgoogle_sessions (';
						$sql .= 'userid, useragent, address, token, iat, exp';
						$sql .= ') VALUES (?, ?, ?, ?, ?, ?);';
						$pdo_prepare = $pdo->prepare($sql);
						$pdo_prepare -> execute([
							$result['google']['user']['userid'],
							$result['client']['user_agent'],
							$result['client']['address'],
							hash('sha512', CLIENT_TOKEN),
							$result['google']['session']['iat'],
							$result['google']['session']['exp'],
						]);

					} else {
						$sql = 'UPDATE public.authgoogle_sessions ';
						$sql .= 'SET useragent=?, address=?, iat=?, exp=?';
						$sql .= 'WHERE userid=? AND token=?;';
						$pdo_prepare = $pdo->prepare($sql);
						$pdo_prepare -> execute([
							$result['client']['user_agent'],
							$result['client']['address'],
							$result['google']['session']['iat'],
							$result['google']['session']['exp'],
							$result['google']['user']['userid'],
							hash('sha512', CLIENT_TOKEN),
						]);
					}
				} catch (\Exception $th) {
					error_log( $th->getMessage() . PHP_EOL . '' . __FILE__ . '#' . __LINE__ );
				}

				/* GET ACCESABLE URL IN INTERNAL */
				try {
					/* get priv level in user. */
					$sql = 'SELECT userid, privlevel FROM public.authgoogle_role_internal_datastore WHERE userid=?;';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_prepare -> execute([ $result['google']['user']['userid'], ]);
					$pdo_result = $pdo_prepare->fetch(PDO::FETCH_ASSOC);

					/* use priv level */
					$sql = 'SELECT links FROM public.authgoogle_internallinks WHERE activate=true AND privid=?;';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_prepare -> execute([ $pdo_result['privlevel'] ]);
					$pdo_result = $pdo_prepare->fetchAll(PDO::FETCH_ASSOC);
					foreach ( $pdo_result as $k => $v ) {
						/* append from privid group */
						$result['links'][] = json_decode($v['links'], TRUE);
					}

					/* use userid */
					$sql = 'SELECT * FROM public.authgoogle_internallinks WHERE userid=?;';
					$pdo_prepare = $pdo->prepare($sql);
					$pdo_prepare -> execute([ $result['google']['user']['userid'], ]);
					$pdo_result = $pdo_prepare->fetchAll(PDO::FETCH_ASSOC);
					foreach ( $pdo_result as $k => $v ) {
						/* append from userid group */
						$result['links'][] = json_decode($v['links'], TRUE);
					}

					/* href is null or name is null then trim */
					foreach ( $result['links'] as $k => $v ) {
						if ( ( is_null( $v['href'] ) ) || (is_null( $v['name'] ) ) ) {
							unset($result['links'][$k]);
						}
					}
					$result['links'] = array_values( $result['links'] );
				} catch (\Exception $th) {
					error_log( $th->getMessage() . PHP_EOL . '' . __FILE__ . '#' . __LINE__ );
				}



				$pdo = null;
			} catch (\Throwable $th) {
				set_http_response_code(500);
				error_log($th->getMessage());
				$result['issue_at'] = microtime(TRUE);
				$result['last_checkpoint'] = __LINE__;
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
	
	if ( !isset( $_REQUEST['dev'] ) ) {
		unset( $result['variable'] );
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
