<?php session_start();
require_once '../vendor/autoload.php';

require_once('./cgi-bin/Discode_push_class.php');
$discord = new discord();
$discord->endpoint = 'https://discord.com/api/webhooks/1090853878519570453/Q8VwiyJtY8QFPiufGPcKBBV1DUq_athBryyS34pSQogHmhYNkz3SoY05WggyXShL6DA3?wait=true';

if (mb_strtolower($_SERVER ['REQUEST_METHOD']) != 'post' ) {
    http_response_code(405);
    $curl_res['ts']   = time();
    $curl_res['mesg'] = 'Method Not Allowed.';

    echo json_encode($curl_res);
    
    $discord_pushmessage  = '';
    $discord_pushmessage .= '[LOGGER]Warn:' .                                  PHP_EOL;
    $discord_pushmessage .= 'user>' . $_SESSION['user']['google']['email'] .   PHP_EOL;
    $discord_pushmessage .= 'uuid>' . $_SESSION['user']['google']['userid'] .  PHP_EOL;
    $discord_pushmessage .= 'name>' . $_SESSION['user']['google']['name'] .    PHP_EOL;
    $discord_pushmessage .= 'icon>' . $_SESSION['user']['google']['icon'] .    PHP_EOL;
    $discord_pushmessage .= 'time>' . date('Y/m/d H:i:s',$payload['iat']) .    PHP_EOL;
    $discord_pushmessage .= 'mesg>' . $curl_res['mesg'] . PHP_EOL;
    $discord_pushmessage .= 'mesg>' . __FILE__ . PHP_EOL;
    $discord_pushmessage .= '';
    $discord->setValue('content', $discord_pushmessage);
    $discord_res = $discord->exec_curl();
    $discord_pushmessage = $discord_res = null;
    
    exit();
}

if ( !isset($_POST) || !is_array($_POST) ) {
    http_response_code(400);
    $curl_res['ts']   = time();
    $curl_res['mesg'] = 'Bad params.';
    echo json_encode($curl_res);

    $discord_pushmessage  = '';
    $discord_pushmessage .= '[LOGGER]Warn:' .                                  PHP_EOL;
    $discord_pushmessage .= 'user>' . $_SESSION['user']['google']['email'] .   PHP_EOL;
    $discord_pushmessage .= 'uuid>' . $_SESSION['user']['google']['userid'] .  PHP_EOL;
    $discord_pushmessage .= 'name>' . $_SESSION['user']['google']['name'] .    PHP_EOL;
    $discord_pushmessage .= 'icon>' . $_SESSION['user']['google']['icon'] .    PHP_EOL;
    $discord_pushmessage .= 'time>' . date('Y/m/d H:i:s',$payload['iat']) .    PHP_EOL;
    $discord_pushmessage .= 'mesg>' . $curl_res['mesg'] . PHP_EOL;
    $discord_pushmessage .= 'mesg>' . __FILE__ . PHP_EOL;
    $discord_pushmessage .= '';
    $discord->setValue('content', $discord_pushmessage);
    $discord_res = $discord->exec_curl();
    $discord_pushmessage = $discord_res = null;
    
    exit();
}
if ( !isset($_POST['client_id']) ) {
    http_response_code(400);
    $curl_res['ts']   = time();
    $curl_res['mesg'] = 'Bad params.';
    echo json_encode($curl_res);

    $discord_pushmessage  = '';
    $discord_pushmessage .= '[LOGGER]Warn:' .                                  PHP_EOL;
    $discord_pushmessage .= 'user>' . $_SESSION['user']['google']['email'] .   PHP_EOL;
    $discord_pushmessage .= 'uuid>' . $_SESSION['user']['google']['userid'] .  PHP_EOL;
    $discord_pushmessage .= 'name>' . $_SESSION['user']['google']['name'] .    PHP_EOL;
    $discord_pushmessage .= 'icon>' . $_SESSION['user']['google']['icon'] .    PHP_EOL;
    $discord_pushmessage .= 'time>' . date('Y/m/d H:i:s',$payload['iat']) .    PHP_EOL;
    $discord_pushmessage .= 'mesg>' . $curl_res['mesg'] . PHP_EOL;
    $discord_pushmessage .= 'mesg>' . __FILE__ . PHP_EOL;
    $discord_pushmessage .= '';
    $discord->setValue('content', $discord_pushmessage);
    $discord_res = $discord->exec_curl();
    $discord_pushmessage = $discord_res = null;
    
    exit();
}
if ( !isset($_POST['credential']) ) {
    http_response_code(400);
    $curl_res['ts']   = time();
    $curl_res['mesg'] = 'Bad params.';
    echo json_encode($curl_res);

    $discord_pushmessage  = '';
    $discord_pushmessage .= '[LOGGER]Warn:' .                                  PHP_EOL;
    $discord_pushmessage .= 'user>' . $_SESSION['user']['google']['email'] .   PHP_EOL;
    $discord_pushmessage .= 'uuid>' . $_SESSION['user']['google']['userid'] .  PHP_EOL;
    $discord_pushmessage .= 'name>' . $_SESSION['user']['google']['name'] .    PHP_EOL;
    $discord_pushmessage .= 'icon>' . $_SESSION['user']['google']['icon'] .    PHP_EOL;
    $discord_pushmessage .= 'time>' . date('Y/m/d H:i:s',$payload['iat']) .    PHP_EOL;
    $discord_pushmessage .= 'mesg>' . $curl_res['mesg'] . PHP_EOL;
    $discord_pushmessage .= 'mesg>' . __FILE__ . PHP_EOL;
    $discord_pushmessage .= '';
    $discord->setValue('content', $discord_pushmessage);
    $discord_res = $discord->exec_curl();
    $discord_pushmessage = $discord_res = null;
    
    exit();
}

define('CLIENT_ID', $_POST['client_id']);
define('CLIENT_TOKEN', $_POST['credential']);

$client = new Google_Client(['client_id' => CLIENT_ID]); 
$payload = $client->verifyIdToken(CLIENT_TOKEN);
if ($payload) {
  $userid = $payload['sub'];
  $_SESSION = [];
  $_SESSION['user']['google']['userid'] = $payload['sub'];
  $_SESSION['user']['google']['email'] = $payload['email'];
  $_SESSION['user']['google']['name'] = $payload['name'];
  $_SESSION['user']['google']['icon'] = $payload['picture'];
  $_SESSION['user']['google']['session']['iat'] = $payload['iat'];
  $_SESSION['user']['google']['session']['exp'] = $payload['exp'];
  /*
  exp: 1677261466 expire at time
  iat: 1677257866 issue at time
  nbf: 1677257566
  aud: CLIENT_ID
  azp: CLIENT_ID
  sub: user id
  iss: "https://accounts.google.com"
  email: user email
  email_verified: 
  */
  $discord->setValue('content', '[LOGGER]Google OAuth2:'.PHP_EOL.'user>'.$payload['email'].PHP_EOL.'uuid>'.$payload['sub'].PHP_EOL.'name>'.$payload['name'].PHP_EOL.'icon>'.$payload['picture'].PHP_EOL.'time>'.date('Y/m/d H:i:s',$payload['iat']).PHP_EOL);
  $discord_res = $discord->exec_curl();
  error_log('Discord API:'.json_encode($discord_res));

  $_SESSION['user']['google'][0] = $payload;
}
echo json_encode($_SESSION);