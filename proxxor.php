#!/usr/local/bin/php -d allow_url_fopen=On
<?php
/*иииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииии
иииии##ииииииииииииииииииииииии#######ииииииииииииииииииииииииииии####иииииииии
иии######и#######ии##и######и###иииии###и####ии#ии####и##########ии########ииии
ииии###и###иииии###и###ииии###иииии####иии###и###и###и##########иии###ииии###ии
ииии###и###иииии###и###иииииииии####иии#иии#########ии###ииииииииии###ииии###ии
иииии####и#######ии#####иииии###########ииии##иии##иииии#########и#########ииии
иииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииии
иииииииииииииииииииииииииииииииииииPOWEREDиBYииииииииииииииииииииииииииииииииии
иииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииии
иииииииииии######.и######.ии.####.и###ии###и###ии###и.####.и######.ииииииииииии
ииииииииииии##иии#ии##иии#ии##ии##иии##.#'ииии##.#'ии##ии##ии##иии#ииииииииииии
ииииииииииии#####'ии#####'ии##ии##ииии##иииииии##ииии##ии##ии#####'ииииииииииии
ииииииииииии##ииииии##ии'#ии##ии##иии#'##ииии.#'##иии##ии##ии##ии'#ииииииииииии
иииииииииии####ииии###ии###и'####'и###ии###и###ии###и'####'и###ии###иииииииииии
иииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииии
#########ии########иииииииииииииииииMADEиBYииииииииииииииии##иииии#########.иии
ии'####:ииии:###'иииииииииииииииииииииииииииииииииииииииии:##:иииии'###ии'###.и
ииии'###.ии.##'иииииииииииииииииииииииииииииииииииииииииии####ииииии###ииии###и
иииии'###..##'иии######ии#####ии.#####.иии..#иии___ииииии:#'##:иииии###ииии###и
ииииии'#####'иииии'###:ии:##'и.##''и''##.####и######.ииии#'ии##иииии###иии.###и
иииииии'###:ииииииии'##..#'ии.##'иииии'##.и###''и'##'иии:#иии##:ииии########:ии
иииииии.####.ииииииии'###'иии###иииииии###и##иииииииииии#'иии:##ииии###иии'###.
ииииии.##'###.ииииииии.##.иии###иииииии###и##ииииииииии:########:иии###ииии'###
иииии.##'и'###.ииииии.#'##.ии###иииииии###и##ииииииииии#'иииии:##иии###иииии###
ииии.##'иии'###.ииии.#'и'##.и'##ииииии.##'и##иииииииии:#иииииии##:ии###ииии.###
ии.###:иииии:####..##:иии:###.'##..и..##'и.##.иииииии.##.иииии.###..###.ии.###'
########иии############и#######''#####''и#######иии#######иии###############'ии
иииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииии
 Copyright (c) 2011, Xxor (Xxor Frans Pehrson AB)
 All rights reserved

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
иииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииииии*/

define('VERSION','1.0');
define('SOFTWARE', 'Proxxor4tor2web');
//echo "Starting ".SOFTWARE." ".VERSION."\n";
declare(ticks = 1);
error_reporting(E_ALL);
set_time_limit(0);

// TODO, Accept commandline options

$conf_file = '/etc/proxxor.conf';

// Default settings.
$GLOBALS = array(
	'IP'                    => '0.0.0.0',
	'PORT'                  => '80,443',
	'DOMAINNAME'            => '',
	'MAXCONNECTIONS'        => 100,
	'CONNECTIONTIMEOUT'     => 120,
	'DESTINATIONPORT'       => 0,
	'USESYSLOG'             => false,
	'LOGLEVEL'              => LOG_NOTICE,
	'ACCESSLOGFILE'         => '',
	'ACCESSLOGFORMAT'       => '[%1$s][%4$s:%5$s > %6$s:%8$s][%3$f] %9$s',
	'TIMEZONE'              => '',
	'DATEFORMAT'            => DATE_RFC2822,
	'CHROOTDIRECTORY'       => '',
	'RUNASUSER'             => '',
	'DETECTSECURE'          => true,
	'FORWARDSECURE'         => false,
	'PEMPASSPHRASE'         => '',
	'PEMFILE'               => '',
	'STREAMRWBUFFER'        => 8192,
	'STREAMWRITECHUNK'      => 4096,
	'AUTOONIONDOMAIN'       => false,
	'USESOCKS5'             => false,
	'SOCKS5IP'              => '127.0.0.1',
	'SOCKS5PORT'            => 1080,
	'SOCKS5OPTIMISTICDATA'  => false,
	'DEBUGMODE'             => false
);

if(file_exists($conf_file) && is_readable($conf_file)){
	// Load settings from conf file.
	foreach(parse_ini_file($conf_file) as $key => $val){
		if(isset($GLOBALS[$key])){
			// Typecast to the same type as the default setting.
			settype($val, gettype($GLOBALS[$key]));
			// Set new setting.
			$GLOBALS[$key]=$val;
			
		}
		// debug_this("$key=$val");
	}
}

// Open syslog
if($GLOBALS['USESYSLOG']){
	openlog(SOFTWARE, LOG_PID | LOG_CONS, LOG_DAEMON);
}

// Use a custom errorhandler for internal PHP errors.
set_error_handler('error_handler');

// Set timezone
if(!$GLOBALS['TIMEZONE']){
	date_default_timezone_set(@date_default_timezone_get()); // Suppress DateTime warnings
	log_this("Setting 'TIMEZONE' is empty. Guessing we are in timezone '".date_default_timezone_get()."'.  It is recommended to configure this setting. List of Supported Timezones: http://www.php.net/manual/en/timezones.php",LOG_WARNING);
}else{
	date_default_timezone_set($GLOBALS['TIMEZONE']);
}

log_this("Starting ".SOFTWARE." ".VERSION, LOG_NOTICE);

// Set a better title for this process
if(is_callable('setproctitle'))setproctitle(SOFTWARE." ".VERSION);

if(!umask(0077)) //Change file mode mask // TODO, make sure the umask works as intended.
	log_this('Failed to set umask', LOG_WARNING);
	
if(!chdir('/')) // Change the current working directory to a safe place
	log_this('Failed to set chdir to /', LOG_WARNING);

// Check enviroment and php extentions to determin if we can execute properly.
if(!is_callable('pcntl_fork'))  log_this('PCNTL functions not available on this PHP installation.', LOG_WARNING);
if(!is_callable('posix_getpid'))log_this('POSIX functions not available on this PHP installation.', LOG_WARNING);
if(!is_callable('chroot'))      log_this('CHROOT function not available on this PHP installation.', LOG_WARNING);
if(!is_callable('setproctitle'))log_this('PROCTITLE functions not available on this PHP installation.', LOG_WARNING);

// Check something
if(!file_exists($conf_file))
	log_this("No configuration-file found at $conf_file", LOG_WARNING);

// Check security
if(file_exists($conf_file) && fileperms($conf_file) & 0177)
	log_this("The configuration file's permissions are '".decoct(fileperms($conf_file)&0777)."'. It is strongly recommended to chmod them to '600'.", LOG_WARNING);

// Open the accesslogfile.
if($GLOBALS['ACCESSLOGFILE'] && !($LOG_FD = fopen($GLOBALS['ACCESSLOGFILE'], 'a'))){
	// Warn if we could not.
	log_this("Unable to open accesslogfile!", LOG_WARNING);
}
	
// Chroot
if(!$GLOBALS['CHROOTDIRECTORY']){
	log_this("Setting 'CHROOTDIRECTORY' is empty. Will not chroot. It is strongly recommended to configure this setting.",LOG_WARNING);
}else{
	if(!chroot($GLOBALS['CHROOTDIRECTORY'])){
		log_this("Failed to chroot to '".CHROOTDIRECTORY."'! Will not continue.",LOG_EMERG);
		exit(1);
	}
	log_this("Chrooted to '".$GLOBALS['CHROOTDIRECTORY']."'. Current working directory set to ".getcwd(),LOG_NOTICE);
}

// Catch signals SIGTERM and SIGINT
pcntl_signal(SIGTERM, "termint_handler");
pcntl_signal(SIGINT, "termint_handler");

// Open listening sockets
$proxy_sockets = array();
foreach(explode(',',$GLOBALS['IP']) as $ip){
	foreach(explode(',',$GLOBALS['PORT']) as $port){
		// Listen to a tcp IP/port, returning the socket stream
		if(!($proxy_sockets[] = @stream_socket_server("tcp://$ip:$port", $errno, $errstr, STREAM_SERVER_BIND|STREAM_SERVER_LISTEN))){
			log_this("Cannot bind to $ip:$port. ($errno) $errstr.",LOG_EMERG);
			array_pop($proxy_sockets);
			//exit(1);
		}else{
			log_this("Listening to $ip:$port for connections",LOG_NOTICE);
		}
	}
}
foreach($proxy_sockets as $socket)stream_socket_enable_crypto($socket, false);

// Drop privileges
if(!$GLOBALS['RUNASUSER']){
	log_this("Setting 'RUNASUSER' is empty. Privileges wont be dropped. It is strongly recommended to configure this setting.",LOG_WARNING);
}elseif( !dropPrivilegesTo($GLOBALS['RUNASUSER']) ){
	log_this("Failed to drop privileges to user '".$GLOBALS['RUNASUSER']."'.",LOG_EMERG);
	exit(1);
}

// Register stream filters
if(!stream_filter_register("htmlproxy_request", "htmlproxy_request_filter")){
	log_this("Failed to register filter 'htmlproxy_request'.",LOG_EMERG);
	exit(1);
}
if(!stream_filter_register("htmlproxy_response", "htmlproxy_response_filter")){
	log_this("Failed to register filter 'htmlproxy_response'.",LOG_EMERG);
	exit(1);
}

if(!is_callable('gzdecode')){
	//ini_set('allow_url_include','On'); // To use data url in gzdecode().
	ini_set('allow_url_fopen','On'); // This might not work, so -d allow_url_fopen=On was added in the shebang.

	//if(!ini_get('allow_url_include') || strtolower(ini_get('allow_url_include')) === 'off'){
	//	log_this('PHP setting "allow_url_include" is set to "'.ini_get('allow_url_include').'". Turn it on or there will be problems with compressed webpages.', LOG_WARNING);
	//}
	
	if(!ini_get('allow_url_fopen') || strtolower(ini_get('allow_url_fopen')) === 'off'){
		log_this('PHP setting "allow_url_fopen" is set to "'.ini_get('allow_url_fopen').'". Turn it on or there will be problems with compressed webpages.', LOG_WARNING);
	}
	// Ugly, but what can one do?
	function gzdecode($string) { // no support for 2nd argument
		return file_get_contents('compress.zlib://data:text/plain;base64,'.base64_encode($string));
	}
}

// Setup childcare
$children = array();
// Blocklist to avoid connection loops. Need some better protection.
$loop_blocklist = array('', strtolower($GLOBALS['DOMAINNAME']),gethostbyname($GLOBALS['DOMAINNAME'])); // Blank and servers domain name
if(isset($proxy_sockets)){
	foreach($proxy_sockets as $proxy_socket){ // Add every ip the server is listening on.
		if(is_resource($proxy_socket)){
			$loop_blocklist[] = current(explode(':',stream_socket_get_name($proxy_socket,false),2));
		}
	}
}

// Fork and close standard file descriptors if not in debug mode.
if($GLOBALS['DEBUGMODE']){
	log_this("Debug mode engadged.",LOG_NOTICE);
}else{
	// TODO, check if it was this that suppressed internal php error messages.
	// Close standard file descriptors
	if(!fclose(STDIN) || !fclose(STDOUT) || !fclose(STDERR)){
		log_this("Faild to close standard file descriptors.",LOG_WARNING);
	}

	// Fork off process.
	$pid = pcntl_fork();
	// Exit if forking fails.
	if($pid === -1){
		log_this('Unable to fork! Can not continue.',LOG_EMERG);
		exit(1);
	}
	// Exit if we are the parent process.
	if($pid) exit(0);
	// Now we are running as a daemon.
	// Clean up the $pid variable.
	unset($pid);
	// Assume ownership of our own process.
	if(posix_setsid()===-1){
		log_this('Unable to set sid! Can not continue.',LOG_EMERG);
		exit(1);
	}
}

// Clean up
unset($ip,$port,$errno,$errstr,$socket,$argv,$argc,$conf_file,$_GET,$_POST,$_COOKIE,$_FILES,$_SERVER);
if (function_exists('gc_enable')) {
	gc_enable();
	gc_collect_cycles();
}

//var_dump(get_defined_vars());


while(1) {
	/*MM"""Mq.                                     mm       `7MM
	  MM   `MM.                                    MM         MM
	  MM   ,M9 ,6"Yb.  `7Mb,od8 .gP"Ya `7MMpMMMb.mmMMmm       MM  ,pW"Wq.   ,pW"Wq.`7MMpdMAo.
	  MMmmdM9 8)   MM    MM' "',M'   Yb  MM    MM  MM         MM 6W'   `Wb 6W'   `Wb MM   `Wb
	  MM       ,pm9MM    MM    8M""""""  MM    MM  MM         MM 8M     M8 8M     M8 MM    M8
	  MM      8M   MM    MM    YM.    ,  MM    MM  MM         MM YA.   ,A9 YA.   ,A9 MM   ,AP
	.JMML.    `Moo9^Yo..JMML.   `Mbmmd'.JMML  JMML.`Mbmo    .JMML.`Ybmd9'   `Ybmd9'  MMbmmd'
	                                                                                 MM
	                                                                               .JMM*/
	while(1){
		while (($chldpid = pcntl_wait($status,WNOHANG)) > 0) {
			debug_this("Child terminated. PID:$chldpid");
			unset($children[$chldpid]);
			if(pcntl_wifexited($status)){ // Checks if status code represents a normal exit
				debug_this("Child $chldpid completed. Exitcode=".pcntl_wexitstatus($status));
			}elseif(pcntl_wifstopped($status)){
				debug_this("Child $chldpid stopped by a signal. Signal=".pcntl_wstopsig($status));
			}elseif(pcntl_wifsignaled($status)){ // Oh no, my child is dead. Make dead baby jokes.
				debug_this("Child $chldpid terminated by a signal. Signal=".pcntl_wtermsig($status));
			}
		}
		// Limit the amount of connections.
		// Wait until another one has exited before checking for new incomming.
		if(count($children) < $GLOBALS['MAXCONNECTIONS']){
			// Check every socket
			foreach($proxy_sockets as $socket){
				// Accept new connections.
				if(($client_socket = @stream_socket_accept($socket, 0, $client_ipport))){
					$GLOBALS['STARTTIME'] = microtime(true); // Store microsecond time for measurements.
					// Debugging without inreference
					//if(substr($client_ipport,0,2) !== '84'){
					//	fwrite($client_socket, error_response('503 Service Unavailable',"Site Temporarily Down for Maintenance. Please try again later."));
					//	@fclose($client_socket);
					//	debug_this("Killed connection from $client_ipport. Moahaha!");
					//}else{
						break 2;
					//}
				}
			}
		}
		// Do not eat CPU.
		usleep(1000);
	}
	
	// Fork off!
	$pid = pcntl_fork();
	if($pid === 0){
		// This is now a child process, break out of the parents main loop.
		break;
	}elseif($pid === -1){
		// Failed to fork a new child process to handle the new connection.
		// Close the new connection.
		stream_socket_shutdown($client_socket,STREAM_SHUT_RDWR); // Disable further receptions and transmissions.
		// Warn
		log_this('Failed to fork a new child process to handle the new connection.',LOG_ERR);
	}
	// Parent
	$children[$pid] = $client_ipport; // Store pid and clients ip:port
}

  /*8"""bgd `7MM          db  `7MM      `7MM        mm   `7MM                                      `7MM
.dP'     `M   MM                MM        MM        MM     MM                                        MM
dM'       `   MMpMMMb.  `7MM    MM   ,M""bMM      mmMMmm   MMpMMMb.  `7Mb,od8 .gP"Ya   ,6"Yb.   ,M""bMM
MM            MM    MM    MM    MM ,AP    MM        MM     MM    MM    MM' "',M'   Yb 8)   MM ,AP    MM
MM.           MM    MM    MM    MM 8MI    MM        MM     MM    MM    MM    8M""""""  ,pm9MM 8MI    MM
`Mb.     ,'   MM    MM    MM    MM `Mb    MM        MM     MM    MM    MM    YM.    , 8M   MM `Mb    MM
  `"bmmmd'  .JMML  JMML..JMML..JMML.`Wbmd"MML.      `Mbmo.JMML  JMML..JMML.   `Mbmmd' `Moo9^Yo.`Wbmd"M*/



$buffer = array('request' => '', 'request_tmp' => '', 'response' => '', 'response_tmp' => '');// Set up buffers

// Catch signals
pcntl_signal(SIGTERM, "forcefully_terminate_child",true);
pcntl_signal(SIGINT, "gracefully_terminate_child",true);
pcntl_signal(SIGALRM, "gracefully_terminate_child", true);

pcntl_alarm($GLOBALS['CONNECTIONTIMEOUT']);// Set a timeout to terminate this child.

proc_nice(5);// Make it nicer.

if(is_callable('setproctitle'))setproctitle(SOFTWARE." ".VERSION.": ".$client_ipport);// Set title

debug_this("New connection from ".$client_ipport);

unset($children,$proxy_sockets,$socket,$chldpid,$pid,$status); // Unset unused variables to free some memory.

stream_set_write_buffer($client_socket,$GLOBALS['STREAMRWBUFFER']); // Set the streams writebuffer.
if(is_callable('stream_set_read_buffer'))stream_set_read_buffer($client_socket,$GLOBALS['STREAMRWBUFFER']);
stream_set_blocking($client_socket, false); // Non-blocking connection

$incomming_port = (int)@array_pop(explode(':',stream_socket_get_name($client_socket,false))); // Extract port from "1.2.3.4:80", the port our client used to connected to us.
$host_port = 80;
$host_ip = '';
$host_socket = stream_context_create();
stream_context_set_option($host_socket, 'ssl', 'allow_self_signed', true);



if($incomming_port === 443){
	// start SSL on the connection
	debug_this("SSL connection from ".$client_ipport);
	// Setup the SSL Options
	stream_context_set_option($client_socket, 'ssl', 'local_cert', $GLOBALS['PEMFILE']);
	stream_context_set_option($client_socket, 'ssl', 'passphrase', $GLOBALS['PEMPASSPHRASE']);
	
	
	//stream_context_set_option($client_socket, 'ssl', 'allow_self_signed', true);
	//stream_context_set_option($client_socket, 'ssl', 'verify_peer', false);	
	
	// Forward Secrecy
	// http://www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT
	// http://se.php.net/manual/en/context.ssl.php
	
	//'kEDH+AES+HIGH:kEDH+3DES+HIGH@STRENGTH' roughtly translates to:
	// (cipher suites using ephemeral DH key agreement AND cipher suites
	// using AES AND those with key lengths larger than 128 bits, and some
	// cipher suites with 128-bit keys) OR (cipher suites using ephemeral DH key
	// agreement AND cipher suites using triple DES AND those with key lengths
	// larger than 128 bits, and some cipher suites with 128-bit keys) @ Sort by strength
	
	stream_context_set_option($client_socket, 'ssl', 'ciphers', 'kEDH+AES+HIGH:kEDH+3DES+HIGH@STRENGTH');
	
	
	// block the connection until SSL is done.
	stream_set_blocking ($client_socket, true);
	// Enable encryption
	if(!stream_socket_enable_crypto($client_socket, true, STREAM_CRYPTO_METHOD_TLS_SERVER)){
		// Debug errors
		while ($ssl_error = openssl_error_string())debug_this($ssl_error);
		gracefully_terminate_child();
	}
	// unblock connection if blocked
	stream_set_blocking ($client_socket, false);
	
}



// Attach proxy filter
//stream_filter_append($client_socket, "htmlproxy_response", STREAM_FILTER_WRITE, array('proxy_hostname' => $SETTINGS['DOMAINNAME']));
stream_filter_append($client_socket, "htmlproxy_request", STREAM_FILTER_READ, array('proxy_hostname' => $GLOBALS['DOMAINNAME']));

// Make the stream unbuffered to allow large writes.
//stream_set_write_buffer($client_socket, 0);

// Find host
$buffer['request_tmp'] = fread($client_socket,8192);
while(!preg_match('/\nHost:([^\r\n]+)\r?\n/i', $buffer['request_tmp'], $m)){
	if(strpos($buffer['request_tmp'], "\r\n\r\n")!==false || strpos($buffer['request_tmp'], "\n\n")!==false){
		debug_this("No host header.");
		// Send back a response containg an error message.
		fwrite($client_socket, error_response('400 Bad Request',"No host header found. Can not forward the request."));
		gracefully_terminate_child();
	}
	debug_this("Have not found host in \$buffer['request_tmp'] yet.");
	usleep(1000);
	//sleep(2);
	$buffer['request_tmp'] .= fread($client_socket,8192);
	// Kolla timeout
}

if($incomming_port !== 443){
	// What to do if the connection is not secure.
	// Extract host and url, then redirect.
}


//log_this(stream_socket_get_name($client_socket,true)." requests $m[0]:$host_port",LOG_INFO);
// Extract hostname
$host_name = preg_replace('/[^a-z0-9-\.]/i','',$m[1]); // Clean hostname.  Should maby allow ":" for port.
$host_name = str_replace(".".strtolower($GLOBALS['DOMAINNAME']), '', trim(strtolower($host_name))); // Fix hostname
// Search for hostname in loop blocklist
if(in_array($host_name, $loop_blocklist)){
		fwrite($client_socket,redirect_to('http://www.'.$GLOBALS['DOMAINNAME']));
		gracefully_terminate_child();
}

if(!preg_match('/(^|\.)([A-z234567]{16})$/',$host_name,$m)){ // Onion

	// Redirect to the regular intrawebs.
	
}else{
	$host_name .= '.onion';
	// tor2web.org Blocklist. Redirect to disney.com :P
	// TODO Move this to the conf-file, or to a sepparate file.
	if(in_array(md5($m[2]), array(	'f32f7088f1d225b6b5c56d5ec4e5e6c9',
									'd1faaa36d01964d1f987fe992006ed23',
									'9b666b99f9f709771180752fac4e784e',
									'fa2f9722a68806e3536a1b9b41783359',
									'912cddddf31444dfa1005fabf548c8f7',
									'6d3d9fc735a24112462dc2c5bc547633',
									'97ff8f3fd33068ddea053fae8c93daf7',
									'1e49bcafa8a011f31a826d0bd60281bc',
									'3d02ac074220d684ed099897d304e082',
									'f7b037fb61dc00147490727cfce7f2dd',
									'65c5152d8e4d3b4d097612e6df8eab93',
									'5b225270bb26ac71ba43d64e3f6ebddd',
									'96ad66add82b63ab4f048707117ce059',
									'67f5031a2d6d13501aaa03dbbf500260',
									'ced3a2ca13737e4fb123122cf251127b',
									'b114e2f1586f245798c2ffb77e4f0736',
									'ea2f93383a900d185287144227d4de12',
									'c22a4915ee32837c2ea23baa0d13dd28',
									'ec4a616918520ab0b8ef4431269e979d',
									'4d7c82d9cab0fe2c85cf30e12518ec48',
									'35d7dea6c8c58cc286fdb0e8bb3cbcba',
									'27c58ae958152d4c9a4096fe6e3c981f',
									'2bbeb602d75369444a42ab8c6128b7da',
									'ad88d74b68a90fdbd46be85a0',// What is this?
									'5226a016c2a35e5319b7fb7055e5c0e4',
									'41fa8ab62b668535630eb27a629d04fa',
									'7769b475c5560256f802dd862fe0f4dd',
									'c31724523ad91fe71e0550ca370b3451',
									'83cd40ff930ae98c46e273a28e9c7cc6',
									'b2719c5a5f1ef72a936621c7968f4f26',
									'5db5e677370019e3907091ad92580cf6'
						)
		)
	){
		fwrite($client_socket,redirect_to('http://disney.com')); // Go to disney.com
		accesslog_this("Blocked by domain blocklist");
		gracefully_terminate_child();
	}
}



// Connect to Socks5 proxy.
debug_this("Connecting to socks5 proxy ".$GLOBALS['SOCKS5IP'].":".$GLOBALS['SOCKS5PORT']."...");
if(!$host_socket = stream_socket_client("tcp://".$GLOBALS['SOCKS5IP'].":".$GLOBALS['SOCKS5PORT'], $errno, $errstr, 30,STREAM_CLIENT_CONNECT, $host_socket)){
	log_this("Failed to connect to socks5 proxy ".$GLOBALS['SOCKS5IP'].":".$GLOBALS['SOCKS5PORT'], LOG_CRIT);
	fwrite($client_socket, error_response('500 Internal Server Error',"Failed to connect to socks5 proxy ".$GLOBALS['SOCKS5IP'].":".$GLOBALS['SOCKS5PORT']));
	gracefully_terminate_child();
}
stream_set_write_buffer($host_socket,$GLOBALS['STREAMRWBUFFER']); // Set the streams writebuffer.
if(is_callable('stream_set_read_buffer'))stream_set_read_buffer($host_socket,$GLOBALS['STREAMRWBUFFER']);
stream_set_blocking($host_socket, true);
debug_this("Connected to socks5 proxy ".$GLOBALS['SOCKS5IP'].":".$GLOBALS['SOCKS5PORT'].".");
debug_this("Negotiationg method with socks5 proxy.");
if(3 !== fwrite($host_socket,"\x05\x01\x00")){
	log_this("Error 1 in communication with upstream proxy.", LOG_CRIT);
	fwrite($client_socket, error_response('502 Bad Gateway',"Error 1 in communication with upstream proxy. 1"));
	gracefully_terminate_child();
}

$buf = fread($host_socket,2);

while(strlen($buf) < 2){
	//usleep(1000);
	$buf .= fread($host_socket,1);

}
if(ord($buf[0]) !== 5 || ord($buf[1]) !== 0 ){
	debug_this("Socks5 proxy returned error.");
	log_this("Error 2 in communication with upstream proxy.", LOG_CRIT);
	fwrite($client_socket, error_response('502 Bad Gateway',"Error 2 in communication with upstream proxy."));
	gracefully_terminate_child();
}

if(strlen($host_name) > 255){
	// Host name to long
	//debug_this("Host name to long for socks5 proxy.");
	fwrite($client_socket, error_response('400 Bad Request',"Host name too long. Cannot exceed 255 bytes."));
	gracefully_terminate_child();
}
debug_this("Requesting proxy to connect to $host_name:$host_port.");
$buf = pack("C5", 0x05, 0x01, 0x00, 0x03, strlen($host_name)).$host_name.pack("n", (int)$host_port);
$bytes = strlen($buf);
if($bytes !== fwrite($host_socket,$buf)){
	//debug_this("Socks5 proxy returned error.");
	log_this("Error 3 in communication with upstream proxy.", LOG_CRIT);
	fwrite($client_socket, error_response('502 Bad Gateway',"Error 3 in communication with upstream proxy."));
	gracefully_terminate_child();
}



// Optimistic data
if($GLOBALS['SOCKS5OPTIMISTICDATA']){
	// Send all data we can.
	$buffer['request_tmp'] = substr($buffer['request_tmp'], (int)fwrite($host_socket,$buffer['request_tmp']));
}

$buf = fread($host_socket,4);
debug_this("Got: ".str2hex($buf));

while(strlen($buf) < 4){
	//usleep(1000);
	$buf .= fread($host_socket,4-strlen($buf));

}

debug_this("Read ".strlen($buf)." bytes.");
if(ord($buf[0]) !== 5){
	debug_this("Socks5 proxy returned error.");
	fwrite($client_socket, error_response('502 Bad Gateway',"Error in communication with upstream proxy."));
	gracefully_terminate_child();
}
if(ord($buf[1]) !== 0 ){
	$socks5errors = array(	0 => 'Request granted',
							1 => 'Temporarily unable to communicate with '.$host_name,
							2 => 'Temporarily unable to communicate with '.$host_name,
							3 => 'Network unreachable',
							4 => 'Host unreachable',
							5 => 'Connection refused by '.$host_name,
							6 => 'Host unreachable, connection timed out',
							7 => 'Temporarily unable to communicate with the onion network',
							8 => 'Address type not supported'
	);
	//fwrite($client_socket, error_response('502 Bad Gateway',"Upstream proxy returned error ".(ord($buf[1])%9)." '".$socks5errors[ord($buf[1])%9]."'."));
	fwrite($client_socket, error_response('502 Bad Gateway',"Tor error(".(ord($buf[1])%9)."): ".$socks5errors[ord($buf[1])%9]));
	gracefully_terminate_child();
}

// Be sure to catch the whole handshake from the socks server.
switch(ord($buf[3])){
	case 1:// IPv4
		//$buf .= fread($host_socket,10-strlen($buf));
		while(strlen($buf) < 10){
			//usleep(1000);
			$buf .= fread($host_socket,10-strlen($buf));
		}
		debug_this("Got: ".str2hex($buf));
		$host_ip = ord($buf[4]).'.'.ord($buf[5]).'.'.ord($buf[6]).'.'.ord($buf[7]);
		debug_this("IP:$host_ip");
	break;
	case 3: // Domain name
		//$buf .= fread($host_socket,7-strlen($buf));
		while(strlen($buf) < 7){
			//usleep(1000);
			$buf .= fread($host_socket,7-strlen($buf));
		}
		//$buf .= fread($host_socket,ord($buf[4])+7-strlen($buf));
		while(strlen($buf) < ord($buf[4])+7){
			//usleep(1000);
			$buf .= fread($host_socket,ord($buf[4])+7-strlen($buf));
		}
	break;
	case 4: // IPv6
		//$buf .= fread($host_socket,22-strlen($buf));
		while(strlen($buf) < 22){
			//usleep(1000);
			$buf .= fread($host_socket,22-strlen($buf));
		}
		// TODO Fix ipv6 ip here
		//$host_ip = ord($buf[4]).'.'.ord($buf[5]).'.'.ord($buf[6]).'.'.ord($buf[7]);
	break;
	default:
		// Warning.
}

// Search for hostname in loop blocklist
if(in_array($host_name, $loop_blocklist)){
		fwrite($client_socket,redirect_to('http://www.'.$GLOBALS['DOMAINNAME']));
		gracefully_terminate_child();
}

debug_this("Connected in ".round(microtime(true)-$GLOBALS['STARTTIME'],7)." sec to $host_name:$host_port throught socks5 proxy ".$GLOBALS['SOCKS5IP'].":".$GLOBALS['SOCKS5PORT'].".");
stream_set_blocking($host_socket, false);






// Accesslog
accesslog_this("Connected");
if(is_callable('setproctitle'))setproctitle(SOFTWARE." ".VERSION.": ".$client_ipport." connected");

debug_this("Connection to $host_name is open.");



// Attach proxy filter
//stream_filter_append($host_socket, "htmlproxy_request", STREAM_FILTER_WRITE, array('proxy_hostname' => $SETTINGS['DOMAINNAME']));
stream_filter_append($host_socket, "htmlproxy_response", STREAM_FILTER_READ, array('proxy_hostname' => $GLOBALS['DOMAINNAME']));

while(!feof($host_socket) && !feof($client_socket)){
	  /*8"""bgd `7MM          db  `7MM      `7MM      `7MM
	.dP'     `M   MM                MM        MM        MM
	dM'       `   MMpMMMb.  `7MM    MM   ,M""bMM        MM  ,pW"Wq.   ,pW"Wq.`7MMpdMAo.
	MM            MM    MM    MM    MM ,AP    MM        MM 6W'   `Wb 6W'   `Wb MM   `Wb
	MM.           MM    MM    MM    MM 8MI    MM        MM 8M     M8 8M     M8 MM    M8
	`Mb.     ,'   MM    MM    MM    MM `Mb    MM        MM YA.   ,A9 YA.   ,A9 MM   ,AP
	  `"bmmmd'  .JMML  JMML..JMML..JMML.`Wbmd"MML.    .JMML.`Ybmd9'   `Ybmd9'  MMbmmd'
	                                                                           MM
	                                                                         .JMM*/
	// Read incomming data into a buffer.
	if($GLOBALS['STREAMWRITECHUNK'] > strlen($buffer['request_tmp'])) $buffer['request'] = $buffer['request_tmp'].fread($client_socket,$GLOBALS['STREAMWRITECHUNK']-strlen($buffer['request_tmp']));
	// Write data.
	if(false===($buffer['request_tmp'] = @fwrite($host_socket, $buffer['request']))){
		//Error
		debug_this("Error while tranmiting request");
		if($error = socket_last_error())log_this('Sending to host caused an Error on line '.__LINE__.': '.socket_strerror($error),LOG_ERR);
		while ($error = openssl_error_string())log_this('Sending to host caused an SSL Error on line '.__LINE__.': '.$error,LOG_ERR);
		// Ressetting, try again.
		$buffer['request_tmp'] = 0;
	}
	if($buffer['request_tmp'])debug_this($buffer['request_tmp']." bytes of request transmited.");
	// Remove written data from the buffer.
	$buffer['request_tmp'] = substr($buffer['request'], $buffer['request_tmp']);
	
	// Read incomming data into a buffer.
	if($GLOBALS['STREAMWRITECHUNK'] > strlen($buffer['response_tmp'])) $buffer['response'] = $buffer['response_tmp'].fread($host_socket,$GLOBALS['STREAMWRITECHUNK']-strlen($buffer['response_tmp']));
	// Write data.
	if(false===($buffer['response_tmp'] = @fwrite($client_socket, $buffer['response']))){
		//Error
		debug_this("Error while tranmiting response");
		if($error = socket_last_error())log_this('Sending to client caused an Error on line '.__LINE__.': '.socket_strerror($error),LOG_ERR);
		while ($error = openssl_error_string())log_this('Sending to client caused an SSL Error on line '.__LINE__.': '.$error,LOG_ERR);
		// Ressetting, try again.
		$buffer['response_tmp'] = 0;
	}
	if($buffer['response_tmp'])debug_this($buffer['response_tmp']." bytes of response transmited.");
	// Remove written data from the buffer.
	$buffer['response_tmp'] = substr($buffer['response'], $buffer['response_tmp']);
	
	// Do not eat CPU.
	usleep(1000);
}

debug_this("One connection has been closed.");
//if(feof($client_socket))debug_this('FEOF Client.');
//if(feof($host_socket))debug_this('FEOF Host.');

debug_this("Client socket is '".@get_resource_type($client_socket)."'. Host socket is '".@get_resource_type($host_socket)."'.");
debug_this("Going to close the connections now.");

gracefully_terminate_child();

/*P""MM""YMM `7MM                    `7MM"""YMM                  `7MM
P'   MM   `7   MM                      MM    `7                    MM
     MM        MMpMMMb.  .gP"Ya        MM   d    `7MMpMMMb.   ,M""bMM
     MM        MM    MM ,M'   Yb       MMmmMM      MM    MM ,AP    MM
     MM        MM    MM 8M""""""       MM   Y  ,   MM    MM 8MI    MM
     MM        MM    MM YM.    ,       MM     ,M   MM    MM `Mb    MM
   .JMML.    .JMML  JMML.`Mbmmd'     .JMMmmmmMMM .JMML  JMML.`Wbmd"M*/

















/*MM"""YMM                                mm     db
  MM    `7                                MM
  MM   d `7MM  `7MM  `7MMpMMMb.  ,p6"bo mmMMmm `7MM  ,pW"Wq.`7MMpMMMb.  ,pP"Ybd
  MM""MM   MM    MM    MM    MM 6M'  OO   MM     MM 6W'   `Wb MM    MM  8I   `"
  MM   Y   MM    MM    MM    MM 8M        MM     MM 8M     M8 MM    MM  `YMMMa.
  MM       MM    MM    MM    MM YM.    ,  MM     MM YA.   ,A9 MM    MM  L.   I8
.JMML.     `Mbod"YML..JMML  JMML.YMbmd'   `Mbmo.JMML.`Ybmd9'.JMML  JMML.M9mmm*/


function gracefully_terminate_child(){
	global $host_socket, $client_socket, $buffer;
	// Turn off alarm and set a new one.
	// If data is still being transmitted from the last request,
	// we'll give it a some time to finnish.
	pcntl_alarm(0);
	pcntl_signal(SIGALRM, "forcefully_terminate_child", true);
	pcntl_alarm($GLOBALS['CONNECTIONTIMEOUT']/3);// Set a timeout to terminate this child.
	
	debug_this('Gracefully terminateing thread.');
	//debug_this("Host sent ".@ftell($host_socket)." bytes. Cient sent ".@ftell($client_socket).' bytes.');
	if(is_resource($client_socket) && is_resource($host_socket) && get_resource_type($client_socket)==='stream' && get_resource_type($host_socket)==='stream'){
		if(!is_string($buffer['request_tmp']))$buffer['request_tmp'] = substr($buffer['request'], (int)$buffer['request_tmp']);
		if(!is_string($buffer['response_tmp']))$buffer['response_tmp'] = substr($buffer['response'], (int)$buffer['response_tmp']);
		stream_set_blocking($client_socket, false);
		stream_set_blocking($client_socket, false);
		
		// Timelimit.
		$i = 0;
		$bytes = ftell($client_socket);
		
		while(!feof($client_socket)){
			// Read incomming data into a buffer.
			if($GLOBALS['STREAMWRITECHUNK'] > strlen($buffer['request_tmp'])) $buffer['request'] = $buffer['request_tmp'].fread($client_socket,$GLOBALS['STREAMWRITECHUNK']-strlen($buffer['request_tmp']));
			// Break out of loop if no data or if unable to write data
			if(!($buffer['request_tmp'] = @fwrite($host_socket, $buffer['request'])))break;
			// Remove written data from the buffer.
			$buffer['request_tmp'] = substr($buffer['request'], $buffer['request_tmp']);
			if($i++>1000){
				if($bytes === ftell($client_socket)) break;
				$i = 0;
				$bytes = ftell($client_socket);
			}
			// Do not eat CPU.
			usleep(1000);
		}
		
		stream_socket_shutdown($client_socket,STREAM_SHUT_RD); // Disable further receptions.
		stream_socket_shutdown($host_socket, STREAM_SHUT_WR); // Disable further transmissions.
		
		if(ftell($host_socket)===0)$buffer['response_tmp'] .= error_response('504 Gateway Timeout',"Proxy timed out after not recieving any data from the upstream server.");
		
		// Timelimit.
		$i = 0;
		$bytes = ftell($host_socket);
		
		while(!feof($host_socket)){
			// Read incomming data into a buffer.
			if($GLOBALS['STREAMWRITECHUNK'] > strlen($buffer['response_tmp'])) $buffer['response'] = $buffer['response_tmp'].fread($host_socket,$GLOBALS['STREAMWRITECHUNK']-strlen($buffer['response_tmp']));
			// Break out of loop if no data or if unable to write data
			if(!($buffer['response_tmp'] = @fwrite($client_socket, $buffer['response'])))break;
			// Remove written data from the buffer.
			$buffer['response_tmp'] = substr($buffer['response'], $buffer['response_tmp']);
			if($i++>1000){
				if($bytes === ftell($host_socket)) break;
				$i = 0;
				$bytes = ftell($host_socket);
			}
			// Do not eat CPU.
			usleep(1000);
		}
		
		stream_socket_shutdown($host_socket,STREAM_SHUT_RD); // Disable further receptions.
		stream_socket_shutdown($client_socket, STREAM_SHUT_WR); // Disable further transmissions.
	}elseif($host_socket && is_resource($host_socket)){
		//stream_socket_shutdown($host_socket,STREAM_SHUT_RDWR);
		@fclose($host_socket);
	}
	if(is_resource($client_socket)){
		//stream_socket_shutdown($client_socket, STREAM_SHUT_RDWR);
		@fclose($client_socket);
	}
	debug_this('Exiting thread.');
	exit(0);
}

function forcefully_terminate_child(){
	global $host_socket, $client_socket, $buffer;
	pcntl_alarm(0); // Turn off alarm
	log_this('Forcefully terminateing thread.',LOG_NOTICE);
	//debug_this("Host sent ".@ftell($host_socket)." bytes. Cient sent ".@ftell($client_socket).' bytes.');
	if(is_resource($client_socket) && is_resource($host_socket) && get_resource_type($client_socket)==='stream' && get_resource_type($host_socket)==='stream'){
		// $buffer['request_tmp'] and $buffer['response_tmp'] might be an int or a boolean, in which case me must extract it from $buffer['request'] or $buffer['response'].
		if(!is_string($buffer['request_tmp']))$buffer['request_tmp'] = substr($buffer['request'], (int)$buffer['request_tmp']);
		if(!is_string($buffer['response_tmp']))$buffer['response_tmp'] = substr($buffer['response'], (int)$buffer['response_tmp']);
		stream_set_blocking($client_socket, false);
		stream_set_blocking($client_socket, false);
		
		fwrite($host_socket, $buffer['request']); // Empty buffer.
		stream_socket_shutdown($client_socket,STREAM_SHUT_RD); // Disable further receptions.
		stream_socket_shutdown($host_socket, STREAM_SHUT_WR); // Disable further transmissions.
		if(ftell($host_socket)===0)$buffer['response_tmp'] .= error_response('504 Gateway Timeout',"Proxy timed out after not recieving any data from the upstream server.");
		fwrite($client_socket, $buffer['response_tmp']);
		stream_socket_shutdown($host_socket,STREAM_SHUT_RD); // Disable further receptions.
		stream_socket_shutdown($client_socket, STREAM_SHUT_WR); // Disable further transmissions.
	}elseif(is_resource($host_socket)){
		//stream_socket_shutdown($host_socket,STREAM_SHUT_RDWR);
		@fclose($host_socket);
	}
	if(is_resource($client_socket)){
		//stream_socket_shutdown($client_socket, STREAM_SHUT_RDWR);
		@fclose($client_socket);
	}
	//if(is_resource($client_socket) || is_resource($host_socket))log_this("Sockets still recources.",LOG_CRIT);
	log_this('Exiting thread.',LOG_NOTICE);
	exit(0);
}



function termint_handler($signal) {
	global $children, $proxy_sockets, $LOG_FD;
	// Log
	if($signal === SIGTERM)log_this("Caught SIGTERM. Forcefully terminateing all threads.",LOG_CRIT);
	elseif($signal === SIGINT)log_this("Caught SIGINT. Gracefully terminateing all threads.",LOG_CRIT);
	else return false;
	// Close listening sockets
	if(isset($proxy_sockets))foreach($proxy_sockets as $proxy_socket){
		@stream_socket_shutdown($proxy_socket, STREAM_SHUT_RDWR);
		@fclose($proxy_socket);
	}
	// Forward the signal to all the children.
	//if(isset($children))foreach($children as $pid => $ip)posix_kill($pid, $signal);
	// If pid equals 0, then sig is sent to every process in the process group of the current process.
	posix_kill(0, $signal);

	while(count($children)){
		if(-1 !== ($chldpid = pcntl_wait($status))){
			debug_this("Child $chldpid has terminated.");
			unset($children[$chldpid]);
			if(pcntl_wifexited($status)){ // Checks if status code represents a normal exit
				debug_this("Child $chldpid completed. Exitcode=".pcntl_wexitstatus($status));
			//}elseif(pcntl_wifstopped($status)){
			//	debug_this("Child $chldpid stopped by a signal. Signal=".pcntl_wstopsig($status));
			}elseif(pcntl_wifsignaled($status)){ // Oh no, my child is dead. Make dead baby jokes.
				debug_this("Child $chldpid terminated by signal ".pcntl_wtermsig($status));
			}
		}
	}
	// Close the accesslogfile.
	if($GLOBALS['ACCESSLOGFILE'] && is_resource($LOG_FD)){
		fclose($LOG_FD);
	}
	log_this('Exiting '.SOFTWARE.' '.VERSION, LOG_NOTICE);
	if($GLOBALS['USESYSLOG']){
		closelog();
	}
	exit(0);
}

function error_response($code,$msg){
	global $client_ipport, $host_name, $host_port, $host_ip;
	accesslog_this($msg);
	$code = preg_replace('/[^a-z0-9 ]/i','',$code);
	$msg = 	"<html>\n".
			"<head><title>$code</title></head>\n".
			"<body bgcolor=white>\n".'<center>
<pre style=font-size:6pt;letter-spacing:0;line-height:4pt;font-weight:bold;>
<span style=color:#fff>####</span><span style=color:#fffffd>##</span><span style=color:#fff>#</span><span style=color:#fefffb>#</span><span style=color:#fffffb>#</span><span style=color:#fffffd>#</span>
<span style=color:#fff>###</span><span style=color:#fffffd>##</span><span style=color:#fcfdff>#</span><span style=color:#c7e293>#</span><span style=color:#edfcd5>#</span><span style=color:#fefff4>#</span><span style=color:#fffffd>#</span>
<span style=color:#fff>####</span><span style=color:#fdfff9>#</span><span style=color:#ddfba5>#</span><span style=color:#7ba01d>#</span><span style=color:#fcfeff>#</span><span style=color:#fffffd>##</span>
<span style=color:#fff>###</span><span style=color:#fdfef9>#</span><span style=color:#fffdff>#</span><span style=color:#698636>#</span><span style=color:#fcfffa>#</span><span style=color:#fffffd>###</span>
<span style=color:#fff>###</span><span style=color:#f8faf7>#</span><span style=color:#baaf99>#</span><span style=color:#94a756>#</span><span style=color:#fffffd>####</span>
<span style=color:#fff>###</span><span style=color:#fffffa>#</span><span style=color:#fef9d1>#</span><span style=color:#fbe9f9>#</span><span style=color:#fffffd>####</span>
<span style=color:#fffffd>##</span><span style=color:#f6f7f2>#</span><span style=color:#0c021d>#</span><span style=color:#f1f0c4>#</span><span style=color:#a89994>#</span><span style=color:#180734>#</span><span style=color:#fff>#</span><span style=color:#fffffd>##</span>
<span style=color:#fffffd>#</span><span style=color:#fffcff>#</span><span style=color:#fffed7>#</span><span style=color:#f0efc1>#</span><span style=color:#efecc1>#</span><span style=color:#d2d1a1>#</span><span style=color:#a489b6>#</span><span style=color:#aa8db9>#</span><span style=color:#faf8fd>#</span><span style=color:#fffffd>#</span>
<span style=color:#f9faf4>#</span><span style=color:#cdc8b5>#</span><span style=color:#fcfad1>#</span><span style=color:#fceed3>#</span><span style=color:#f1efc6>#</span><span style=color:#e1d9b5>#</span><span style=color:#351852>#</span><span style=color:#936ea1>#</span><span style=color:#9574ad>#</span><span style=color:#fefeff>#</span>
<span style=color:#efeaf0>#</span><span style=color:#ededbb>#</span><span style=color:#f0ebcd>#</span><span style=color:#efefbd>#</span><span style=color:#e8e3bd>#</span><span style=color:#d9d5a5>#</span><span style=color:#b3afa3>#</span><span style=color:#7f5692>#</span><span style=color:#7c5493>#</span><span style=color:#2d265a>#</span>
<span style=color:#070000>#</span><span style=color:#c6bdac>#</span><span style=color:#f6f5c9>#</span><span style=color:#f5f1cc>#</span><span style=color:#ebecc2>#</span><span style=color:#e2dda6>#</span><span style=color:#d7d1b1>#</span><span style=color:#70428b>#</span><span style=color:#663785>#</span><span style=color:#00060f>#</span>
<span style=color:#170f24>#</span><span style=color:#bab59f>#</span><span style=color:#564b45>#</span><span style=color:#eeedc1>#</span><span style=color:#fffcdf>#</span><span style=color:#dfd8bb>#</span><span style=color:#beb69f>#</span><span style=color:#5c2d7e>#</span><span style=color:#59297d>#</span><span style=color:#0c0018>#</span>
<span style=color:#fffffb>#</span><span style=color:#e8e7b1>#</span><span style=color:#f9f6d3>#</span><span style=color:#eeefc7>#</span><span style=color:#f3f2c2>#</span><span style=color:#a49e86>#</span><span style=color:#070a1b>#</span><span style=color:#4f1f75>#</span><span style=color:#522077>#</span><span style=color:#fffffb>#</span>
<span style=color:#fffffd>#</span><span style=color:#a79fb6>#</span><span style=color:#f3eece>#</span><span style=color:#fdfdc9>#</span><span style=color:#fffedd>#</span><span style=color:#eae6c0>#</span><span style=color:#3b2266>#</span><span style=color:#521f7c>#</span><span style=color:#100820>#</span><span style=color:#fcfff6>#</span>
<span style=color:#fffffd>##</span><span style=color:#fefdf9>#</span><span style=color:#352667>#</span><span style=color:#42344d>#</span><span style=color:#0a050b>#</span><span style=color:#000404>#</span><span style=color:#fbfffc>#</span><span style=color:#fbfef5>#</span><span style=color:#fcfff6>#</span>
</pre></center>'.
			"<center><h1><span style='color:#8335a3'>O<span style=color:#68b12e>n</span>i<span style=color:#68b12e>o</span>n<span style=color:#68b12e>.</span>T<span style=color:#68b12e>o</span></span></span></h1></center>\n".
			"<center><h3>".htmlspecialchars($msg)."</h3></center>\n".
			"<hr><center>Powered by ".SOFTWARE." ".htmlspecialchars(VERSION)."</center>\n".
			"</body>\n".
			"</html>\n";
	
	return	"HTTP/1.1 $code\r\n".
			"Connection: close\r\n".
			"Content-Length: ".strlen($msg)."\r\n".
			"\r\n".
			$msg;
}


function redirect_to($url){
	$msg = 	"<html>\n".
			"<head><title>Onion.To</title></head>\n".
			"<body bgcolor=white>\n".
			'<meta HTTP-EQUIV="REFRESH" content="0; url='.htmlentities($url).'">';
			'<a href="'.htmlentities($url)."\"\n".
			"<hr><center>Powered by ".SOFTWARE." ".htmlspecialchars(VERSION)."</center>\n".
			"</body>\n".
			"</html>\n";
	
	return	"HTTP/1.1 302\r\n".
			"Location: ".str_replace("\r\n",'',$url)."\r\n".
			"Connection: close\r\n".
			"Content-Length: ".strlen($msg)."\r\n".
			"\r\n".
			$msg;
}

function error_handler($errno, $errstr, $errfile, $errline, $errcontext){
	if(error_reporting() === 0) return true;
	switch ($errno) {
		case E_NOTICE:
		case E_USER_NOTICE:
			log_this("($errno) $errstr in $errfile on line $errline.",LOG_NOTICE);
			break;
		case E_WARNING:
		case E_USER_WARNING:
			log_this("($errno) $errstr in $errfile on line $errline.",LOG_WARNING);
			break;
		case E_RECOVERABLE_ERROR:
			log_this("($errno) $errstr in $errfile on line $errline.",LOG_ERR);
			break;
		case E_ERROR:
		case E_USER_ERROR:
			log_this("($errno) $errstr in $errfile on line $errline.",LOG_EMERG);
			break;
		default:
			log_this("(Unknown PHP error level $errno) $errstr in $errfile on line $errline.",LOG_ERR);
			break;
	}
	return true;
}

function log_this($msg, $lvl){
	if($lvl > $GLOBALS['LOGLEVEL'] && !$GLOBALS['DEBUGMODE'])return false;
	$msg = preg_replace("/\s/",' ',$msg);
	//$msg = preg_replace("/%m/",' m',$msg);
	
	if($GLOBALS['USESYSLOG'] && !$GLOBALS['DEBUGMODE']){
		syslog($lvl, $msg);
	}
	
	// If debugging, we'll want the pid.
	// Oh yes, that sweet sweet pid. WE CRAVE IT!
	// Oh how we crave it.
	if($GLOBALS['DEBUGMODE']) $msg = '[PID:'.posix_getpid()."] $msg";
	
	switch($lvl){
		case LOG_EMERG:$msg = "[!] $msg";break;
		case LOG_ALERT:$msg = "[A] $msg";break;
		case LOG_CRIT:$msg = "[C] $msg";break;
		case LOG_ERR:$msg = "[E] $msg";break;
		case LOG_WARNING:$msg = "[W] $msg";break;
		
		case LOG_NOTICE:$msg = "[N] $msg";break;
		case LOG_INFO:$msg = "[i] $msg";break;
		case LOG_DEBUG:$msg = "[D] $msg";break;
	}
	
	$msg = '['.date(DATE_RFC2822)."] $msg\n";
		
	switch($lvl){
		case LOG_EMERG:case LOG_ALERT:case LOG_CRIT:case LOG_ERR:case LOG_WARNING:
			@fwrite(STDERR,$msg);
			break;
		case LOG_NOTICE:case LOG_INFO:case LOG_DEBUG:
			@fwrite(STDOUT,$msg);
	}

}

function accesslog_this($msg){
	global $LOG_FD, $client_ipport, $host_name, $host_port, $host_ip;
	if($LOG_FD){
		list($client_ip,$client_port) = explode(':',$client_ipport);
		$msg = sprintf(	$GLOBALS['ACCESSLOGFORMAT'],
						date($GLOBALS['DATEFORMAT']), // %1$s
						posix_getpid(), // %2$u
						microtime(true)-$GLOBALS['STARTTIME'], // %3$f
						$client_ip, // %4$s
						$client_port, // %5$s
						$host_name, // %6$s
						$host_ip, // %7$s
						$host_port, // %8$s
						$msg // %9$s
		);
		fwrite($LOG_FD, preg_replace("/\s/",' ',$msg)."\n");
		//fwrite($LOG_FD, '['.date(DATE_RFC2822).'] [PID:'.posix_getpid().'] '.preg_replace("/\s/",' ',$msg)."\n");
	}
	return true;
}

function debug_this($msg){
	return log_this($msg, LOG_DEBUG);
}


function str2hex($string){
    $hex='';
    for ($i=0; $i < strlen($string); $i++)
    {
        $hex .= dechex(ord($string[$i]))." ";
    }
    return $hex;
}

function dropPrivilegesTo($user){
	if(false===($userinfo = posix_getpwnam($user))){
		log_this("Can not find user $user. System error message: ".posix_strerror(posix_get_last_error()),LOG_ERR);
		return false;
	}
	if(false===posix_setgid($userinfo['gid'])){
		log_this("Can not set group id to {$userinfo['gid']}. System error message: ".posix_strerror(posix_get_last_error()),LOG_ERR);
		return false;
	}
	if(false===posix_setuid($userinfo['uid'])){
		log_this("Can not set user id to {$userinfo['uid']}. System error message: ".posix_strerror(posix_get_last_error()),LOG_ERR);
		return false;
	}
	log_this("Dropped privileges to User id:".posix_getuid()." and Group id:".posix_getgid(),LOG_NOTICE);
	return true;
}


/*
*      CLIENT TO SERVER
*/

class htmlproxy_request_filter extends php_user_filter{
    private $buf;
	//private $stream_body = false;
	private $proxy_hostname = '';
	private $content_left = 0;

    /* Called when the filter is initialized */
    function onCreate(){
		debug_this('Creating new htmlproxy_request_filter.');
        $this->buf = '';
		if(isset($this->params['proxy_hostname']))
			$this->proxy_hostname = (string)$this->params['proxy_hostname'];
        return true;
    }

    /* This is where the actual stream data conversion takes place */
    public function filter($in, $out, &$consumed, $closing){

		if($this->content_left > 0){
			// If the buffer isn't empty
			if(!empty($this->buf)){
				// Get a new empty bucket and fill it with buffered data.
				$bucket = stream_bucket_new($this->stream, $this->buf);
				// Decrese content_left
				$this->content_left -= $bucket->datalen;
				// If we got more data than intended.
				if($this->content_left < 0){
					// Put the overflow in our buffer
					$this->buf = substr($bucket->data,$this->content_left);
					// And the remaining data in the bucket.
					$bucket->data = substr($bucket->data,0,$this->content_left);
					// Reset content_left
					$this->content_left = 0;
					// Expect a new header
					//$this->partitial_headers = true;
				}
				// Output buffered data.
				stream_bucket_append($out, $bucket);
				// Empty the buffer
				$this->buf = '';
			}
			
			while($this->content_left && ($bucket = stream_bucket_make_writeable($in))){
				// Increment $consumed
				$consumed += $bucket->datalen;
				// Decrese content_left
				$this->content_left -= $bucket->datalen;
				// If we got more data than intended.
				if($this->content_left < 0){
					// Put the overflow in our buffer
					$this->buf = substr($bucket->data,$this->content_left);
					// And the remaining data in the bucket.
					$bucket->data = substr($bucket->data,0,$this->content_left);
					// Reset content_left
					$this->content_left = 0;
					// Expect a new header
					//$this->partitial_headers = true;
				}
				debug_this($bucket->data);
				// Stream content
				stream_bucket_append($out, $bucket);
				debug_this($this->content_left." bytes of content left to strem.");
			}
			return PSFS_PASS_ON;
		}

		if($closing){ // No need to send a request if the client is closing its socket... I think.
			debug_this("Closing!");
			
			if($bucket = stream_bucket_make_writeable($in)){
				//$consumed += $bucket->datalen;
				log_this("Closing with {$bucket->datalen} bytes of a request in a bucket! {$bucket->data}",LOG_WARNING);
			}
			if(!empty($this->buf)){
				log_this("Closing with ".strlen($this->buf)." bytes of a request in a buf! ".$this->buf,LOG_WARNING);
			}
		}
	
		if($bucket = stream_bucket_make_writeable($in)){
			$this->buf .= $bucket->data;
			$consumed += $bucket->datalen;
		}
		
		// Check if we have got all of the headers
		if(false!==($eoh = strpos($this->buf, "\r\n\r\n"))){
			$headers = substr($this->buf,0,$eoh+4);
			$this->buf = substr($this->buf,$eoh+4);
		}elseif(false!==($eoh = strpos($this->buf, "\n\n"))){
			$headers = substr($this->buf,0,$eoh+2);
			$this->buf = substr($this->buf,$eoh+2);
		}else{
			//debug_this("Read {$bucket->datalen} bytes, no header yet.");
			// Wait until we have got all of the headers
			return PSFS_FEED_ME;
		}
		//debug_this("Got: ".str2hex($headers));
		//debug_this("Got: ".str2hex($this->buf));
		//debug_this($headers);
		// We have got all of the headers
		
		// DEBUG accesslog
		//global $client_ipport;
		//$host = preg_match('/Host:\s?([^\r\n ]+)/', $headers, $m)?$m[1]:'';
		//if(!preg_match('/(GET|POST|HEAD|PUT|DELETE|TRACE|CONNECT|OPTIONS)\s?(\S+)/', $headers, $m))$m=array(1=>'',2=>'');
		//accesslog_this("$m[1] $host$m[2]");
		
		
		// Set some default values
		$this->content_left = 0;

		
		// Method
		//$method = strstr($headers, ' ', true);
		//debug_this("Request method: $method");
		//if($method==='POST'){ // Lфs specifikationerna pх PUT
			// Stream the message body
			//$this->stream_body = true;

			
		//}
		// Content-Length
		if(preg_match('/\nContent-Length:\s*(\d+)/i',$headers,$m)){
			$this->content_left = (int)$m[1];
		}//else{
			debug_this("Content-Length not specified.");
		//}
			
		//$headers = preg_replace('/^Host:\s?(.*?)\.'.preg_quote($this->proxy_hostname,'/').'.*(\r?)$/m', 'Host: \\1\\2', $headers, 1);
		$headers = preg_replace('/(\nHost:\s*[A-z0-9\.-]*)\.'.preg_quote($this->proxy_hostname,'/').'/i', '\\1', $headers, 1);
		
		//$buffer['request'] = preg_replace('/^Host:.*(\r?)$/m', "Host: $host_name\\1", $buffer['request'], 1);
		
		// Make sure response is not gziped.
		//$headers = preg_replace('/\nAccept-Encoding:[^\r\n]*/i', "\nAccept-Encoding: identity", $headers, 1);
		//$headers = preg_replace('/sdch/', "Accept-Encoding: identity\\1", $headers, 1);
		if(preg_match('/\nAccept-Encoding:([^\r\n]*?sdch[^\r\n]*)/i',$headers,$m)){
			// We do not do sdch compressions.
			str_replace($m[0],preg_replace('/sdch(;q=[0-9\.](,\s?)?)?/','',$m[0]),$headers);
		}
		
		// Refferer
		//$headers = preg_replace('/^(Referr?er:.*?)\.'.preg_quote($this->proxy_hostname,'/').'(.*\r?)$/m', '\\1\\2', $headers, 1);
		$headers = preg_replace('/(\nReferr?er:[^\r\n]*)\.'.preg_quote($this->proxy_hostname,'/').'/i', '\\1', $headers, 1);
		
		//http://www.jmarshall.com/easy/http/#http1.1s2
		
		//$bucket = stream_bucket_new($this->stream, '');
		//$bucket->data = $headers;
		//stream_bucket_append($out, $bucket);
		
		debug_this("Got headers: ".str2hex($headers));
		//debug_this("Got: ".str2hex($this->buf));
		
		// Stream out a new bucket filled with headers.
		stream_bucket_append($out, stream_bucket_new($this->stream, $headers));
		
		
		//$bucket->data = $headers;
		//$bucket->datalen = strlen($bucket->data);
		//debug_this(str2hex($bucket->data));
		debug_this($bucket->data);
		//stream_bucket_append($out, $bucket);
		
		
		

        return PSFS_PASS_ON;
    }
}






/*
*      SERVER TO CLIENT
*/
class htmlproxy_response_filter extends php_user_filter{
    protected $buf;
	protected $tmpbuf = '';
	protected $headers = '';
	protected $content = '';
	protected $buffer_content = false;
	//protected $partitial_headers = true;
	//private $stream_body = false;
	protected $content_type = '';
	protected $proxy_hostname = '';
	protected $content_left = 0;
	protected $content_encoding = false;
	//protected $content_length = 0;
	
	protected $chunkbytes = 0; //bytes remaining in the current chunk
	protected $ischunked = false; //whether the stream is chunk-encoded.
	
	//protected $bucket = false;
	
	protected $placeholders = array(); // Temporarily stores javascript when rewriteing content.

	
    /* Called when the filter is initialized */
    function onCreate(){
		debug_this('Creating new htmlproxy_response_filter.');
        $this->buf = '';
		if(isset($this->params['proxy_hostname']))
			$this->proxy_hostname = (string)$this->params['proxy_hostname'];
        return true;
    }

    public function filter($in, $out, &$consumed, $closing){
	
	
		if($this->content_left){
			if($this->buffer_content){
				while($this->content_left > strlen($this->buf)){
					// Retrieve a bucket
					if(!$bucket = stream_bucket_make_writeable($in)){
						// Need more data.
						return PSFS_FEED_ME;
					}
					// Increment $consumed
					$consumed += $bucket->datalen;
					// Apend bucket data to the buffer.
					$this->buf .= $bucket->data;
					debug_this("Buffered ".strlen($this->buf)."/".$this->content_left." bytes.");
				}
				// Buffering compleate.
				debug_this("Buffering compleate. ".strlen($this->buf)." bytes.");
				// Create new bucket if we need to.
				if(!isset($bucket) || !$bucket){
					// Create a new bucket with the buffered content inside.
					$bucket = stream_bucket_new($this->stream, substr($this->buf,0,$this->content_left));
				}else{
					// Move the buffered content to the bucket
					$bucket->data = substr($this->buf,0,$this->content_left);
				}
				// Remove it from our buffer.
				$this->buf = substr($this->buf,$this->content_left);
				// Rewrite links and such in the content
				$bucket->data = $this->proxifyContent($bucket->data);
				// Reassemble http response
				$bucket->data = $this->headers.$bucket->data;
				//$bucket->datalen = strlen($bucket->data);
				// Empty buffers
				$this->headers = '';
				// Send http response
				stream_bucket_append($out, $bucket);
				// Clear buffer flag
				$this->buffer_content = false;
				// Reset content_left
				$this->content_left = 0;
				// Expect a new header
				//$this->partitial_headers = true;
				
				return PSFS_PASS_ON;
			}else{
				// If the buffer isn't empty
				if(!empty($this->buf)){
					// Get a new empty bucket and fill it with buffered data.
					$bucket = stream_bucket_new($this->stream, $this->buf);
					// Decrese content_left
					$this->content_left -= $bucket->datalen;
					// If we got more data than intended.
					if($this->content_left < 0){
						// Put the overflow in our buffer
						$this->buf = substr($bucket->data,$this->content_left);
						// And the remaining data in the bucket.
						$bucket->data = substr($bucket->data,0,$this->content_left);
						// Reset content_left
						$this->content_left = 0;
						// Expect a new header
						//$this->partitial_headers = true;
					}
					// Output buffered data.
					stream_bucket_append($out, $bucket);
					// Empty the buffer
					$this->buf = '';
				}
				
				while($this->content_left && ($bucket = stream_bucket_make_writeable($in))){
					// Increment $consumed
					$consumed += $bucket->datalen;
					// Decrese content_left
					$this->content_left -= $bucket->datalen;
					// If we got more data than intended.
					if($this->content_left < 0){
						// Put the overflow in our buffer
						$this->buf = substr($bucket->data,$this->content_left);
						// And the remaining data in the bucket.
						$bucket->data = substr($bucket->data,0,$this->content_left);
						// Reset content_left
						$this->content_left = 0;
						// Expect a new header
						//$this->partitial_headers = true;
					}
					// Stream content
					stream_bucket_append($out, $bucket);
					debug_this($this->content_left." bytes of content left to strem.");
				}
				return PSFS_PASS_ON;
			} // End of not buffering content
		
		}

        if($this->ischunked){
			if($this->buffer_content){
				if($bucket = stream_bucket_make_writeable($in)){
					$consumed += $bucket->datalen;
				}
				if(!empty($this->buf)){
					if(!$bucket)$bucket = stream_bucket_new($this->stream, '');
					// Prepend the buffer to the buckets data.
					$bucket->data = $this->buf.$bucket->data;
					$bucket->datalen = strlen($bucket->data);
					$this->buf = '';
				}
				//var_dump($bucket);
				while ($bucket) {
				
					// Spara i en outbuffer фnda tills vi fхtt sista biten.
					// Dх kapar vi av och sparar resten i buf
				
					//$outbuffer = '';
					$offset = 0;
					//debug_this("Chunkdata in: {$bucket->data}");
					debug_this("Chunkdatalen in: ".strlen($bucket->data));
					while ($offset < $bucket->datalen) {
						if ($this->chunkbytes===0) {
							$lineone = strpos($bucket->data, "\r\n", $offset);
							// Get chunk length, ignore MIME-like extensions
							$chunklen = trim(current(explode(';', substr($bucket->data, $offset, $lineone-$offset), 2)));
							// Sanitycheck
							if (!ctype_xdigit($chunklen))return PSFS_ERR_FATAL;
							// Convert hex to decimal
							$this->chunkbytes = hexdec($chunklen);
							// Add to offset
							$offset = $lineone+2; // +2 is CRLF
							if ($this->chunkbytes===0) { //end of the transfer
								debug_this("No chunks remaining.");
								// Clear ischunked flag.
								$this->ischunked = false;
								// Clear buffer flag
								$this->buffer_content = false;
								// Expect a new header
								//$this->partitial_headers = true;
								// Save remaining data in buf
								$this->buf = substr($bucket->data, $offset+2); // +2 is CRLF
								debug_this(strlen($this->buf)." bytes of data after last chunk:{$this->buf}");
								// Rewrite links and such in the content
								$this->content = $this->proxifyContent($this->content);
								// Reassemble http response
								$bucket->data = $this->headers.$this->content;
								//$bucket->datalen = strlen($bucket->data);
								debug_this("Sending previously buffered ".strlen($this->headers)." bytes response header.");
								//if($this->headers<1000){
								//	debug_this($this->headers);
								//	debug_this(str2hex($this->headers));
								//}
								$this->headers = $this->content = '';
								
								debug_this("Chunkdatalen out: ".strlen($bucket->data));
								//debug_this("Chunkdata out: {$bucket->data}");
								stream_bucket_append($out, $bucket);
								//break 2;  // ignore possible trailing headers. TODO Stream trailing headers.
								return PSFS_PASS_ON;
							}
						}
						// get all available data
						$nibble = substr($bucket->data, $offset, $this->chunkbytes);
						$nibblesize = strlen($nibble);
						$offset += $nibblesize; // ...but recognize we may not have got all of it
						if ($nibblesize === $this->chunkbytes) {
							$offset += 2; // skip over trailing CRLF
						}
						$this->chunkbytes -= $nibblesize;
						//$outbuffer .= $nibble;
						$this->content .= $nibble;
					}
					//$consumed += $bucket->datalen;
					//$bucket->data = $outbuffer;
					//debug_this("Chunkdatalen out: ".strlen($bucket->data));
					//debug_this("Chunkdata out: {$bucket->data}");
					//stream_bucket_append($out, $bucket);
					
					// Get another bucket for the next iteration of the while loop.
					if($bucket = stream_bucket_make_writeable($in)){
						$consumed += $bucket->datalen;
					}
				}
				return PSFS_PASS_ON;
			}else{
				if($bucket = stream_bucket_make_writeable($in)){
					$consumed += $bucket->datalen;
				}
				if(!empty($this->buf) && $bucket){
					// Prepend the buffer to the buckets data.
					$bucket->data = $this->buf.$bucket->data;
					$bucket->datalen = strlen($bucket->data);
					$this->buf = '';
				}
				while ($bucket) {
					//$consumed += $bucket->datalen;
					if(false!==stripos($this->tmpbuf.$bucket->data,"\r\n0\r\n\r\n")){
						// Found the end of a chunked content body
						// Position -6 byted for tmpbuf +7 for length of matchstring =1
						$end = stripos($this->tmpbuf.$bucket->data,"\r\n0\r\n\r\n") + 1;
						// Save remaining data in the buffer
						$this->buf = substr($bucket->data,$end);
						// And everything, including the end, gets streamed to the client.
						$bucket->data = substr($bucket->data,$end);
						// Empty tmpbuf
						$this->tmpbuf = '';
						// Send it on its way, yeeeeeeeeeeehaa!
						stream_bucket_append($out, $bucket);
						// Clear ischunked flag.
						$this->ischunked = false;
						// Clear buffer flag
						$this->buffer_content = false;
						// Expect a new header
						//$this->partitial_headers = true;
						return PSFS_PASS_ON;
					}
					
					// Save last six bytes of bucket to use when trying to find the end.
					$this->tmpbuf = substr($bucket->data,-6);
					
					debug_this("Streaming a chunk-encoded response.");
					//debug_this($bucket->data);
					stream_bucket_append($out, $bucket);
					// Get another bucket for the next iteration of the while loop.
					if($bucket = stream_bucket_make_writeable($in)){
						$consumed += $bucket->datalen;
					}
				}
				return PSFS_PASS_ON;
			}
		} // end($this->ischunked)
		
		if($closing){ // Just flush it all.
			debug_this("Closing!");
			/*
			if($bucket = stream_bucket_make_writeable($in)){
				//$consumed += $bucket->datalen;
				log_this("Closing with {$bucket->datalen} bytes in a bucket!",LOG_WARNING);
			}
			if(!empty($this->buf)){
				log_this("Closing with ".strlen($this->buf)." bytes in a buf!",LOG_WARNING);
				var_dump($this->buf,
						$this->tmpbuf,
						$this->headers,
						$this->content,
						$this->buffer_content,
						$this->content_type,
						$this->proxy_hostname,
						$this->content_left,
						$this->content_encoding,
						$this->chunkbytes,
						$this->ischunked
				);
			}
			*/
			
			// Create new bucket if we need to.
			if($bucket = stream_bucket_make_writeable($in)){
				$consumed += $bucket->datalen;
				debug_this("Closing with {$bucket->datalen} bytes in a bucket and ".strlen($this->buf)." bytes in a buf.");
				$bucket->data = $this->buf.$bucket->data;
				//log_this("Closing with {$bucket->datalen} bytes in a bucket!",LOG_WARNING);
			}elseif(!empty($this->buf)){
				debug_this("Closing with ".strlen($this->buf)." bytes in buf.");
				// Create a new bucket with the buffered content inside.
				$bucket = stream_bucket_new($this->stream, $this->buf);
			}else{
				return PSFS_FEED_ME;
			}
			// Remove it from our buffer.
			$this->buf = '';
			if(false!==stripos($this->content_type,'html') || false!==stripos($this->content_type,'css')){
				debug_this("Closing with html or css. Rewriting it.");
				// Rewrite links and such in the content
				$bucket->data = $this->proxifyContent($bucket->data);
			}
			//$bucket->datalen = strlen($bucket->data);

			// Send http response
			stream_bucket_append($out, $bucket);

			
			return PSFS_PASS_ON;

		}
		
		if($bucket = stream_bucket_make_writeable($in)){
			$this->buf .= $bucket->data;
			$consumed += $bucket->datalen;
		}
		// Check if we have got all of the headers
		if( false === ($eoh = strpos($this->buf, "\r\n\r\n"))){
			//debug_this("Read ".strlen($this->buf)." bytes, no header yet.");
			//debug_this(substr($this->buf,0,500));
			//var_dump($this);
			// Wait until we have got all of the headers
			return PSFS_FEED_ME;
		}
		// We have got all of the headers
		
		// Set some default values
		$this->buffer_content = false;
		$this->content_left = 0;
		$this->content_encoding = false;
		$this->ischunked = false;
		$this->content_type = '';
		$this->content = '';
		$this->headers = '';
		$this->tmpbuf = '';
		
		// Off with its head!!!
		$headers = substr($this->buf,0,$eoh+4);
		$this->buf = substr($this->buf,$eoh+4);
		
		debug_this("Recieved ".strlen($headers)." bytes response header.");
		
		//}elseif(false!==($eoh = strpos($this->buf, "\n\n"))){
		//	$headers = substr($this->buf,0,$eoh+2);
		//	$this->buf = substr($this->buf,$eoh+2);
		
		
		//preg_match('/^Transfer-Encoding:\s?chunked/mi',$headers,$m);
		//echo "LOL\n";
		//var_dump($m,$headers);
		//die();

		// Spara enkodning, om ingen encodning. lete efter meta tagg
		// Implement -> http://www.jmarshall.com/easy/http/#http1.1s2

		// Find content length
		if(preg_match('/\nContent-Length:\s*(\d+)/i',$headers,$m)){
			$this->content_left = (int)$m[1];
			//$this->content_length = (int)$m[1];
			debug_this("Content length: {$this->content_left}.");
			// Content ahead
			//$this->partitial_headers = false;
		}//else{
		//	debug_this("Content-Length not specified.");
			
			//$this->content_length = 0;
		//}
		
		if(preg_match('/\nContent-Encoding:\s*([a-z]+)/i',$headers,$m)){
			$this->content_encoding = strtolower($m[1]);
			debug_this("Content encoding: {$this->content_encoding}.");
		}


		// Rewrite the Set-Cookie header
		$headers = preg_replace('/\nSet-Cookie:.*?;\s?Domain=[A-z0-9-\.]+/i','\\0.'.$this->proxy_hostname,$headers);
		
		// Rewrite location and other redirects
		if(preg_match('/(\nLocation:\s*|\nRefresh:\s*\d+;\surl=)([^\r\n]*)/i',$headers,$m)){
			debug_this(print_r($m,true));
			$headers = str_replace($m[0], $m[1].$this->proxifyURL($m[2]), $headers);
			//$headers = preg_replace('/(\nLocation:\s?|\nRefresh:\s\d+;\s?url=)([^\r\n]*)/i','\\1'.$this->proxifyURL($m[2]).'\\3',$headers);
		}
		
		if(preg_match('/\nTransfer-Encoding:\s*chunked/i',$headers)){
			$this->ischunked = true;
			
			debug_this("Transfer-Encoding chunked.");
			// Content ahead
			//$this->partitial_headers = false;
			// Must retain the header till we know the correct content length.
			//$this->headers = $headers;
			//return PSFS_FEED_ME;
		}
		
		// Find content type
		if(preg_match('/\nContent-Type:\s*([^\s;\r\n]+)(;\s?charset=([^\s;\r\n]+))?/i',$headers,$m)){
			$this->content_type = $m[1];
			debug_this("Content type: {$this->content_type}.");
			// Check fore content types with links in need of a rewrite.
			if((false!==stripos($this->content_type,'html') || false!==stripos($this->content_type,'css'))
			// But only if there actually are some content.
			&& ($this->content_left || $this->ischunked) ){
				// Buffer the content body so it can be proxified.
				$this->buffer_content = true;
				// We are not planning to "rechunk" a "dechunked" content body. Remove that header
				if($this->ischunked)$headers = preg_replace('/\r?\nTransfer-Encoding:\s*chunked[^\r\n]*/i','',$headers,1);
				// Must retain the header till we know the correct content length.
				$this->headers = $headers;
				debug_this("Buffering ".strlen($headers)." bytes response header.");
				//if($headers<1000){
				//	debug_this($headers);
				//	debug_this(str2hex($headers));
				//}
				return PSFS_FEED_ME;
			}
			// If a charset was found. Save it.
			if(isset($m[3]) && !empty($m[3])) $this->charset = $m[3];
		}else{
			debug_this("Content-Type not specified.");
		}
		
		debug_this("Returning ".strlen($headers)." bytes response header.");
	
		//if(strlen($headers)<1000){
			debug_this($headers);
		//	debug_this(str2hex($headers));
		//}
		
		//$bucket = stream_bucket_new($this->stream, '');
		//$bucket->data = $headers;
		//stream_bucket_append($out, $bucket);
		
		// Stream out a new bucket filled with headers.
		stream_bucket_append($out, stream_bucket_new($this->stream, $headers));
		
		//$this->stream_data_append($out, $headers);
		
		// Put the head in a bucket.       ...seems legit.
		//$bucket->data = $headers;
		
		//$bucket->datalen = strlen($bucket->data);
		//debug_this(str2hex($bucket->data));
		//debug_this("Header len: {$bucket->datalen}");
		//if($bucket->datalen<1000)debug_this($bucket->data);
		//debug_this($bucket->data);
		
		// Pass the bucket on.
		//stream_bucket_append($out, $bucket);
		
		// Fill the bucket
		//if(!($bucket = stream_bucket_make_writeable($in))){
			// No bucket found.
		//	return PSFS_PASS_ON;
		//}
		return PSFS_PASS_ON;
    }

	function setContentLength($length){
		// Remove current content length header
		$this->headers = preg_replace('/\r?\nContent-Length:[^\r\n]*/i','',$this->headers,1);
		// Insert a new content length header
		$this->headers = preg_replace('/(\r?\n)\r?\n/','\\1Content-Length: '.$length.'\\0',$this->headers,1);
		debug_this("New Content Length set to $length.");
	}
	
	function proxifyURL($url){
		//debug_this("URL:$url");
		$urlparts = @parse_url(preg_replace('/^:?\/\//','http://',$url));
		if(isset($urlparts['host'])){
			if(preg_match('/^([A-z234567]{16})\.onion$/i',$urlparts['host'], $m)){
				return preg_replace('/'.preg_quote($urlparts['host'],'/').'/', "{$m[1]}.{$this->proxy_hostname}", $url, 1);
			}
			return preg_replace('/'.preg_quote($urlparts['host'],'/').'/', "{$urlparts['host']}.{$this->proxy_hostname}", $url, 1);
		}
		//debug_this("Proxified URL:$url");
		return $url;
	}
	
	function fixHTMLAttribute($m){
		//return "0:#{$m[0]}# 1:#{$m[1]}# 2:#{$m[2]}# 3:#{$m[3]}# 4:#{$m[4]}# 5:#{$m[5]}# 6:#{$m[6]}# 7:#{$m[7]}#";
		$tag = $m[1];
		$attribute = $m[2];
		$quote = $m[3];
		$value = @html_entity_decode($m[4].$m[5], ENT_QUOTES);
		switch(strtolower($attribute)){
			case 'style':
				$value = $this->parseCSS($value);
				break;
			case 'href':
			case 'code':
			case 'codebase':
			case 'cite':
			case 'background':
			case 'data':
			case 'usemap':
			case 'src':
			case 'action':
			case 'longdesc':
			case 'profile':
				$value = $this->proxifyURL($value);
				break;
			default:
				if(strtolower(substr($attribute,0,2)) === 'on'){
				$m[1] = $m[3] = '';
				$m[2] = $value;
				$value = $this->scriptPlaceholder($m);
				}
				//$value = $this->parseJS($value);
				break;
		}
		
		debug_this("$attribute=$quote".htmlentities($value, ENT_QUOTES)."$quote");
		return "$tag$attribute=$quote".htmlentities($value, ENT_QUOTES).$quote;

	}


	function fixCSSURL($m){
		//print_r($m);
		//return "0:#{$m[0]}# 1:#{$m[1]}# 2:#{$m[2]}# 3:#{$m[3]}# 4:#{$m[4]}# 5:#{$m[5]}# 6:#{$m[6]}# 7:#{$m[7]}#";
		return $m[1].$m[2].$this->proxifyURL($m[3]).$m[4];
	}

	function parseCSS($css){
		$css = preg_replace_callback('/(url\s*\(?\s*)([\'"]?)(.*?)(\\2\s*\)?)/i', array( &$this, 'fixCSSURL'), $css);   //'"url(\\1".$this->proxifyURL(\'\\2\')."\\1)"', $css);
		return preg_replace_callback('/(@import\s*)([\'"]?)(.*?)(\\2)/i', array( &$this, 'fixCSSURL'), $css);   //'"url(\\1".$this->proxifyURL(\'\\2\')."\\1)"', $css);
	}


	function parseMetaRefresh($m){
		//str_replace  ( mixed $search  , mixed $replace  , mixed $subject  [, int &$count  ] )
		return str_replace($m[3], $this->proxifyURL($m[3]),  $m[0]);
	}

	function parseStyleTag($m){
		return $m[1].$this->parseCSS($m[2]).$m[3];
	}

	function scriptPlaceholder($m){
		//return "0:#{$m[0]}# 1:#{$m[1]}# 2:#{$m[2]}# 3:#{$m[3]}# 4:#{$m[4]}# 5:#{$m[5]}# 6:#{$m[6]}# 7:#{$m[7]}#";
		$md5 = md5($m[2]);
		$this->placeholders[$md5] = $m[2];
		return "{$m[1]}/*ScriptPlaceholder$md5*/{$m[3]}";
	}

	function testregex($m){
		return "0:#{$m[0]}# 1:#{$m[1]}# 2:#{$m[2]}# 3:#{$m[3]}# 4:#{$m[4]}# 5:#{$m[5]}# 6:#{$m[6]}# 7:#{$m[7]}#";
	}

	function proxifyContent($buffert){
		//return $buffert;
		//echo "\n<br>parseBuffert($buffert, $mode)";
		
		// Decompress
		if($this->content_encoding){
			//debug_this("Buffer b4 decompression: ".str2hex($buffert));
			switch($this->content_encoding){
				//case 'compress': $bucket->data = $bucket->data; break;
				case 'deflate': $buffert = gzinflate($buffert); break;
				case 'gzip': $buffert = gzdecode($buffert); break;
				//case 'identity': $bucket->data = $bucket->data; break;
				//case 'sdch': $bucket->data = $bucket->data; break;
				default: debug_this("Got a response with content encoding {$this->content_encoding}.");
			}
			//debug_this("Buffer after decompression: ".str2hex($buffert));
		}

		if(false!==stripos($this->content_type,'html')){
			debug_this("Parseing content as html.");
			// Find scripts
			$buffert = preg_replace_callback('/(<script(?:(?:\s+(?:\w|\w[\w-]*\w)(?:\s*=\s*(?:".*?"|\'.*?\'|[^\'">\s]+))?)+\s*|\s*)>)(.*?)(<\/script>)/is', array( &$this, 'scriptPlaceholder'), $buffert);
			// Find css
			$buffert = preg_replace_callback('/(<style(?:(?:\s+(?:\w|\w[\w-]*\w)(?:\s*=\s*(?:".*?"|\'.*?\'|`.*?`|[^\'">\s]+))?)+\s*|\s*)>)(.*?)(<\/style(?:.*?)>)/is', array( &$this, 'parseStyleTag'), $buffert);
			// Find meta refresh
			$buffert = preg_replace_callback('/content=([\'"`])?[0-9]+\s*;\s*url=([\'"`])?(.*?)(?:\\2|\\1)/i', array( &$this, 'parseMetaRefresh'), $buffert);
			// Find tags containing url:s, scripts and css
			$buffert = preg_replace_callback('/([\'"`\/\s])(href|code|codebase|cite|background|data|usemap|src|action|longdesc|profile|style|on\w*)=\s*(?:([\'"`])(.*?)\\3|([^\s>]*)(?=[\s>]))/i', array( &$this, 'fixHTMLAttribute'), $buffert);
			//$buffert = preg_replace_callback('/(<\w[^>]*[\'"`\/\s])(href|code|codebase|cite|background|data|usemap|src|action|longdesc|profile|style|on\w*)=\s*(?:([\'"`])(.*?)\\3|(.*?)(?=[\\s>]))/i', array( &$this, 'fixHTMLAttribute'), $buffert);

			// Replace the script placeholders with it's orginal content.
			// Commented to remove JavaScript.
			//foreach( $this->placeholders as $key => $value ) $buffert = str_replace("/*ScriptPlaceholder$key*/", $value, $buffert);
			

		}elseif(false!==stripos($this->content_type,'css')){
			debug_this("Parseing content as css.");
			$buffert = $this->parseCSS($buffert);
		}
		
		// Compress
		if($this->content_encoding){
			switch($this->content_encoding){
				//case 'compress': $bucket->data = $bucket->data; break;
				case 'deflate': $buffert = gzdeflate($buffert); break;
				case 'gzip': $buffert = gzencode($buffert); break;
				//case 'identity': $bucket->data = $bucket->data; break;
				//case 'sdch': $bucket->data = $bucket->data; break;
				default: debug_this("Got a response with content encoding {$this->content_encoding}.");
			}
		}

		// Update content length
		$this->setContentLength(strlen($buffert));
		
		return $buffert;
	}
}

?>