<?php
/*
Модуль antiddos
--------------------------------------------------------
Модуль предназначен для ограничения доступа к сайту или к страницам, где он включён,
для защиты от DDOS атаки средней тяжести. 
При этом, в момент атаки, сайт отвечает только тем пользователям, кто обращается к сайту реже чем в заданной задержке.

Принцип работы в том, что запоминается ip-адрес и время обращения с этого адреса. 
И если в течение заданного времени происходит обращение с того же адреса, то ему выдаётся ошибка 503.

Модуль необходимо подключать к скрипту самым первым.
Например: include "antidos.php";

Если нужно посмотреть статистику атаки, то откройте ваш сайт с параметром ?antiddos
Это позволит увидеть список атакующих IP ботов.
Например: http://site.com/?antiddos

*/
class AntiDDOS {

	const BotDelay = 2; // Время задержки в секундах, после которого можно снова обращаться к сайту, иначе это атакующий бот.
	const TempDir = '/var/www/.....ru/ddos'; // Путь к папке с временными файлами. Должен существовать 
 
/*
	Если атака мягкая, то лучше не запрещать обход сайта поисковым роботам.
	Очень не хорошо, если поисковый робот будет натыкаться на ошибки на сайте. 
	Ему это может сильно не понравиться.
	Поэтому пишем список юзер-агентов роботов; добавляем или
	удаляем, что нужно. Если хотите не делать исключение, закоментируйте содержимое массива.
*/
	const UserAgent = array( 
		'aipbot',
		'Aport',
		'eStyleSearch',
		'Gigabot',
		'Gokubot',
		'Google',
		'MJ12bot',
		'msnbot',
		'PlantyNet_WebRobot',
		'StackRambler',
		'TurtleScanner',
		'Yahoo',
		'Yandex',
		'YaDirectBot',
	);
/*
	Список доверенных IP.
	В вашем офисе может работать множество народа, которых банить не надо, 
	даже если они постоянно сидят на сайте.
*/
	const GoodIP = array(
		'217.107.36.73',
	);
/*
	Основной код проверки IP и доступа на сайт.
*/
	function __construct() {
		// Проверка на доверенный IP
		if( in_array($_SERVER['REMOTE_ADDR'], self::GoodIP) ) {
			return true;
		}

		// Проверка на наличие в поле HTTP_USER_AGENT чего-нибудь из вышенаписанного списка.
		foreach (self::UserAgent as $match){
			if ( strpos($_SERVER['HTTP_USER_AGENT'], $match) > 0){
				return true;
			}
		}
 
		// Чтение каталога и удаление старых файлов
		// IP-адрес в имени файла, с расширением ddos, а время обращения - время изменения файла 
		$forbid = time() - self::BotDelay;
		$dir = opendir( self::TempDir ) or die('Отсутствует директория для временных файлов AntiDDOS');
		while ( false !== ( $file = readdir($dir) ) ){
			if ( (strpos($file, '.ddos' ) > 0) && (@filemtime(self::TempDir . '/' . $file) < $forbid)){
				@unlink(self::TempDir . '/' . $file);
			}
		}
		closedir($dir);

		// Проверка на существование пометки о недавнем обращении с данного ip-адреса. 
		// Если обращение было недавно, то выводим сообщение об ошибке.
		$ddosbot = false;
		if (file_exists(self::TempDir . '/' . $_SERVER['REMOTE_ADDR'] . '.ddos' )){
			$ddosbot = true;
			header('HTTP/1.0 503 Service Unavailable');
			header('Status: 503 Service Unavailable');
			header('Retry-After: ' . (self::BotDelay * 2));
			echo '
<!DOCTYPE html>
<html>
	<head>
		<title>Ошибка 503</title>
		<meta charset="utf-8">
	</head>
<body>
	<h1>Ошибка 503 (Service Unavailable)</h1>
	<p>
		Сервер не может в данный момент выдать запрашиваемую Вами страницу. <br/>
		Попробуйте вызвать эту страницу позже, через ' . (self::BotDelay * 2) . ' сек. (клавиша F5).
	</p>
</body>
</html>';
		}
		// Перед выходом создаем файлик с ip и увеличиваем счетчик.
		$inc = (int)@file_get_contents(self::TempDir . '/' . $_SERVER['REMOTE_ADDR'] . '.ddos') + 1;
		file_put_contents(self::TempDir . '/' . $_SERVER['REMOTE_ADDR'] . '.ddos', $inc, LOCK_EX);
		
		// если есть подозрение что это DDOS бот, то досрочно прекращаем работу.
		if ($ddosbot) exit;
	}
	
/*
	Мониторинг IP адресов, с которых больше всего идет заходов.
*/
	function monitor() {
		$dir = opendir( self::TempDir ) or die('Отсутствует директория для временных файлов AntiDDOS');
		$ip = array();		
		while ( false !== ( $file = readdir($dir) ) ){
			if ( (strpos($file, '.ddos' ) > 0) ){
				$ip[str_replace('.ddos', '', $file)] =  (int)@file_get_contents(self::TempDir . '/' . $file);
			}
		}
		closedir($dir);

		echo '
<!DOCTYPE html>
<html>
	<head>
		<title>AntiDDOS</title>
		<meta charset="utf-8">
	<style>
		th, td {
			border: 1px solid #000;
			padding: 15px;
		}
	</style>
	</head>
<body>
	<h1>Список IP адресов, делающих запросы быстрее чем раз в '.self::BotDelay .' сек. </h1>
	<table>
		<tr>
			<th>IP адрес</th>
			<th>Количество запросов</th>
		</tr>';
		arsort($ip);
		foreach($ip as $ipa => $count) {
			echo '
			<tr>
				<td>' . $ipa . '</td>
				<td>' . $count . '</td>
			</tr>';
		}
		echo '
	</table>
</body>
</html>';
		exit;
	}
}

// Теперь запустим модуль в работу
$antiddos = new AntiDDOS();

// Если монитор не нужен, закоментируйте строку ниже
if( isset( $_GET['antiddos'] ) ) $antiddos->monitor();

