# Модуль защиты сайтов от DDOS атаки на любой CMS

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
