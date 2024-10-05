<?php

declare(strict_types=1);

/**
 * Класс для защиты от DDoS-атак.
 *
 * Модуль antiddos
 * --------------------------------------------------------
 * Модуль предназначен для ограничения доступа к сайту или к страницам, где он включён,
 * для защиты от DDOS атаки средней тяжести. 
 * При этом, в момент атаки, сайт отвечает только тем пользователям, кто обращается к сайту реже чем в заданной задержке.
 *
 * Принцип работы в том, что запоминается ip-адрес и время обращения с этого адреса. 
 * И если в течение заданного времени происходит обращение с того же адреса, то ему выдаётся ошибка 503.
 *
 * Модуль необходимо подключать к скрипту самым первым.
 * Например: include "antidos.php";
 *
 * Если нужно посмотреть статистику атаки, то откройте ваш сайт с параметром ?antiddos
 * Это позволит увидеть список атакующих IP ботов.
 * Например: http://site.com/?antiddos
 */
class AntiDDOS
{
    /**
     * Время задержки в секундах, после которого можно снова обращаться к сайту,
     * иначе это атакующий бот.
     */
    public const BOT_DELAY = 2;

    /**
     * Путь к папке с временными файлами (используется только для файлового кэша).
     * если оставить null то возмется стандартный TMP 
     */
    public const TEMP_DIR = null; // Путь к папке с временными файлами. Должен существовать.

    /**
     * Список юзер-агентов роботов (закомментируйте, чтобы не делать исключений).
     * Если атака мягкая, то лучше не запрещать обход сайта поисковым роботам.
     * Очень не хорошо, если поисковый робот будет натыкаться на ошибки на сайте. 
     * Ему это может сильно не понравиться.
     * Поэтому пишем список юзер-агентов роботов; добавляем или
     * удаляем, что нужно. Если хотите не делать исключение, закоментируйте содержимое массива.
     */
    public const USER_AGENT = [
        'OpenAIbot',
        'YandexBot',
        'Bingbot',
        'DuckDuckGo',
        'AhrefsBot',
        'SeznamBot',
        'MJ12bot',
        'Baiduspider',
        'Slurp',
        'Yahoo! Slurp',
        'ia_archiver',
        'Ask Jeeves',
        'Exabot',
        'Scooter',
        'WebAlta',
        'Gigablast',
        'Nutch',
        'WordPress',
        'facebookexternalhit',
        'LinkedInBot',
        'Twitterbot',
        'Pinterest',
    ];

    /**
     * Список доверенных IP.
     */
    public const GOOD_IP = [
        '127.0.0.1', // localhost
        // Добавьте сюда другие доверенные IP
    ];

    private $cache; // Кэш (файл, Redis, Memcached)

    /**
     * Конструктор класса.
     *
     * @throws Exception Если папка TEMP_DIR не существует (для файлового кэша).
     */
    public function __construct()
    {
        // Инициализация TEMP_DIR, если не указана явно (для файлового кэша)
        if (self::TEMP_DIR === null) {
            self::TEMP_DIR = sys_get_temp_dir();
        }

        if (!is_dir(self::TEMP_DIR)) {
            throw new Exception("Папка " . self::TEMP_DIR . " не существует.");
        }

        // Настройка кэша по приоритетам
        $this->initCache();

        // Проверка на доверенный IP
        if (in_array($_SERVER['REMOTE_ADDR'], self::GOOD_IP)) {
            return true;
        }

        // Проверка на робота
        if ($this->isRobot($_SERVER['HTTP_USER_AGENT'])) {
            return true;
        }

        // Проверка на атаку
        if ($this->isAttack($_SERVER['REMOTE_ADDR'], time())) {
            $this->showDDOSError();
            exit;
        }

        // Увеличение счетчика для текущего IP
        $this->incrementIPCounter($_SERVER['REMOTE_ADDR']);
    }

    /**
     * Инициализация кэша (файл, Redis, Memcached) по приоритетам.
     */
    private function initCache(): void
    {
        // 1. Пробуем подключиться к Redis
        if ($this->tryConnect('redis', '127.0.0.1', 6379)) {
            return;
        }

        // 2. Пробуем подключиться к Memcached
        if ($this->tryConnect('memcached', '127.0.0.1', 11211)) {
            return;
        }

        // 3. Используем файловый кэш по умолчанию
        $this->cache = new stdClass();
        $this->cache->cacheDir = self::TEMP_DIR;
	$this->cleanUpOldFiles();
    }

    /**
     * Пробуем подключиться к кэшу (Redis или Memcached) и инициализируем его.
     *
     * @param string $type Тип кэша ('redis' или 'memcached').
     * @param string $host Хост для подключения.
     * @param int    $port Порт для подключения.
     *
     * @return bool True, если подключение успешно, иначе false.
     */
    private function tryConnect(string $type, string $host, int $port): bool
    {
        try {
            if ($type === 'redis') {
                $this->cache = new Redis();
                $this->cache->connect($host, $port);
            } elseif ($type === 'memcached') {
                $this->cache = new Memcached();
                $this->cache->addServer($host, $port);
            } else {
                return false; // Неверный тип кэша
            }
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Проверяет, является ли юзер-агент роботом.
     *
     * @param string $userAgent Юзер-агент.
     *
     * @return bool True, если юзер-агент является роботом, иначе false.
     */
    private function isRobot(string $userAgent): bool
    {
        return in_array(strstr($userAgent, '/'), self::USER_AGENT);
    }

    /**
     * Очищает папку TEMP_DIR от старых файлов (только для файлового кэша).
     */
    private function cleanUpOldFiles(): void
    {
        if (get_class($this->cache) === 'stdClass') {
            $forbid = time() - self::BOT_DELAY;
            $dir = opendir(self::TEMP_DIR) or die('Отсутствует директория для временных файлов AntiDDOS');
            while (false !== ($file = readdir($dir))) {
                if (strpos($file, '.ddos') > 0 && filemtime(self::TEMP_DIR . '/' . $file) < $forbid) {
                    unlink(self::TEMP_DIR . '/' . $file);
                }
            }
            closedir($dir);
        }
    }

    /**
     * Проверяет, является ли текущий IP атакующим, основываясь на времени последнего обращения.
     *
     * @param string $ip IP-адрес.
     * @param int    $time Текущее время.
     *
     * @return bool True, если атака обнаружена, иначе false.
     */
    private function isAttack(string $ip, int $time): bool
    {
        // Проверяем время последнего обращения в кэше
        $lastRequest = $this->get("antiddos:last_request:{$ip}");
        if ($lastRequest !== null && $time - (int)$lastRequest < self::BOT_DELAY) {
            return true; // Атака
        }

        // Обновляем время последнего обращения в кэше
        $this->set("antiddos:last_request:{$ip}", $time);

        return false; // Не атака
    }

    /**
     * Увеличивает счетчик для текущего IP.
     *
     * @param string $ip IP-адрес.
     */
    private function incrementIPCounter(string $ip): void
    {
        $this->incr("antiddos:counter:{$ip}");
    }

    /**
     * Отображает сообщение об ошибке 503.
     */
    private function showDDOSError(): void
    {
        header('HTTP/1.0 503 Service Unavailable');
        header('Status: 503 Service Unavailable');
        header('Retry-After: ' . (self::BOT_DELAY * 2));
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
		Попробуйте вызвать эту страницу позже, через ' . (self::BOT_DELAY * 2) . ' сек. (клавиша F5).
	</p>
</body>
</html>';
    }

    /**
     * Отображает статистику атак или список IP-адресов с количеством запросов.
     */
    public function monitor(): void
    {
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
	<h1>Список IP адресов, делающих запросы быстрее чем раз в ' . self::BOT_DELAY . ' сек. </h1>
	<table>
		<tr>
			<th>IP адрес</th>
			<th>Количество запросов</th>
		</tr>';

        if (get_class($this->cache) === 'stdClass') {
            $dir = opendir(self::TEMP_DIR) or die('Отсутствует директория для временных файлов AntiDDOS');
            $ip = [];
            while (false !== ($file = readdir($dir))) {
                if (strpos($file, '.ddos') > 0) {
                    $ip[str_replace('.ddos', '', $file)] = (int)@file_get_contents(self::TEMP_DIR . '/' . $file);
                }
            }
            closedir($dir);

            arsort($ip);
            foreach ($ip as $ipa => $count) {
                echo '
			<tr>
				<td>' . $ipa . '</td>
				<td>' . $count . '</td>
			</tr>';
            }
        } else {
            // Получаем данные из кэша для всех ключей с префиксом "antiddos:counter:"
            $keys = $this->getKeys("antiddos:counter:*");
            foreach ($keys as $key) {
                // Извлекаем IP из ключа
                $ip = str_replace('antiddos:counter:', '', $key);

                // Получаем значение счетчика из кэша
                $count = $this->get($key);

                echo '
			<tr>
				<td>' . $ip . '</td>
				<td>' . $count . '</td>
			</tr>';
            }
        }

        echo '
	</table>
</body>
</html>';
        exit;
    }

    /**
     * Получает значение из кэша.
     *
     * @param string $key Ключ.
     *
     * @return mixed|null Значение или null, если ключ не найден.
     */
    private function get(string $key): ?string
    {
        switch (get_class($this->cache)) {
            case 'Redis':
                return $this->cache->get($key);
            case 'Memcached':
                return $this->cache->get($key);
            default:
                if (is_object($this->cache) && isset($this->cache->cacheDir)) {
                    $cacheFile = $this->cache->cacheDir . '/' . $key;
                    if (file_exists($cacheFile)) {
                        return file_get_contents($cacheFile);
                    }
                }
                return null;
        }
    }

    /**
     * Записывает значение в кэш.
     *
     * @param string $key   Ключ.
     * @param string $value Значение.
     */
    private function set(string $key, string $value): void
    {
        switch (get_class($this->cache)) {
            case 'Redis':
                $this->cache->set($key, $value);
                break;
            case 'Memcached':
                $this->cache->set($key, $value);
                break;
            default:
                if (is_object($this->cache) && isset($this->cache->cacheDir)) {
                    $cacheFile = $this->cache->cacheDir . '/' . $key;
                    // Используем блокировку для записи
                    file_put_contents($cacheFile, $value, LOCK_EX); 
                }
                break;
        }
    }

    /**
     * Увеличивает значение счетчика в кэше.
     *
     * @param string $key Ключ.
     *
     * @return int Новое значение счетчика.
     */
    private function incr(string $key): int
    {
        switch (get_class($this->cache)) {
            case 'Redis':
                return $this->cache->incr($key);
            case 'Memcached':
                return $this->cache->increment($key);
            default:
                if (is_object($this->cache) && isset($this->cache->cacheDir)) {
                    $cacheFile = $this->cache->cacheDir . '/' . $key;
                    if (file_exists($cacheFile)) {
                        $value = (int)file_get_contents($cacheFile);
                        // Используем блокировку для записи
                        file_put_contents($cacheFile, $value + 1, LOCK_EX); 
                        return $value + 1;
                    }
                    // Используем блокировку для записи
                    file_put_contents($cacheFile, 1, LOCK_EX); 
                    return 1;
                }
                return 0;
        }
    }

    /**
     * Получает список ключей из кэша.
     *
     * @param string $pattern Шаблон ключа.
     *
     * @return array Список ключей.
     */
    private function getKeys(string $pattern): array
    {
        switch (get_class($this->cache)) {
            case 'Redis':
                return $this->cache->keys($pattern);
            case 'Memcached':
                // Memcached не имеет метода для получения списка ключей по шаблону.
                // Поэтому используем getAllKeys и фильтруем результат.
                $allKeys = $this->cache->getAllKeys();
                return array_filter($allKeys, function ($key) use ($pattern) {
                    return strpos($key, $pattern) === 0;
                });
            default:
                if (is_object($this->cache) && isset($this->cache->cacheDir)) {
                    $keys = [];
                    $dir = opendir($this->cache->cacheDir) or die('Отсутствует директория для временных файлов AntiDDOS');
                    while (false !== ($file = readdir($dir))) {
                        if (strpos($file, $pattern) === 0) {
                            $keys[] = $file;
                        }
                    }
                    closedir($dir);
                    return $keys;
                }
                return [];
        }
    }
}

// Теперь запустим модуль в работу
$antiddos = new AntiDDOS();

// Если монитор не нужен, закомментируйте строку ниже
if (isset($_GET['antiddos'])) {
    $antiddos->monitor();
}
