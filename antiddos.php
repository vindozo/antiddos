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
    private string $cacheType; // Тип кэша: 'redis', 'memcached', 'file'
    private string $errorLog = ''; // Переменная для хранения ошибок
	
    /**
     * Время задержки в секундах, после которого можно снова обращаться к сайту,
     * иначе это атакующий бот.
     */
    private int $botDelay = 2; // Время задержки в секундах (по умолчанию 2)
    /**
     * Путь к папке с временными файлами (используется только для файлового кэша).
     * если оставить null то возмется стандартный TMP 
     */	
    private string $tempDir; // Путь к папке с временными файлами

    /**
     * Конструктор класса.
     *
     * @param string $cacheType Тип кэша ('redis', 'memcached', 'file' - по умолчанию).
     * @param string $tempDir   Путь к папке с временными файлами (по умолчанию sys_get_temp_dir()).
     *
     * @throws Exception Если передан некорректный тип кэша.
     */
    public function __construct(string $cacheType = 'file', string $tempDir = null)
    {
        $this->cacheType = $cacheType;

        if ($tempDir === null) {
            $this->tempDir = sys_get_temp_dir();
        } else {
            $this->tempDir = $tempDir;
        }

        // Проверка существования папки для временных файлов
        if (!is_dir($this->tempDir)) {
            $this->errorLog .= "Папка " . $this->tempDir . " не существует.\n";
            // throw new Exception("Папка " . $this->tempDir . " не существует.");
        }

        // Настройка кэша по приоритетам и типу
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

        // Если монитор нужен, вызываем monitor()
        if (isset($_GET['antiddos'])) {
            $this->monitor();
            exit;
        }
    }

    /**
     * Инициализация кэша (файл, Redis, Memcached) по приоритетам и типу.
     */
    private function initCache(): void
    {
        if ($this->cacheType === 'redis') {
            // 1. Пробуем подключиться к Redis
            if ($this->tryConnect('redis', '127.0.0.1', 6379)) {
                $this->errorLog .= "Redis кэш подключен успешно.\n";
                return;
            } else {
                $this->errorLog .= "Ошибка подключения к Redis кэшу.\n";
            }
        }

        if ($this->cacheType === 'memcached') {
            // 2. Пробуем подключиться к Memcached
            if ($this->tryConnect('memcached', '127.0.0.1', 11211)) {
                $this->errorLog .= "Memcached кэш подключен успешно.\n";
                return;
            } else {
                $this->errorLog .= "Ошибка подключения к Memcached кэшу.\n";
            }
        }

        // 3. Используем файловый кэш по умолчанию или если указан тип 'file'
        if ($this->cacheType === 'file' || $this->cacheType !== 'redis' && $this->cacheType !== 'memcached') {
            $this->cache = new stdClass();
            $this->cache->cacheDir = $this->tempDir;
            $this->errorLog .= "Файловый кэш инициализирован.\n";
        } else {
            // Заменяем throw на запись в лог
            $this->errorLog .= "Некорректный тип кэша: {$this->cacheType}\n";
            // throw new Exception("Некорректный тип кэша: {$this->cacheType}");
        }
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
            $forbid = time() - $this->botDelay;
            $dir = opendir($this->tempDir) or die('Отсутствует директория для временных файлов AntiDDOS');
            while (false !== ($file = readdir($dir))) {
                if (strpos($file, '.ddos') > 0 && filemtime($this->tempDir . '/' . $file) < $forbid) {
                    unlink($this->tempDir . '/' . $file);
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
        if ($lastRequest !== null && $time - (int)$lastRequest < $this->botDelay) {
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
        header('Retry-After: ' . ($this->botDelay * 2));
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
		Попробуйте вызвать эту страницу позже, через ' . ($this->botDelay * 2) . ' сек. (клавиша F5).
	</p>
</body>
</html>';
    }

    /**
     * Отображает статистику атак или список IP-адресов с количеством запросов.
     */
    public function monitor(): void
    {
        $startTime = microtime(true); // Замеряем время начала выполнения скрипта

        echo '
<!DOCTYPE html>
<html>
	<head>
		<title>AntiDDOS</title>
		<meta charset="utf-8">
		<meta http-equiv="refresh" content="60">
	<style>
		th, td {
			border: 1px solid #000;
			padding: 15px;
		}
	</style>
	</head>
<body>
	<h1>Список IP адресов, делающих запросы быстрее чем раз в ' . $this->botDelay . ' сек. </h1>
	<table>
		<tr>
			<th>IP адрес</th>
			<th>Количество запросов</th>
		</tr>';

        if (get_class($this->cache) === 'stdClass') {
            // Обработка ошибок при чтении файлов
            if (!is_dir($this->tempDir)) {
                $this->errorLog .= "Отсутствует директория для временных файлов AntiDDOS\n";
            } else {
                $dir = opendir($this->tempDir);
                if ($dir === false) {
                    $this->errorLog .= "Ошибка открытия директории " . $this->tempDir . "\n";
                } else {
                    $ip = [];
                    while (false !== ($file = readdir($dir))) {
                        if (strpos($file, '.ddos') > 0) {
                            // Обработка ошибок при чтении файла
                            $count = (int)@file_get_contents($this->tempDir . '/' . $file);
                            if ($count === false) {
                                $this->errorLog .= "Ошибка чтения файла {$this->tempDir}/{$file}\n";
                            } else {
                                $ip[str_replace('.ddos', '', $file)] = $count;
                            }
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
                }
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

	<h2>Тип кэша:</h2>
	<pre>' . htmlspecialchars($this->cacheType) . '</pre>
	<h2>Лог ошибок:</h2>
	<pre>' . htmlspecialchars($this->errorLog) . '</pre>';

        $endTime = microtime(true); // Замеряем время окончания выполнения скрипта
        $executionTime = $endTime - $startTime; // Вычисляем время выполнения
        $requestsPerSecond = floor(1 / $executionTime); // Вычисляем количество запросов в секунду

        echo "<h2>Производительность:</h2>";
        echo "<p>Время выполнения: {$executionTime} сек.</p>";
        echo "<p>Количество запросов в секунду: {$requestsPerSecond}</p>";

        echo '</body>
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
// $antiddos = new AntiDDOS('redis'); // Используем Redis
// $antiddos = new AntiDDOS('memcached'); // Используем Memcached
// $antiddos = new AntiDDOS('file'); // Используем файловый кэш
$antiddos = new AntiDDOS('file', '/tmp/antiddos'); // Используем файловый кэш
// $antiddos = new AntiDDOS(); // Автодетект, по умолчанию файловый кэш

// ... (остальной код)
