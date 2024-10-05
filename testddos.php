<?php

// Указываем адрес, куда будем отправлять запросы
$targetUrl = 'http://localhost/ваш_сайт/index.php'; // Замените на реальный адрес

// Количество запросов
$requestCount = 100;

// Цикл для отправки запросов
for ($i = 0; $i < $requestCount; $i++) {
    // Создаем контекст cURL
    $ch = curl_init();

    // Устанавливаем параметры cURL
    curl_setopt($ch, CURLOPT_URL, $targetUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); // Возвращаем результат запроса
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); // Максимальное время ожидания ответа

    // Выполняем запрос
    $response = curl_exec($ch);

    // Проверяем наличие ошибок
    if (curl_errno($ch)) {
        echo "Ошибка cURL: " . curl_error($ch) . "\n";
    } else {
        // Проверяем, была ли ошибка от скрипта AntiDDOS
        if (strpos($response, 'Ошибка 503 (Service Unavailable)') !== false) {
            echo "Защита AntiDDOS сработала! Получен ответ 503.\n";
        } else {
            echo "Защита AntiDDOS не сработала. Получен ответ: " . $response . "\n";
        }
    }

    // Закрываем контекст cURL
    curl_close($ch);
}

echo "Отправлено {$requestCount} запросов.\n";
