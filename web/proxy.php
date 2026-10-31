<?php
/* M87 抓取接口 · 精简版（PHP 5.6+，零依赖）
   ?action=status  -> 服务状态
   ?url=<绝对地址>  -> 返回目标站原始正文（bin=1 时按二进制返回） */

error_reporting(0);
ini_set('display_errors', '0');

$origin = 'https://awreffyt.github.io';

header('Access-Control-Allow-Origin: ' . $origin);
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: *');

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'status') {
    header('Content-Type: application/json; charset=utf-8');
    echo '{"ok":true,"mode":"m87-local","backend":"php"}';
    exit;
}

$url = isset($_GET['url']) ? trim($_GET['url']) : '';
if ($url === '' || !preg_match('/^https?:\/\//i', $url)) {
    http_response_code(400);
    echo 'bad url';
    exit;
}
$bin = isset($_GET['bin']) && $_GET['bin'] === '1';

$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
$hdr = array(
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding: gzip, deflate',
);

$raw  = false;
$code = 0;
$type = '';

if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 8);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_USERAGENT, $ua);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $hdr);
    $raw  = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $type = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);
}

if ($raw === false) {
    $ctx = stream_context_create(array(
        'http' => array(
            'method'          => 'GET',
            'header'          => implode("\r\n", $hdr),
            'timeout'         => 20,
            'ignore_errors'   => true,
            'follow_location' => 1,
            'max_redirects'   => 8,
        ),
        'ssl' => array('verify_peer' => false, 'verify_peer_name' => false),
    ));
    $raw = @file_get_contents($url, false, $ctx);
}

if ($raw === false) {
    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'fetch failed';
    exit;
}

header('X-M87-Status: ' . ($code > 0 ? $code : 200));
header('Content-Type: ' . ($bin && $type !== '' ? $type : 'text/plain; charset=utf-8'));
header('Cache-Control: no-store');
echo $raw;
