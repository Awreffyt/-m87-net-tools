<?php
/* ============================================================================
   M87 抓取后端 · PHP 单文件版（PHP 7.0+ / 需要 curl + openssl）
   ----------------------------------------------------------------------------
   上传到任意支持 PHP 的空间（InfinityFree、宝塔、虚拟主机、自己的服务器都行），
   然后在 web/site.config.js 里把 backend 填成这个文件的完整地址，例如：

     backend: 'https://你的域名/m87-proxy.php',

   网页版从此拥有服务端能力：
     - 跨域抓取（不受浏览器同源限制）
     - JS Cookie 门禁自动解算并重放（slowAES / aes.js 挑战）
     - 自动 Cookie jar、跟随重定向、gzip、二进制原样回传

   接口：
     ?action=status           -> {"ok":true,"mode":"m87-local","backend":"php"}
     ?url=<绝对地址>          -> 目标站正文（UTF-8 文本）
     ?url=<绝对地址>&bin=1    -> 目标站原始字节（图片/字体/压缩包）
   ========================================================================== */

error_reporting(0);
ini_set('display_errors', '0');
@set_time_limit(60);

/* ---- CORS：允许任意来源（GET 只读转发），预检直接放行 ---- */
$allowOrigin = isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== ''
    ? $_SERVER['HTTP_ORIGIN'] : '*';
header('Access-Control-Allow-Origin: ' . $allowOrigin);
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Expose-Headers: X-M87-Status, X-M87-Gate, X-M87-Final');
header('Vary: Origin');

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'status') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array(
        'ok' => true,
        'mode' => 'm87-local',
        'backend' => 'php',
        'gate' => function_exists('openssl_decrypt'),
        'curl' => function_exists('curl_init'),
        'php' => PHP_VERSION,
    ));
    exit;
}

$url = isset($_GET['url']) ? trim($_GET['url']) : '';
$bin = isset($_GET['bin']) && $_GET['bin'] === '1';

if ($url === '' || !preg_match('#^https?://#i', $url)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array('error' => '地址不合法'));
    exit;
}

/* ---- SSRF 防护：拒绝内网 / 回环 / 链路本地 ----
   唯一的例外：请求本身就来自本机（127.0.0.1）且显式带 allow_local=1，
   用于本机调试。外部请求无法利用这条，防止被当成打内网的跳板。 */
$fromLocal = isset($_SERVER['REMOTE_ADDR'])
    && in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'), true);
$allowLocal = $fromLocal && isset($_GET['allow_local']) && $_GET['allow_local'] === '1';

$host = strtolower((string) parse_url($url, PHP_URL_HOST));
$bad = false;
if ($host === '' || $host === 'localhost' || substr($host, -6) === '.local') {
    $bad = true;
} elseif (preg_match('/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/', $host)) {
    $bad = true;
} elseif (preg_match('/^172\.(1[6-9]|2[0-9]|3[01])\./', $host)) {
    $bad = true;
} elseif (strpos($host, '[') === 0 || $host === '::1') {
    $bad = true;
}
if ($bad && !$allowLocal) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array('error' => '目标地址不允许（内网）'));
    exit;
}

$UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/* ---- 单次请求：带 cookie jar，返回 [body, code, type, finalUrl] ---- */
function m87_once($url, $UA, $jar, $bin, $cookies, $timeout = 20)
{
    $body = false;
    $code = 0;
    $type = '';
    $final = $url;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $hdr = array(
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8',
            'Cache-Control: no-cache',
        );
        if ($cookies !== '') $hdr[] = 'Cookie: ' . $cookies;

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 8);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_TIMEOUT, max(4, (int) $timeout));
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, $UA);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $hdr);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $jar);
        curl_setopt($ch, CURLOPT_COOKIEJAR, $jar);
        if (defined('CURLOPT_ACCEPT_ENCODING')) {
            curl_setopt($ch, CURLOPT_ACCEPT_ENCODING, '');
        }
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $type = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $final = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
    } else {
        /* 没有 curl 时退回 stream，能力弱一些但可用 */
        $ctx = stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'timeout' => max(4, (int) $timeout),
                'follow_location' => 1,
                'max_redirects' => 8,
                'ignore_errors' => true,
                'header' => "User-Agent: $UA\r\nAccept: */*\r\n"
                    . ($cookies !== '' ? "Cookie: $cookies\r\n" : ''),
            ),
            'ssl' => array('verify_peer' => false, 'verify_peer_name' => false),
        ));
        $body = @file_get_contents($url, false, $ctx);
        if (isset($http_response_header) && is_array($http_response_header)) {
            foreach ($http_response_header as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) $code = (int) $m[1];
                if (stripos($line, 'content-type:') === 0) $type = trim(substr($line, 13));
                if (stripos($line, 'location:') === 0) $final = trim(substr($line, 9));
            }
        }
    }
    return array($body, $code, $type, $final);
}

/* ---- 门禁页识别 + 解算 ----------------------------------------------------
   InfinityFree 一类主机的挑战长这样：
     <script src="/aes.js"></script>
     <script>
       a=toNumbers("KEY16HEX"), b=toNumbers("IV16HEX"), c=toNumbers("CT16HEX");
       document.cookie = "__test=" + toHex(slowAES.decrypt(c,2,a,b)) + "; path=/";
       location.href = "/post.php?i=1";
     </script>
   密文就是 AES-128-CBC(key, iv)，解出来 hex 化就是 Cookie 值。
   ------------------------------------------------------------------------- */
function m87_is_gate($text)
{
    if (!is_string($text) || $text === '' || strlen($text) > 12000) return false;
    $head = substr($text, 0, 6000);
    $hasAes = (stripos($head, 'slowAES') !== false || stripos($head, '/aes.js') !== false);
    /* 光出现 slowAES 三个字不算，必须同时有解题代码（toNumbers / document.cookie），
       否则正文里提到这几个词的普通页面会被误判成门禁页。 */
    $hasSolve = (stripos($head, 'toNumbers(') !== false || stripos($head, 'document.cookie') !== false);
    return $hasAes && $hasSolve;
}

function m87_solve_gate($text, $pageUrl)
{
    if (!function_exists('openssl_decrypt')) return null;

    /* Cookie 名：document.cookie="__test=" ... 也可能是别的名字 */
    $name = '__test';
    if (preg_match('/document\.cookie\s*=\s*["\']([A-Za-z0-9_\-]+)=/', $text, $m)) {
        $name = $m[1];
    }

    /* 三组十六进制数：顺序可能写成 a= / b= / c= 任意位置 */
    $nums = array();
    if (preg_match_all('/=\s*toNumbers\(\s*["\']([0-9a-fA-F]{32})["\']\s*\)/', $text, $mm)) {
        foreach ($mm[1] as $hex) $nums[] = $hex;
    }
    if (count($nums) < 3) {
        /* 退化写法：直接内联 toNumbers("...") 三段 */
        if (preg_match_all('/toNumbers\(\s*["\']([0-9a-fA-F]{32})["\']\s*\)/', $text, $mm)) {
            foreach ($mm[1] as $hex) $nums[] = $hex;
        }
    }
    if (count($nums) < 3) return null;

    $key = hex2bin($nums[0]);
    $iv  = hex2bin($nums[1]);
    $ct  = hex2bin($nums[2]);
    if (strlen($key) !== 16 || strlen($iv) !== 16 || strlen($ct) < 16) return null;

    $raw = @openssl_decrypt($ct, 'aes-128-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    if ($raw === false || $raw === '') return null;
    $val = bin2hex(substr($raw, 0, 16));

    /* 挑战页里若还写了跳转地址，拿它做二次请求（多数站带 Cookie 后原地址即可） */
    $next = $pageUrl;
    if (preg_match('/location\.href\s*=\s*["\']([^"\']+)["\']/', $text, $lm)) {
        $to = html_entity_decode($lm[1], ENT_QUOTES, 'UTF-8');
        $next = m87_abs($to, $pageUrl);
    }
    return array('name' => $name, 'value' => $val, 'next' => $next);
}

function m87_abs($href, $base)
{
    if (preg_match('#^https?://#i', $href)) return $href;
    $p = parse_url($base);
    $scheme = isset($p['scheme']) ? $p['scheme'] : 'https';
    $host = isset($p['host']) ? $p['host'] : '';
    $port = isset($p['port']) ? ':' . $p['port'] : '';
    if (substr($href, 0, 2) === '//') return $scheme . ':' . $href;
    if (substr($href, 0, 1) === '/') return $scheme . '://' . $host . $port . $href;
    $dir = isset($p['path']) ? preg_replace('#/[^/]*$#', '/', $p['path']) : '/';
    return $scheme . '://' . $host . $port . $dir . $href;
}

/* ------------------------------------------------------------------ 主流程 */

$jar = @tempnam(sys_get_temp_dir(), 'm87ck');
$gateTripped = 0;
$cookies = '';
/* 总预算 22 秒：前端等 25 秒，后端必须先返回，宁可早退也不让页面空转 */
$deadline = microtime(true) + 22;
$result = m87_once($url, $UA, $jar, $bin, '', 20);

/* 门禁最多解 3 轮（少数站会连发两次挑战） */
while (!$bin && m87_is_gate($result[0]) && $gateTripped < 3 && (microtime(true) < $deadline - 3)) {
    $solved = m87_solve_gate($result[0], $url);
    if ($solved === null) break;
    $gateTripped++;
    $cookies = $solved['name'] . '=' . $solved['value'];
    /* 第一次解完再请求；若挑战页指定了跳转就先走跳转地址 */
    $target = ($gateTripped === 1 && $solved['next'] !== $url) ? $solved['next'] : $url;
    $result = m87_once($target, $UA, $jar, $bin, $cookies, ceil($deadline - microtime(true)));
    if (!m87_is_gate($result[0])) {
        $url = $target;
        break;
    }
    $url = $target;
}

@unlink($jar);

list($body, $code, $type, $final) = $result;

if ($body === false || $body === null) {
    http_response_code(502);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array('error' => '目标站无响应（连接被拒绝或超时）'));
    exit;
}

/* 仍然停在挑战页：说明不是标准 slowAES，原样回传并打标记，前端可据此提示 */
$stillGate = (!$bin && m87_is_gate($body)) ? '1' : '0';

if ($bin) {
    $out = $type !== '' ? $type : 'application/octet-stream';
} else {
    /* 文本：统一按 UTF-8 回传。GBK 页面先转码，否则中文全是乱码 */
    $isUtf8 = preg_match('/charset\s*=\s*["\']?utf-?8/i', (string) $type) === 1;
    if (!$isUtf8 && function_exists('mb_check_encoding') && !mb_check_encoding($body, 'UTF-8')) {
        $conv = @mb_convert_encoding($body, 'UTF-8', 'GB18030');
        if (is_string($conv) && $conv !== '') $body = $conv;
    }
    $out = 'text/html; charset=utf-8';
    if ($type !== '' && stripos($type, 'charset') === false && stripos($type, 'text/html') === false) {
        $out = $type . '; charset=utf-8';
    }
}

header('Content-Type: ' . $out);
header('X-M87-Status: ' . $code);
header('X-M87-Gate: ' . $stillGate);
header('X-M87-Final: ' . rawurlencode($final));
header('X-M87-Cookies: ' . ($cookies === '' ? '0' : '1'));
header('Cache-Control: no-store');

echo $body;
