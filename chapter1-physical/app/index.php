<?php
// 素朴なショップAPI。1リクエストごとに:
//   1) MySQLに接続して商品数を数える（DB接続を1本使う）
//   2) ちょっとしたCPU仕事をする
//   3) 結果を返す
// 負荷が上がると、DBの接続数上限・CPU・Apacheのワーカー数、どこかが先に音を上げる。

header('Content-Type: text/plain; charset=utf-8');

// PHP 8.2 の mysqli は既定で例外を投げる。今回は自前でエラーを見て
// 503 を返したいので、例外ではなくエラーコードを返すモードに戻す。
mysqli_report(MYSQLI_REPORT_OFF);

$host = getenv('DB_HOST');
$user = getenv('DB_USER');
$pass = getenv('DB_PASS');
$name = getenv('DB_NAME');

// DB接続（軽くリトライ）
$mysqli = null;
for ($i = 0; $i < 3; $i++) {
    $mysqli = @new mysqli($host, $user, $pass, $name);
    if (!$mysqli->connect_errno) break;
    usleep(200000); // 0.2s
}
if ($mysqli->connect_errno) {
    // ここに来る典型 = "Too many connections"（DBの接続数が上限に達した悲鳴）
    http_response_code(503);
    echo "DB_ERROR: " . $mysqli->connect_error;
    exit;
}

// 遅いDBクエリを模す（?dbslow=ミリ秒）。DBが1本の接続を長く握る状況を作る。
$dbslow = isset($_GET['dbslow']) ? max(0, (int)$_GET['dbslow']) : 0;
if ($dbslow > 0) {
    $mysqli->query("SELECT SLEEP(" . (min($dbslow, 1000) / 1000) . ")");
}

$res = $mysqli->query("SELECT COUNT(*) AS c FROM products");
$row = $res ? $res->fetch_assoc() : ['c' => '?'];

// CPU仕事（?work=数 で重さを調整できる。既定3万回）
$work = isset($_GET['work']) ? max(0, (int)$_GET['work']) : 30000;
$acc = 0.0;
for ($i = 0; $i < $work; $i++) { $acc += sqrt($i); }

$mysqli->close();

echo "OK products=" . $row['c'] . " work=" . $work . " host=" . gethostname();
