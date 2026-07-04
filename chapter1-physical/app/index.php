<?php
// 素朴なショップAPI。1リクエストで:
//   1) （?nodb=1 でなければ）MySQLに接続して商品数を数える
//   2) 重いCPU計算をする（CACHE=1 のときは結果をキャッシュ）
//   3) 結果を返す
// 負荷が上がると、DBの接続数上限 / CPU / Apacheのワーカー、どこかが先に音を上げる。

header('Content-Type: text/plain; charset=utf-8');
mysqli_report(MYSQLI_REPORT_OFF); // 例外でなくエラーコードで扱う（自前で503を返すため）

$nodb = isset($_GET['nodb']) && $_GET['nodb'] === '1';
$products = '-';

if (!$nodb) {
    $host = getenv('DB_HOST');
    $user = getenv('DB_USER');
    $pass = getenv('DB_PASS');
    $name = getenv('DB_NAME');

    // DB接続（軽くリトライ）
    $mysqli = null;
    for ($i = 0; $i < 3; $i++) {
        $mysqli = @new mysqli($host, $user, $pass, $name);
        if (!$mysqli->connect_errno) break;
        usleep(200000);
    }
    if ($mysqli->connect_errno) {
        // 典型 = "Too many connections"。ログにも残す → `docker logs <app>` で追える（調査の起点）
        error_log("[app] DB connect failed: " . $mysqli->connect_error);
        http_response_code(503);
        echo "DB_ERROR: " . $mysqli->connect_error;
        exit;
    }

    // 遅いDBクエリを模す（?dbslow=ミリ秒）。DBが1本の接続を長く握る状況。
    $dbslow = isset($_GET['dbslow']) ? max(0, (int)$_GET['dbslow']) : 0;
    if ($dbslow > 0) {
        $mysqli->query("SELECT SLEEP(" . (min($dbslow, 1000) / 1000) . ")");
    }

    $res = $mysqli->query("SELECT COUNT(*) AS c FROM products");
    $row = $res ? $res->fetch_assoc() : ['c' => '?'];
    $products = $row['c'];
    $mysqli->close();
}

// 重いCPU計算（このページは"重い処理"をする前提）。
// 環境変数 CACHE=1 のとき結果をキャッシュして「毎回の再計算」を避ける（M2の対処）。
$work = isset($_GET['work']) ? max(0, (int)$_GET['work']) : 400000;
$cacheOn = getenv('CACHE') === '1';
$cacheFile = sys_get_temp_dir() . "/work_$work.cache";
if ($cacheOn && is_file($cacheFile) && (time() - filemtime($cacheFile) < 30)) {
    $acc = (float) file_get_contents($cacheFile);            // キャッシュヒット：計算しない
} else {
    $acc = 0.0;
    for ($i = 0; $i < $work; $i++) { $acc += sqrt($i); }     // 重い計算（CPUを食う）
    if ($cacheOn) { @file_put_contents($cacheFile, (string) $acc); }
}

echo "OK products=" . $products . " work=" . $work . " host=" . gethostname();
