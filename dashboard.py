#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SRE道場 ライブダッシュボード（標準ライブラリのみ・依存ゼロ）

Docker の実状態を読んで、ブラウザに:
  - 今の構成図（起動中コンテナから自動生成、変更すると即反映）
  - 各コンテナの CPU / メモリ（上限に対する使用率バー）
  - 今来ている攻撃（k6 コンテナを検知して内容表示）
  - 各コンテナの「ログの見方」コマンド（コピー用。中身は出さない＝自分で読む）
  - 難易度トグル（易しい=メトリクスとログの読み方の解説つき）

使い方:  python dashboard.py [chapter1-physical]
ブラウザ: http://localhost:8090
"""
import sys, os, json, subprocess, threading, time, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

CHAPTER = sys.argv[1] if len(sys.argv) > 1 else "chapter1-physical"
ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = 8090

# 攻撃パターン（k6 の SCENARIO と対応）
SCENARIOS = {
    "ramp":    ("じわ増し負荷", "10→50→200→500人と徐々に増やす。容量(スケール)不足を炙り出す"),
    "spike":   ("スパイク急襲", "いきなり400人が殺到。急増に反応する間もない状況"),
    "cpubomb": ("重い処理攻撃", "1リクエストが重い計算をする。少人数でもCPUを焼き切る"),
    "dbflood": ("DB遅延攻撃", "重いDBクエリを連打。CPU/メモリは余るのに応答だけ遅くなる"),
}

# 各攻撃の攻略導線（易しいモードで攻撃中に表示）。
# 観察 → 確認(どのコンテナのどのボタンか=クリックで開く) → 犯人サイン → 対処、の4ステップ。
# check の各項目 = (role, action, ボタン名, 見るべきもの)
PLAYBOOK = {
    "ramp": {
        "watch": "app の CPU バーと メモリ バー。人数が増えるにつれ、どちらが先に上限へ張り付くか。",
        "check": [("app", "procs", "プロセス上位", "apache2/php がCPUを食っているか"),
                  ("app", "workers", "ワーカー数", "apache2 が増え続けてメモリを圧迫していないか")],
        "sign": "CPU が 50%(＝0.5コアの上限) に張り付く／メモリが 256MiB 上限に迫り、応答が急に遅くなる。1台の処理能力を超えた状態。",
        "fix": "1台の限界。<b>スケールアウト</b>で耐える → 第2章で app を複数台にし、前に <b>ロードバランサー</b> を置いて分散する（第1章では上限までが答え）。",
        "wrong": "ここでDBを疑っても直らない。db のCPU/接続はまだ余裕のはず（自分で確認して切り分けろ）。",
    },
    "spike": {
        "watch": "開始3秒でいきなり400人。app の CPU バーが一瞬で天井に張り付く様子。",
        "check": [("app", "workers", "ワーカー数", "処理中の作業員が一気に増える"),
                  ("app", "logs", "ログ", "503 や応答遅延の兆候")],
        "sign": "反応する間もなくCPU/ワーカーが飽和。じわ増しと違い、増やす猶予がない＝事前に備えるしかないと分かる。",
        "fix": "急増は事後では間に合わない。<b>Auto Scaling（自動増設）</b>や、平常から余裕を持った台数＝<b>プロビジョニング</b>で備える（第2〜3章の主題）。",
        "wrong": "「後から手で増やす」では急襲に勝てない。それを体感するのがこの攻撃の狙い。",
    },
    "cpubomb": {
        "watch": "たった20人なのに app の CPU バーだけが天井。メモリは低いまま。",
        "check": [("app", "procs", "プロセス上位", "php がCPU%上位に居座る"),
                  ("app", "stats", "リソース", "CPUだけ高く、プロセス数(PIDs)は少ない")],
        "sign": "人数が少ないのにCPUが張り付く＝1リクエストの処理が重い（計算過多）。台数でなく処理自体が犯人。",
        "fix": "重い処理そのものを軽くする → <b>結果をキャッシュ</b>（同じ計算を毎回しない）、非同期化、アルゴリズム改善。むやみに台数を増やすのは金の無駄。",
        "wrong": "台数を増やせば「捌ける数」は増えるが、1発が重い問題は残る。まず処理を軽くするのが筋。",
    },
    "dbflood": {
        "watch": "app の CPU/メモリは余裕なのに、応答だけ遅い。犯人は app じゃない。",
        "check": [("db", "conns", "接続数/上限", "Threads_connected が max_connections(50) に迫る/超える"),
                  ("db", "proclist", "実行中クエリ", "SELECT SLEEP … が大量に並ぶ＝重いクエリが接続を長く握る"),
                  ("db", "logs", "ログ", "Too many connections が出ていないか")],
        "sign": "リソースは余ってるのに遅い＝『待ち』。DB接続が上限まで埋まり、新規は接続できず弾かれる。",
        "fix": "① 遅いクエリを速く（インデックス/クエリ改善）。② <b>コネクションプール</b>で接続を使い回す。③ 読み取りを<b>リードレプリカ</b>に逃がす。④ 応急で max_connections↑（根本治療ではない）。",
        "wrong": "app を増やしてもDBが詰まってるので無意味。むしろ接続が増えてDBがさらに苦しむ。ボトルネックの層を見極めろ。",
    },
}

_lock = threading.Lock()
_cache = {"t": 0.0, "data": None}
_attack_lock = threading.Lock()  # 攻撃の起動/停止を直列化（裏スレッド同士の競合防止）

# サービス健全性カナリア: dashboard 自身が定期的に app を叩き、生きているかを測る
_canary = {"state": "up", "rate": 100, "ms": 0, "samples": []}


def _canary_loop():
    import urllib.request
    while True:
        ok = False
        t0 = time.time()
        try:
            with urllib.request.urlopen("http://localhost:8080/", timeout=2) as r:
                body = r.read(64)
                ok = (r.status == 200 and body[:2] == b"OK")
        except Exception:
            ok = False
        ms = int((time.time() - t0) * 1000)
        s = _canary["samples"]
        s.append(1 if ok else 0)
        if len(s) > 8:
            s.pop(0)
        rate = round(sum(s) / len(s) * 100) if s else 100
        state = "up" if rate >= 80 else ("degraded" if rate >= 35 else "down")
        _canary.update({"state": state, "rate": rate, "ms": ms})
        time.sleep(1.2)


def read_maxconn():
    """docker-compose.yml の現在の --max-connections 値を読む（ミッションの修正検知用）。"""
    try:
        with open(os.path.join(ROOT, CHAPTER, "docker-compose.yml"), encoding="utf-8") as f:
            m = re.search(r"--max-connections=(\d+)", f.read())
            return int(m.group(1)) if m else None
    except Exception:
        return None


def run(args, timeout=15):
    try:
        p = subprocess.run(["docker"] + args, capture_output=True, text=True,
                            timeout=timeout, encoding="utf-8", errors="replace")
        return p.stdout or ""
    except Exception:
        return ""


def docker_logs(name, lines):
    """docker logs をstdout/stderr両方まとめて返す（コンテナのログはstderrにも出る）。"""
    try:
        p = subprocess.run(["docker", "logs", "--tail", str(lines), name],
                           capture_output=True, text=True, timeout=12,
                           encoding="utf-8", errors="replace")
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"(ログ取得エラー: {e})"


def run_out(args, timeout=15):
    """任意のdockerコマンドのstdout+stderrをまとめて返す（診断用）。"""
    try:
        p = subprocess.run(["docker"] + args, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return ((p.stdout or "") + (p.stderr or "")).strip() or "(出力なし)"
    except Exception as e:
        return f"(実行エラー: {e})"


# 診断アクション: key -> dockerに渡す引数を作る関数。実コマンドを撃って結果を見せる。
DIAG = {
    "logs":     lambda n: ["logs", "--tail", "60", n],
    "stats":    lambda n: ["stats", "--no-stream", "--format",
                           "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}", n],
    # app(Apache/PHP)向け
    "procs":    lambda n: ["exec", n, "sh", "-c",
                           "ps -eo pid,pcpu,pmem,rss,comm --sort=-pcpu 2>/dev/null | head -15 "
                           "|| echo 'ps不可(procps未導入?)'"],
    "workers":  lambda n: ["exec", n, "sh", "-c",
                           "printf 'Apacheワーカー数(処理中の作業員): '; "
                           "ps -C apache2 --no-headers 2>/dev/null | wc -l"],
    # db(MySQL)向け
    "conns":    lambda n: ["exec", n, "sh", "-c",
                           "mysql -uroot -proot -t -e \"SHOW STATUS LIKE 'Threads_connected'; "
                           "SHOW STATUS LIKE 'Threads_running'; "
                           "SHOW GLOBAL STATUS LIKE 'Max_used_connections'; "
                           "SHOW VARIABLES LIKE 'max_connections'\" 2>&1 | grep -vi insecure"],
    "proclist": lambda n: ["exec", n, "sh", "-c",
                           "mysql -uroot -proot -e 'SHOW PROCESSLIST' 2>&1 | grep -vi insecure"],
}


def read_attack_plan():
    """load/attack.js の stages を読んで攻撃内容を人間語にする。"""
    path = os.path.join(ROOT, CHAPTER, "load", "attack.js")
    try:
        with open(path, encoding="utf-8") as f:
            txt = f.read()
    except Exception:
        return "k6 による負荷テスト"
    stages = re.findall(r"target:\s*(\d+)", txt)
    if not stages:
        return "k6 による負荷テスト"
    peak = max(int(s) for s in stages)
    seq = "→".join(s for s in stages if s != "0")
    return f"k6 負荷テスト: 仮想ユーザーを {seq} 人と段階的に増やす（ピーク {peak} 人同時）"


def classify(svc, image):
    im = (image or "").lower()
    if "k6" in im:
        return "attacker"
    if svc in ("lb", "nginx", "proxy", "haproxy") or (svc != "app" and "nginx" in im):
        return "lb"
    if svc == "db" or any(x in im for x in ("mysql", "postgres", "maria", "redis")):
        return "db"
    return "app"


def gather():
    ids = run(["ps", "-q"]).split()
    data = []
    if ids:
        out = run(["inspect"] + ids)
        try:
            data = json.loads(out) if out.strip() else []
        except Exception:
            data = []

    # ライブ CPU/メモリ
    stats = {}
    sout = run(["stats", "--no-stream", "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"])
    for line in sout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            stats[parts[0]] = {"cpu": parts[1], "mem": parts[2], "memperc": parts[3]}

    def pct(s):
        try:
            return float(str(s).replace("%", "").strip())
        except Exception:
            return 0.0

    tiers = {"lb": [], "app": [], "db": []}
    attack = {"active": False, "name": "", "detail": "", "scenario": "", "container": ""}

    for c in data:
        conf = c.get("Config", {}) or {}
        labels = conf.get("Labels", {}) or {}
        svc = labels.get("com.docker.compose.service", "")
        proj = labels.get("com.docker.compose.project", "")
        image = conf.get("Image", "")
        name = (c.get("Name", "") or "").lstrip("/")
        state = c.get("State", {}) or {}
        status = state.get("Status", "unknown")
        host = c.get("HostConfig", {}) or {}
        nano = host.get("NanoCpus", 0) or 0
        memlimit = host.get("Memory", 0) or 0

        role = classify(svc, image)

        if role == "attacker":
            sc = "ramp"
            for e in (conf.get("Env", []) or []):
                if e.startswith("SCENARIO="):
                    sc = e.split("=", 1)[1] or "ramp"
            nm, det = SCENARIOS.get(sc, SCENARIOS["ramp"])
            attack = {"active": status == "running", "name": nm,
                      "detail": det, "scenario": sc, "container": name,
                      "playbook": PLAYBOOK.get(sc)}
            continue

        # dojo 以外のプロジェクトのコンテナは無視（このPCの他の物を映さない）
        if not proj.startswith("dojo"):
            continue

        st = stats.get(name, {})
        cpu_perc = pct(st.get("cpu"))            # 100% = 1コア
        cpu_cap = (nano / 1e9 * 100) if nano else 0  # 例 0.5コア → 50
        cpu_of_cap = (cpu_perc / cpu_cap * 100) if cpu_cap else cpu_perc
        mem_perc = pct(st.get("memperc"))

        card = {
            "name": name,
            "svc": svc or role,
            "image": image,
            "status": status,
            "cpuPerc": round(cpu_perc, 1),
            "cpuCap": round(cpu_cap, 0),
            "cpuOfCap": round(min(cpu_of_cap, 130), 0),
            "cpuLabel": (f"{cpu_perc:.0f}% / {cpu_cap:.0f}% 上限"
                         if cpu_cap else f"{cpu_perc:.0f}%（上限なし）"),
            "mem": st.get("mem", "-"),
            "memPerc": round(mem_perc, 0),
            "memCap": (f"{memlimit // (1024*1024)}MiB" if memlimit else "上限なし"),
            "logCmd": f"docker logs --tail 50 -f {name}",
            "role": role,
        }
        tiers[role].append(card)

    for k in tiers:
        tiers[k].sort(key=lambda x: x["name"])

    return {
        "project": next((c.get("Config", {}).get("Labels", {}).get(
            "com.docker.compose.project", "") for c in data
            if c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project", "").startswith("dojo")), CHAPTER),
        "chapter": CHAPTER,
        "time": time.strftime("%H:%M:%S"),
        "up": bool(tiers["lb"] or tiers["app"] or tiers["db"]),
        "attack": attack,
        "tiers": tiers,
        "health": {"state": _canary["state"], "rate": _canary["rate"], "ms": _canary["ms"]},
        "maxconn": read_maxconn(),
    }


def get_state():
    now = time.time()
    with _lock:
        if _cache["data"] is not None and now - _cache["t"] < 1.5:
            return _cache["data"]
    data = gather()
    with _lock:
        _cache["data"] = data
        _cache["t"] = time.time()
    return data


HTML = r"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SRE道場 ダッシュボード</title>
<style>
  :root{
    --bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#2a313c;
    --txt:#e6edf3;--txt2:#9aa6b2;--txt3:#6b7682;--accent:#3b9eff;
    --ok:#3fb950;--warn:#e3b341;--danger:#f85149;--radius:10px;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
    font-family:-apple-system,"Segoe UI",system-ui,sans-serif;line-height:1.5}
  .wrap{max-width:960px;margin:0 auto;padding:18px 16px 60px}
  .top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
  h1{font-size:19px;margin:0;font-weight:600}
  .clock{color:var(--txt3);font-size:13px}
  .seg{display:inline-flex;border:1px solid var(--line);border-radius:999px;overflow:hidden}
  .seg button{background:transparent;color:var(--txt2);border:0;padding:6px 14px;font-size:13px;cursor:pointer;font-family:inherit}
  .seg button.on{background:var(--accent);color:#001}
  .attacks{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
  .attacks .albl{color:var(--txt3);font-size:13px;margin-right:2px}
  .attacks button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer;font-family:inherit}
  .attacks button:hover{border-color:var(--accent);background:#22304a}
  .attacks button.stopbtn{border-color:#5c2a28;color:#ff8a80}
  .attacks button.stopbtn:hover{background:#2a1210}
  .alegend{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:12px;color:var(--txt2);line-height:1.8}
  .attack{border-radius:var(--radius);padding:11px 15px;margin-bottom:14px;font-size:14px;border:1px solid var(--line);background:var(--panel)}
  .attack.on{border-color:var(--danger);background:#2a1210;animation:pulse 1.3s infinite}
  @keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(248,81,73,.0)}50%{box-shadow:0 0 0 4px rgba(248,81,73,.18)}}
  .attack .h{font-weight:700}
  .attack.on .h{color:#ff8a80}
  .diagram{display:flex;flex-direction:column;align-items:center;gap:0}
  .tierlabel{color:var(--txt3);font-size:12px;margin:2px 0}
  .conn{width:2px;height:22px;background:var(--line);position:relative}
  .conn.hot{background:var(--danger)}
  .conn.hot::after{content:"";position:absolute;left:-3px;top:0;width:8px;height:8px;border-radius:50%;background:var(--danger);animation:drop 1s linear infinite}
  @keyframes drop{0%{top:0;opacity:1}100%{top:22px;opacity:0}}
  .cloud{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:8px 20px;font-size:14px;color:var(--txt2)}
  .row{display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:12px;width:210px}
  .card .n{font-size:13px;font-weight:600;display:flex;align-items:center;gap:7px;word-break:break-all}
  .card .sub{font-size:11px;color:var(--txt3);margin:1px 0 9px}
  .dot{width:9px;height:9px;border-radius:50%;flex:none}
  .dot.ok{background:var(--ok)}.dot.bad{background:var(--danger)}
  .metric{font-size:11px;color:var(--txt2);margin:7px 0 3px;display:flex;justify-content:space-between}
  .bar{height:8px;background:#0b0f14;border-radius:5px;overflow:hidden}
  .fill{height:100%;width:0;background:var(--ok);transition:width .5s ease}
  .fill.warn{background:var(--warn)}.fill.danger{background:var(--danger)}
  .logcmd{margin-top:10px;font-size:11px}
  .logcmd code{display:block;background:#0b0f14;border:1px solid var(--line);border-radius:6px;padding:6px 8px;color:#9ecbff;cursor:pointer;word-break:break-all;font-family:ui-monospace,Consolas,monospace}
  .logcmd code:hover{border-color:var(--accent)}
  .hint{font-size:11px;color:var(--txt3);margin-top:4px}
  .help{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px;margin-top:22px;font-size:13px;color:var(--txt2)}
  .help h3{margin:0 0 8px;font-size:14px;color:var(--txt)}
  .help li{margin:4px 0}
  .help code{background:#0b0f14;padding:1px 6px;border-radius:4px;color:#9ecbff;font-family:ui-monospace,Consolas,monospace}
  .down{text-align:center;color:var(--txt2);padding:40px;border:1px dashed var(--line);border-radius:var(--radius)}
  .toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--accent);color:#001;padding:8px 16px;border-radius:8px;font-size:13px;opacity:0;transition:opacity .3s;pointer-events:none}
  .toast.show{opacity:1}
  .easyonly{display:none}
  body.easy .easyonly{display:block}
  .logbtn{margin-top:9px;width:100%;background:#0b0f14;color:#9ecbff;border:1px solid var(--line);border-radius:6px;padding:6px;font-size:12px;cursor:pointer;font-family:inherit}
  .logbtn:hover{border-color:var(--accent)}
  .logmodal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:flex-end;justify-content:center;z-index:50}
  .logmodal.hidden{display:none}
  .logbox{background:var(--panel);border:1px solid var(--line);border-radius:12px 12px 0 0;width:100%;max-width:960px;height:62vh;display:flex;flex-direction:column}
  .loghead{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)}
  .loghead span{font-weight:600;font-size:14px}
  .loghead button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:7px;padding:6px 13px;cursor:pointer;font-family:inherit}
  #logbody{margin:0;padding:12px 16px;overflow:auto;flex:1;font-family:ui-monospace,Consolas,monospace;font-size:12px;line-height:1.5;color:var(--txt2);white-space:pre-wrap;word-break:break-all}
  .lerr{color:#ff8a80;font-weight:600}
  .card.easyw{width:320px}
  .chint{margin-top:9px;background:#0b0f14;border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:11px;color:var(--txt2);line-height:1.6}
  .chint b{color:var(--txt)}
  .diagbtns{display:flex;gap:6px;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line)}
  .diagbtns button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:7px;padding:6px 11px;font-size:12px;cursor:pointer;font-family:inherit}
  .diagbtns button.on{background:var(--accent);color:#001;border-color:var(--accent)}
  .diagcmd{padding:7px 16px;font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#9ecbff;border-bottom:1px solid var(--line);word-break:break-all;background:#0b0f14}
  .diagguide{padding:11px 16px;border-top:1px solid var(--line);font-size:12px;color:var(--txt2);line-height:1.8;background:var(--panel2)}
  .diagguide b{color:var(--txt)}
  .pb{background:var(--panel);border:1px solid #5c4a12;border-left:3px solid var(--warn);border-radius:var(--radius);padding:13px 16px;margin:0 0 16px;font-size:13px}
  .pb h4{margin:0 0 10px;font-size:14px;color:var(--warn)}
  .pb .step{margin:9px 0;padding-left:27px;position:relative;color:var(--txt2);line-height:1.7}
  .pb .step .num{position:absolute;left:0;top:1px;width:19px;height:19px;border-radius:50%;background:var(--warn);color:#1a1400;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center}
  .pb .step b{color:var(--txt)}
  .pb .cbtn{display:inline-block;margin:3px 6px 3px 0;background:#0b0f14;color:#9ecbff;border:1px solid var(--line);border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer;font-family:inherit}
  .pb .cbtn:hover{border-color:var(--accent)}
  .pb .look{color:var(--txt3);font-size:12px}
  .pb .fix{background:#0f2a16;border:1px solid #1e5c30;border-radius:6px;padding:9px 12px;margin-top:6px;color:#c9f0d4;line-height:1.7}
  .pb .wrong{color:var(--txt3);font-size:12px;margin-top:8px}
  .canary{display:flex;align-items:center;gap:11px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:11px 16px;margin-bottom:12px}
  .canary .lamp{width:13px;height:13px;border-radius:50%;flex:none}
  .canary .st{font-weight:700;font-size:15px}
  .canary .sub{color:var(--txt3);font-size:12px;margin-left:auto;text-align:right}
  .canary .csub2{font-size:11px;color:var(--txt3);margin-top:2px}
  .canary.up{border-color:#1e5c30} .canary.up .lamp{background:var(--ok);box-shadow:0 0 8px var(--ok)} .canary.up .st{color:var(--ok)}
  .canary.degraded{border-color:#5c4a12} .canary.degraded .lamp{background:var(--warn)} .canary.degraded .st{color:var(--warn)}
  .canary.down{border-color:#5c2a28;animation:pulse 1.3s infinite} .canary.down .lamp{background:var(--danger);box-shadow:0 0 8px var(--danger)} .canary.down .st{color:var(--danger)}
  .mission{background:var(--panel);border:1px solid var(--accent);border-left:3px solid var(--accent);border-radius:var(--radius);padding:15px 17px;margin-bottom:14px}
  .mission .mtag{font-size:11px;color:var(--accent);font-weight:600;letter-spacing:.05em}
  .mission h4{margin:3px 0 9px;font-size:16px;color:var(--txt)}
  .mission p{margin:7px 0;color:var(--txt2);font-size:13px;line-height:1.75}
  .mission code{background:#0b0f14;padding:2px 7px;border-radius:4px;color:#9ecbff;font-family:ui-monospace,Consolas,monospace}
  .mbtn{background:var(--accent);color:#001;border:0;border-radius:8px;padding:10px 17px;font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;margin-top:9px}
  .mbtn:hover{background:#5cb0ff}
  .mbtn2{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer;font-family:inherit;margin-top:9px}
  .mbtn2:hover{border-color:var(--accent)}
  .mstep{display:inline-block;background:var(--accent);color:#001;font-size:11px;font-weight:700;border-radius:999px;padding:2px 9px;margin-bottom:4px}
  .mok{color:var(--ok);font-weight:600}
  .mclear{text-align:center;padding:6px 0}
  .mclear h4{color:var(--ok);font-size:20px;margin:4px 0 8px}
  .mnote{color:var(--txt3);font-size:12px;background:#0b0f14;border-radius:6px;padding:9px 12px;text-align:left;line-height:1.7}
</style></head>
<body class="easy">
<div class="wrap">
  <div class="top">
    <div><h1>🥋 SRE道場 ダッシュボード</h1><div class="clock" id="clock"></div></div>
    <div class="seg">
      <button id="b-easy" class="on" onclick="setMode('easy')">易しい（解説つき）</button>
      <button id="b-hard" onclick="setMode('hard')">難しい（数値だけ）</button>
    </div>
  </div>

  <div id="canary"></div>
  <div id="mission"></div>

  <div id="body"></div>
</div>
<div id="logmodal" class="logmodal hidden">
  <div class="logbox">
    <div class="loghead"><span id="logtitle"></span><button onclick="closeLog()">✕ 閉じる</button></div>
    <div class="diagbtns" id="diagbtns"></div>
    <div class="diagcmd" id="diagcmd"></div>
    <pre id="logbody"></pre>
    <div class="diagguide easyonly" id="diagguide"></div>
  </div>
</div>
<div class="toast" id="toast">コピーした</div>

<script>
let MODE = localStorage.getItem('dojoMode') || 'easy';
function setMode(m){MODE=m;localStorage.setItem('dojoMode',m);
  document.body.classList.toggle('easy',m==='easy');
  document.getElementById('b-easy').classList.toggle('on',m==='easy');
  document.getElementById('b-hard').classList.toggle('on',m==='hard');}
setMode(MODE);

const ATTACKS={
  ramp:['じわ増し負荷','10→50→200→500人と徐々に増やす。容量(スケール)不足を炙り出す'],
  spike:['スパイク急襲','いきなり400人が殺到。急増に反応する間もない状況'],
  cpubomb:['重い処理攻撃','1リクエストが重い計算をする。少人数でもCPUを焼き切る'],
  dbflood:['DB遅延攻撃','重いDBクエリを連打。CPU/メモリは余るのに応答だけ遅くなる'],
};
function toast(m){const to=document.getElementById('toast');to.textContent=m;to.classList.add('show');setTimeout(()=>to.classList.remove('show'),1200);}
function copyCmd(el){const t=el.textContent;if(navigator.clipboard)navigator.clipboard.writeText(t);toast('コピーした');}
function pollBurst(){[250,800,1600,2600,3600].forEach(function(ms){setTimeout(tick,ms);});}
function fire(t){toast('攻撃を起動中… '+ATTACKS[t][0]);fetch('/api/attack?type='+t,{method:'POST'});pollBurst();}
function stopAttack(){toast('攻撃を停止中…');fetch('/api/stop',{method:'POST'});pollBurst();}
// 自由攻撃ボタンは撤去。攻撃はミッションが駆動する。

const DIAG_ACTIONS={
  app:[['logs','ログ'],['procs','プロセス上位(CPU)'],['workers','ワーカー数'],['stats','リソース']],
  db: [['logs','ログ'],['conns','接続数/上限'],['proclist','実行中クエリ'],['stats','リソース']],
  lb: [['logs','ログ'],['stats','リソース']],
};
const DIAG_GUIDE={
  app:'<b>appの診かた（Apache/PHP）:</b><br>・CPUバーが上限(100%) → 「プロセス上位」で <b>apache2</b>/<b>php</b> がCPUを食ってるか確認（計算過多 or リクエスト過多）。<br>・メモリが上限近い → 「ワーカー数」を見る。<b>apache2</b> が多数＝同時処理がRAMで頭打ち＝新規は行列待ち。<br>・ログに <b>503</b> / <b>Connection refused</b> → 犯人はappでなくDB。dbを診ろ。',
  db:'<b>dbの診かた（MySQL）:</b><br>・「接続数/上限」で <b>Threads_connected</b> が <b>max_connections</b> に迫る → 接続あふれ（ログに <b>Too many connections</b>）。対処＝上限↑/コネクションプール/リードレプリカ。<br>・「実行中クエリ」に <b>Sleep</b> や重い行が並ぶ → 遅いクエリが接続を長く握ってる。<br>・CPUもメモリも低いのに遅い → 待ち（ロック/遅延）。リソースでなく設計を疑え。',
  lb:'<b>lbの診かた:</b><br>・「ログ」で振り分け先やエラー、「リソース」でLB自身の負荷を確認。',
};
let curName=null, curRole='app', curAction='logs', diagTimer=null;
function openLog(name, role){curName=name;curRole=(DIAG_ACTIONS[role]?role:'app');curAction='logs';
  document.getElementById('logtitle').textContent='🔍 診断: '+name+'（2.5秒ごとに自動更新／赤い行=悲鳴）';
  document.getElementById('diagbtns').innerHTML=DIAG_ACTIONS[curRole].map(function(a){return '<button data-a="'+a[0]+'" onclick="setAction(\''+a[0]+'\')">'+a[1]+'</button>';}).join('');
  document.getElementById('diagguide').innerHTML=DIAG_GUIDE[curRole]||'';
  document.getElementById('logmodal').classList.remove('hidden');
  setAction('logs');
  clearInterval(diagTimer);diagTimer=setInterval(runDiag,2500);}
function setAction(a){curAction=a;
  Array.prototype.forEach.call(document.querySelectorAll('#diagbtns button'),function(b){b.classList.toggle('on',b.getAttribute('data-a')===a);});
  runDiag();}
function closeLog(){document.getElementById('logmodal').classList.add('hidden');curName=null;clearInterval(diagTimer);}
function escHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmtLog(t){return t.split('\n').map(function(l){var e=escHtml(l);
  return /error|too many connections|fatal|503|cannot|denied|aborted|refused|warn|Sleep/i.test(l)?'<span class="lerr">'+e+'</span>':e;}).join('\n');}
async function runDiag(){if(!curName)return;
  try{const r=await fetch('/api/diag?name='+encodeURIComponent(curName)+'&action='+curAction);const j=await r.json();
    document.getElementById('diagcmd').textContent='$ '+(j.cmd||'');
    const b=document.getElementById('logbody');const atBottom=b.scrollTop+b.clientHeight>=b.scrollHeight-30;
    b.innerHTML=fmtLog(j.out||'(空)');if(curAction==='logs'&&atBottom)b.scrollTop=b.scrollHeight;}catch(e){}}

let ROLE2NAME={};
function openDiagFor(role, action){
  const name=ROLE2NAME[role];
  if(!name){toast('対象コンテナが見つからない');return;}
  openLog(name, role);
  setAction(action);
}
function renderPlaybook(s){
  const pb=document.getElementById('playbook');
  if(!(s.attack.active && s.attack.playbook && MODE==='easy')){pb.innerHTML='';return;}
  const p=s.attack.playbook;
  const checks=p.check.map(function(c){
    return '<button class="cbtn" onclick="openDiagFor(\''+c[0]+'\',\''+c[1]+'\')">'+c[0]+' → 「'+c[2]+'」を開く</button> <span class="look">'+c[3]+'</span>';
  }).join('<br>');
  pb.innerHTML='<div class="pb"><h4>🎯 この攻撃の攻略手順（'+s.attack.name+'）</h4>'
    +'<div class="step"><span class="num">1</span><b>観察</b>：'+p.watch+'</div>'
    +'<div class="step"><span class="num">2</span><b>確認</b>（ボタンを押すとその診断が直接開く）：<br>'+checks+'</div>'
    +'<div class="step"><span class="num">3</span><b>犯人サイン</b>：'+p.sign+'</div>'
    +'<div class="step"><span class="num">4</span><b>対処（どう直せば耐えるか）</b>：<div class="fix">'+p.fix+'</div><div class="wrong">⚠ やりがちな誤り：'+p.wrong+'</div></div>'
    +'</div>';
}

function fillClass(p){return p>=90?'danger':p>=70?'warn':'';}

const HINTS={
  app:'🩺 <b>見る観点</b>: 同時処理の上限。攻撃中にCPUバーが上限へ張り付く（計算過多）か、メモリでワーカー数が頭打ち（行列待ち）か。診断パネルの「プロセス上位」「ワーカー数」で確認。',
  db:'🩺 <b>見る観点</b>: 接続と遅いクエリ。攻撃中に接続数が上限へ迫る（あふれ）か、実行中クエリに <b>Sleep</b> が並ぶ（待ち）か。診断パネルの「接続数/上限」「実行中クエリ」で確認。',
  lb:'🩺 <b>見る観点</b>: 振り分け先とLB自身の負荷。',
};
function card(c){
  const dot = c.status==='running'?'ok':'bad';
  const cpuFill = fillClass(c.cpuOfCap), memFill = fillClass(c.memPerc);
  const wide = MODE==='easy' ? ' easyw' : '';
  const chint = '';
  let logs = '';
  if(MODE==='easy'){
    logs = '<div class="logcmd">ターミナル派はこれでも見れる（クリックでコピー）:'
         + '<code onclick="copyCmd(this)">'+c.logCmd+'</code></div>';
  }
  const viewbtn = '<button class="logbtn" onclick="openLog(\''+c.name+'\',\''+c.role+'\')">🔍 このコンテナを診断する</button>';
  return '<div class="card'+wide+'"><div class="n"><span class="dot '+dot+'"></span>'+c.svc+'</div>'
    + '<div class="sub">'+c.name+'<br>'+c.image+'</div>'
    + '<div class="metric"><span>CPU</span><span>'+c.cpuLabel+'</span></div>'
    + '<div class="bar"><div class="fill '+cpuFill+'" style="width:'+Math.min(c.cpuOfCap,100)+'%"></div></div>'
    + '<div class="metric"><span>メモリ</span><span>'+c.mem+'（上限 '+c.memCap+'）</span></div>'
    + '<div class="bar"><div class="fill '+memFill+'" style="width:'+Math.min(c.memPerc,100)+'%"></div></div>'
    + chint + viewbtn + logs + '</div>';
}

function tierRow(cards){return '<div class="row">'+cards.map(card).join('')+'</div>';}

function render(s){
  document.getElementById('clock').textContent = '更新 '+s.time+' ／ 章: '+s.chapter+' ／ プロジェクト: '+(s.project||'-');

  ROLE2NAME={};
  if(s.tiers){['lb','app','db'].forEach(function(r){if(s.tiers[r]&&s.tiers[r][0])ROLE2NAME[r]=s.tiers[r][0].name;});}

  renderCanary(s);
  renderMission(s);

  const body = document.getElementById('body');
  if(!s.up){
    body.innerHTML='<div class="down">コンテナが起動していない。<br><br>PowerShellで <b>./dojo.ps1 up</b> を実行してから、このページを開いたままにしろ。</div>';
    return;
  }
  const t = s.tiers;
  const hot = s.attack.active ? ' hot' : '';
  let h = '<div class="diagram">';
  h += '<div class="cloud">☁ インターネット（ユーザー / 攻撃）</div>';
  if(t.lb.length){
    h += '<div class="conn'+hot+'"></div><div class="tierlabel">全リクエストがここへ集まる</div>';
    h += tierRow(t.lb);
    h += '<div class="conn'+hot+'"></div><div class="tierlabel">振り分け</div>';
  } else {
    h += '<div class="conn'+hot+'"></div>';
  }
  if(t.app.length){ h += tierRow(t.app); }
  if(t.db.length){
    h += '<div class="conn'+hot+'"></div><div class="tierlabel">DB接続</div>';
    h += tierRow(t.db);
  }
  h += '</div>';
  body.innerHTML = h;
}

// ===== ミッション1: DB接続の枯渇を耐えろ =====
const M1={attack:'dbflood', file:'chapter1-physical/docker-compose.yml'};
let mStep=0;  // リロードごとに必ず最初(STEP0)から。stale state を残さない
let winHold=0;
function setStep(n){mStep=n;tick();}
function startMission(){toast('ミッション開始：攻撃を撃つ');fetch('/api/attack?type='+M1.attack,{method:'POST'});setStep(1);pollBurst();}
function applyRetry(){toast('適用中…DBを作り直して再攻撃（20秒ほど）');fetch('/api/apply?scenario='+M1.attack,{method:'POST'});winHold=0;setStep(5);pollBurst();}
function resetMission(){fetch('/api/stop',{method:'POST'});winHold=0;setStep(0);}
function renderCanary(s){
  const c=document.getElementById('canary');
  const h=s.health||{state:'up',rate:100,ms:0};
  const label={up:'稼働中',degraded:'劣化（一部エラー）',down:'ダウン'}[h.state]||'—';
  const atk=(s.attack&&s.attack.active)?('🔴 攻撃中：'+s.attack.name):'⚪ 攻撃なし';
  c.className='canary '+h.state;
  c.innerHTML='<span class="lamp"></span>'
    +'<span><span class="st">🎯 対象サイト（app）: '+label+'</span>'
    +'<div class="csub2">'+atk+'　／　localhost:8080（あなたが守る実サイト。この道場画面ではない）</div></span>'
    +'<span class="sub">成功率 '+h.rate+'% ／ 応答 '+h.ms+'ms</span>';
}
function renderMission(s){
  const el=document.getElementById('mission');
  const h=s.health||{state:'up'};
  if(mStep===1 && (h.state==='down'||h.state==='degraded')) mStep=2;
  if(mStep===3 && s.maxconn && s.maxconn!==50) mStep=4;
  if(mStep===5){ if(s.attack.active && h.state==='up'){winHold++;}else{winHold=0;} if(winHold>=4) mStep=6; }
  let b='';
  if(mStep===0) b='<div class="mtag">MISSION 1</div><h4>DB接続の枯渇を耐えろ</h4>'
    +'<p>DBが同時に受けられる接続には上限がある。今その上限は低く設定されてる。負荷をかけると接続があふれ、新しいリクエストが弾かれてサービスが落ちる。<br>まず攻撃を撃って、<b>本当に落ちる</b>のを見ろ。</p>'
    +'<button class="mbtn" onclick="startMission()">▶ ミッション開始（攻撃を撃つ）</button>';
  else if(mStep===1) b='<div class="mstep">STEP 1 ／ 観察</div><h4>攻撃中。対象サイトが壊れるのを待て</h4>'
    +'<p>上の「🎯 対象サイト（app）」の状態を見ろ。攻撃が接続を食いつぶしにいってる。<b>緑じゃなくなったら（黄＝劣化 でも 赤＝ダウン でも）</b>自動で次に進む。<br>※半分のリクエストがエラーになれば、それはもう立派な障害だ。</p>';
  else if(mStep===2) b='<div class="mstep">STEP 2 ／ 診断</div><h4 class="mok">✓ 落ちた。なぜかを突き止めろ</h4>'
    +'<p>db の接続数を見て、<b>上限に張り付いてないか</b>を確かめろ。</p>'
    +'<button class="mbtn2" onclick="openDiagFor(\'db\',\'conns\')">db の「接続数/上限」を開く</button>'
    +'<p style="color:var(--txt3);font-size:12px">→ <code>Threads_connected</code> が <code>max_connections</code>（50）に達してるはず。それが原因だ。</p>'
    +'<button class="mbtn" onclick="setStep(3)">確認した → 直し方へ</button>';
  else if(mStep===3) b='<div class="mstep">STEP 3 ／ 修正（自分の手で）</div><h4>接続の上限を上げろ</h4>'
    +'<p>エディタで <code>'+M1.file+'</code> を開き、<br>　<code>--max-connections=50</code><br>を<br>　<code>--max-connections=200</code><br>に書き換えて<b>保存</b>しろ。保存すると自動で検知する。</p>'
    +'<p class="mok">現在の設定値: '+(s.maxconn||'?')+'　… これが 200 になれば次へ</p>';
  else if(mStep===4) b='<div class="mstep">STEP 4 ／ 適用</div><h4 class="mok">✓ 変更を検知（'+(s.maxconn)+'）</h4>'
    +'<p>ファイルを変えただけでは反映されない。<b>DBを作り直して</b>初めて効く。下を押すと、DBを再構築して攻撃をやり直す（20秒ほど）。</p>'
    +'<button class="mbtn" onclick="applyRetry()">🔧 適用して再挑戦</button>';
  else if(mStep===5) b='<div class="mstep">STEP 5 ／ 検証</div><h4>耐えているか？</h4>'
    +'<p>DB再構築 → 再攻撃中。上の「🎯 対象サイト（app）」が<b>緑（稼働中）</b>を数秒キープすればクリアだ。<br>DB起動に時間がかかるので、緑になるまで少し待て。</p>';
  else if(mStep===6) b='<div class="mclear"><h4>🎉 ミッション1 クリア！</h4>'
    +'<p>接続があふれて落ちたDBを、<b>上限を上げて</b>耐えさせた。「ログで接続枯渇を確認 → 設定を変更 → 適用 → 耐える」を<b>自分の手で1周</b>した。これがSREの基本ループだ。</p>'
    +'<div class="mnote">⚠ 上限を上げるのは<b>対症療法</b>。接続はタダじゃない（1本ごとにメモリを食う）ので無限には上げられない。根本策は<b>コネクションプール</b>（接続を使い回す）や<b>リードレプリカ</b>（読み取りを別DBへ逃がす）＝第2章以降でやる。</div>'
    +'<button class="mbtn2" onclick="stopAttack()">攻撃を止める</button> <button class="mbtn2" onclick="resetMission()">もう一度</button></div>';
  if(mStep>0 && mStep<6) b+='<div style="margin-top:11px"><a href="#" onclick="resetMission();return false" style="color:var(--txt3);font-size:11px">↺ 最初からやり直す（攻撃も止める）</a></div>';
  el.innerHTML='<div class="mission">'+b+'</div>';
}

async function tick(){
  try{const r=await fetch('/api/state');const s=await r.json();render(s);}catch(e){}
}
tick(); setInterval(tick, 2000);
</script>
</body></html>"""


def start_attack(scenario):
    if scenario not in SCENARIOS:
        scenario = "ramp"
    with _attack_lock:  # 停止や別の攻撃と重ならないよう直列化
        run(["rm", "-f", "dojo-attack"])
        loaddir = os.path.join(ROOT, CHAPTER, "load").replace("\\", "/")
        run(["run", "--rm", "-d", "--name", "dojo-attack",
             "--add-host=host.docker.internal:host-gateway",
             "-e", "SCENARIO=" + scenario,
             "-v", loaddir + ":/load",
             "grafana/k6", "run", "/load/attack.js"], timeout=40)
    with _lock:
        _cache["t"] = 0.0  # 次のポーリングで即再取得


def stop_attack():
    with _attack_lock:
        run(["rm", "-f", "dojo-attack"])
    with _lock:
        _cache["t"] = 0.0


def apply_and_retry(scenario):
    """設定変更(compose)を反映するため db を作り直し、その後 攻撃を撃ち直す。"""
    compose = os.path.join(ROOT, CHAPTER, "docker-compose.yml")
    with _attack_lock:
        run(["rm", "-f", "dojo-attack"])
    run(["compose", "-f", compose, "up", "-d", "db"], timeout=120)
    time.sleep(6)
    start_attack(scenario)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/attack":
            t = q.get("type", ["ramp"])[0]
            # docker run は時間がかかるので裏スレッドへ回し、応答は即返す（ボタンの体感を軽く）
            threading.Thread(target=start_attack, args=(t,), daemon=True).start()
            self._json({"ok": True, "type": t})
        elif u.path == "/api/stop":
            threading.Thread(target=stop_attack, daemon=True).start()
            self._json({"ok": True})
        elif u.path == "/api/apply":
            sc = q.get("scenario", ["dbflood"])[0]
            threading.Thread(target=apply_and_retry, args=(sc,), daemon=True).start()
            self._json({"ok": True})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/diag"):
            q = parse_qs(urlparse(self.path).query)
            name = q.get("name", [""])[0]
            action = q.get("action", ["logs"])[0]
            if not re.match(r"^[A-Za-z0-9_.-]+$", name) or action not in DIAG:
                self._json({"cmd": "", "out": "(不正な要求)"})
                return
            args = DIAG[action](name)
            self._json({"cmd": "docker " + " ".join(args), "out": run_out(args)})
            return
        if self.path.startswith("/api/logs"):
            q = parse_qs(urlparse(self.path).query)
            name = q.get("name", [""])[0]
            lines = q.get("lines", ["80"])[0]
            if not re.match(r"^[A-Za-z0-9_.-]+$", name):
                self._json({"log": "(不正なコンテナ名)"})
                return
            self._json({"log": docker_logs(name, lines if lines.isdigit() else "80")})
            return
        if self.path.startswith("/api/state"):
            payload = json.dumps(get_state()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":
    print(f"SRE道場 ダッシュボード: http://localhost:{PORT}  (章: {CHAPTER})")
    print("止めるには この窓で Ctrl+C")
    threading.Thread(target=_canary_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
