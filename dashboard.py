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

_lock = threading.Lock()
_cache = {"t": 0.0, "data": None}


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
                      "detail": det, "scenario": sc, "container": name}
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

  <div class="attacks">
    <span class="albl">攻撃を撃つ:</span>
    <button onclick="fire('ramp')">じわ増し</button>
    <button onclick="fire('spike')">スパイク急襲</button>
    <button onclick="fire('cpubomb')">重い処理</button>
    <button onclick="fire('dbflood')">DB遅延</button>
    <button class="stopbtn" onclick="stopAttack()">■ 停止</button>
  </div>
  <div class="alegend easyonly" id="alegend"></div>

  <div id="attack" class="attack"></div>
  <div id="body"></div>

  <div class="help easyonly">
    <h3>メトリクスとログの読み方（答えは出さない・推測はお前がやる）</h3>
    <ul>
      <li><b>CPUバーが上限（100%）に張り付く</b> → その箱は計算で手一杯。1秒あたりの処理量が頭打ち＝<i>CPUがボトルネックの疑い</i>。</li>
      <li><b>メモリバーが上限に近い</b> → 同時に立てられる作業員（プロセス/ワーカー）の数が頭打ちの疑い。あふれると強制終了(OOM)も。</li>
      <li><b>応答が遅いのにCPUもメモリも余ってる</b> → どこかで「順番待ちの行列」か「接続数の上限」に引っかかってる疑い。</li>
      <li><b>ログの見方</b>：各カードの黒いコマンドをクリックでコピー → 自分のターミナルに貼って実行。<code>-f</code> は追従表示（Ctrl+Cで止める）。</li>
      <li>DBの悲鳴を探すなら db のログで <code>Too many connections</code> / <code>aborted</code>、Webの悲鳴なら app のログで <code>503</code> / <code>MaxRequestWorkers</code> あたりを目で探す。</li>
    </ul>
    <p style="margin:8px 0 0">ログを読んで「これが原因かな？」と思ったら、その推測をチャットの俺にぶつけろ。合ってたら、どこをどう構成変更すれば攻撃に耐えるかを返す。</p>
  </div>
</div>
<div id="logmodal" class="logmodal hidden">
  <div class="logbox">
    <div class="loghead"><span id="logtitle"></span><button onclick="closeLog()">✕ 閉じる</button></div>
    <pre id="logbody"></pre>
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
function fire(t){toast('攻撃開始: '+ATTACKS[t][0]);fetch('/api/attack?type='+t,{method:'POST'}).then(()=>setTimeout(tick,400));}
function stopAttack(){toast('攻撃を停止');fetch('/api/stop',{method:'POST'}).then(()=>setTimeout(tick,400));}
document.getElementById('alegend').innerHTML='<b>各攻撃の狙い（易しいモード）:</b><br>'+Object.keys(ATTACKS).map(k=>'・<b>'+ATTACKS[k][0]+'</b> … '+ATTACKS[k][1]).join('<br>');

let curLog=null, logTimer=null;
function openLog(name){curLog=name;document.getElementById('logtitle').textContent='ログ: '+name+'（赤い行がエラー＝悲鳴。2秒ごとに自動更新）';
  document.getElementById('logmodal').classList.remove('hidden');refreshLog();
  clearInterval(logTimer);logTimer=setInterval(refreshLog,2000);}
function closeLog(){document.getElementById('logmodal').classList.add('hidden');curLog=null;clearInterval(logTimer);}
function escHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmtLog(t){return t.split('\n').map(function(l){var e=escHtml(l);
  return /error|too many connections|fatal|503|cannot|denied|aborted|refused|warn/i.test(l)?'<span class="lerr">'+e+'</span>':e;}).join('\n');}
async function refreshLog(){if(!curLog)return;
  try{const r=await fetch('/api/logs?name='+encodeURIComponent(curLog)+'&lines=100');const j=await r.json();
    const b=document.getElementById('logbody');const atBottom=b.scrollTop+b.clientHeight>=b.scrollHeight-30;
    b.innerHTML=fmtLog(j.log||'(空)');if(atBottom)b.scrollTop=b.scrollHeight;}catch(e){}}

function fillClass(p){return p>=90?'danger':p>=70?'warn':'';}

function card(c){
  const dot = c.status==='running'?'ok':'bad';
  const cpuFill = fillClass(c.cpuOfCap), memFill = fillClass(c.memPerc);
  let logs = '';
  if(MODE==='easy'){
    logs = '<div class="logcmd">ターミナル派はこれでも見れる（クリックでコピー）:'
         + '<code onclick="copyCmd(this)">'+c.logCmd+'</code></div>';
  }
  const viewbtn = '<button class="logbtn" onclick="openLog(\''+c.name+'\')">📄 このコンテナのログを見る</button>';
  return '<div class="card"><div class="n"><span class="dot '+dot+'"></span>'+c.svc+'</div>'
    + '<div class="sub">'+c.name+'<br>'+c.image+'</div>'
    + '<div class="metric"><span>CPU</span><span>'+c.cpuLabel+'</span></div>'
    + '<div class="bar"><div class="fill '+cpuFill+'" style="width:'+Math.min(c.cpuOfCap,100)+'%"></div></div>'
    + '<div class="metric"><span>メモリ</span><span>'+c.mem+'（上限 '+c.memCap+'）</span></div>'
    + '<div class="bar"><div class="fill '+memFill+'" style="width:'+Math.min(c.memPerc,100)+'%"></div></div>'
    + viewbtn + logs + '</div>';
}

function tierRow(cards){return '<div class="row">'+cards.map(card).join('')+'</div>';}

function render(s){
  document.getElementById('clock').textContent = '更新 '+s.time+' ／ 章: '+s.chapter+' ／ プロジェクト: '+(s.project||'-');

  const a = document.getElementById('attack');
  if(s.attack.active){
    a.className='attack on';
    a.innerHTML='<div class="h">⚠ 攻撃 進行中: '+s.attack.name+'</div>'
      +'<div>'+s.attack.detail+'</div>'
      +(MODE==='easy'?'<div class="hint" style="margin-top:5px">この攻撃が来ている間に、下の各コンテナのCPU/メモリがどう動くかを見ろ。先に上限へ張り付いた箱が犯人候補。</div>':'');
  } else {
    a.className='attack';
    a.innerHTML='<div class="h">攻撃なし（待機中）</div>'
      +(MODE==='easy'?'<div class="hint" style="margin-top:4px">別ウィンドウで <code style="background:#0b0f14;padding:1px 5px;border-radius:4px">./dojo.ps1 attack</code> を撃つと、ここに攻撃内容が出て、下のバーが動き出す。</div>':'');
  }

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

async function tick(){
  try{const r=await fetch('/api/state');const s=await r.json();render(s);}catch(e){}
}
tick(); setInterval(tick, 2000);
</script>
</body></html>"""


def start_attack(scenario):
    if scenario not in SCENARIOS:
        scenario = "ramp"
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
    run(["rm", "-f", "dojo-attack"])
    with _lock:
        _cache["t"] = 0.0


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
            start_attack(t)
            self._json({"ok": True, "type": t})
        elif u.path == "/api/stop":
            stop_attack()
            self._json({"ok": True})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
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
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
