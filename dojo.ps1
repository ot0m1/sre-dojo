<#
  SRE道場ドライバ。PowerShellから叩く。
  例:
    ./dojo.ps1 up
    ./dojo.ps1 open
    ./dojo.ps1 stats
    ./dojo.ps1 attack
    ./dojo.ps1 logs
    ./dojo.ps1 down
  別の章は -Chapter で切り替え:
    ./dojo.ps1 up -Chapter chapter2-vm
#>
param(
  [Parameter(Position = 0)]
  [ValidateSet('up','open','dashboard','stats','attack','logs','down','ps')]
  [string]$Command = 'up',

  [string]$Chapter = 'chapter1-physical'
)

$ErrorActionPreference = 'Stop'
$root     = $PSScriptRoot
$chapDir  = Join-Path $root $Chapter
$loadDir  = Join-Path $chapDir 'load'

if (-not (Test-Path $chapDir)) { throw "章が見つからない: $chapDir" }

switch ($Command) {
  'up' {
    Write-Host "▶ 建てる: $Chapter (初回はビルドで数分かかる)" -ForegroundColor Cyan
    docker compose -f (Join-Path $chapDir 'docker-compose.yml') up -d --build
    Write-Host "`n起動した。DBの初期化に20秒ほど待ってから attack しろ。" -ForegroundColor Green
    Write-Host "ブラウザ確認: ./dojo.ps1 open   /   監視: ./dojo.ps1 stats" -ForegroundColor Green
  }
  'open' {
    Start-Process 'http://localhost:8080/'
  }
  'dashboard' {
    Write-Host "▶ ライブダッシュボードを起動: http://localhost:8090" -ForegroundColor Cyan
    $py = (Get-Command python -ErrorAction SilentlyContinue) ?? (Get-Command py -ErrorAction SilentlyContinue)
    if (-not $py) { throw "python が見つからない" }
    Start-Process -FilePath $py.Source -ArgumentList @((Join-Path $root 'dashboard.py'), $Chapter) -WorkingDirectory $root
    Start-Sleep -Seconds 2
    Start-Process 'http://localhost:8090/'
  }
  'stats' {
    Write-Host "▶ リソース監視（Ctrl+Cで抜ける）。攻撃中にCPU/メモリが振り切れるのを見ろ。" -ForegroundColor Cyan
    docker stats
  }
  'attack' {
    Write-Host "▶ 攻める: k6で負荷を撃ち込む（約95秒）" -ForegroundColor Yellow
    docker run --rm -i --add-host=host.docker.internal:host-gateway `
      -v "${loadDir}:/load" grafana/k6 run /load/attack.js
  }
  'logs' {
    docker compose -f (Join-Path $chapDir 'docker-compose.yml') logs --tail=80
  }
  'ps' {
    docker compose -f (Join-Path $chapDir 'docker-compose.yml') ps
  }
  'down' {
    Write-Host "▶ 片付け: コンテナとデータを消す" -ForegroundColor Cyan
    docker compose -f (Join-Path $chapDir 'docker-compose.yml') down -v
  }
}
