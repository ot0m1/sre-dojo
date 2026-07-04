// k6 攻撃スクリプト（4パターン）。環境変数 SCENARIO で切り替える。
//   ramp    ... じわ増し（容量不足を炙る）
//   spike   ... スパイク急襲（いきなり殺到）
//   cpubomb ... 重い処理（少人数でCPUを焼く）
//   dbflood ... DB遅延（重いクエリ連打）
// ダッシュボードのボタンから SCENARIO を指定して起動される。
//
// 各パターンはピークまで上げたあと、その負荷を「4時間」保持し続ける。
// = ダッシュボードの ■停止（docker rm -f）を押すまで、事実上ずっと攻撃が続く。

import http from 'k6/http';
import { check } from 'k6';

const S = __ENV.SCENARIO || 'ramp';
const BASE = __ENV.TARGET || 'http://host.docker.internal:8080';

const HOLD = '4h'; // ピーク到達後の保持時間（停止するまで続くのと同義）

const PLANS = {
  ramp:    { stages: [{ d: '15s', t: 10 }, { d: '20s', t: 50 }, { d: '20s', t: 200 }, { d: '25s', t: 500 }, { d: HOLD, t: 500 }], path: '/' },
  spike:   { stages: [{ d: '3s', t: 400 }, { d: HOLD, t: 400 }], path: '/' },
  cpubomb: { stages: [{ d: '5s', t: 30 }, { d: HOLD, t: 30 }], path: '/?nodb=1' },
  dbflood: { stages: [{ d: '10s', t: 30 }, { d: '15s', t: 80 }, { d: HOLD, t: 80 }], path: '/?dbslow=300&work=0' },
};

const plan = PLANS[S] || PLANS.ramp;

export const options = {
  stages: plan.stages.map((s) => ({ duration: s.d, target: s.t })),
};

const URL = BASE + plan.path;

export default function () {
  const res = http.get(URL);
  check(res, { 'status is 200': (r) => r.status === 200 });
}
