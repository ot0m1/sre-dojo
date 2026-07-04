// k6 攻撃スクリプト（4パターン）。環境変数 SCENARIO で切り替える。
//   ramp    ... じわ増し（容量不足を炙る）
//   spike   ... スパイク急襲（いきなり殺到）
//   cpubomb ... 重い処理（少人数でCPUを焼く）
//   dbflood ... DB遅延（重いクエリ連打）
// ダッシュボードのボタンから SCENARIO を指定して起動される。

import http from 'k6/http';
import { check } from 'k6';

const S = __ENV.SCENARIO || 'ramp';
const BASE = __ENV.TARGET || 'http://host.docker.internal:8080';

const PLANS = {
  ramp:    { stages: [{ d: '15s', t: 10 }, { d: '20s', t: 50 }, { d: '20s', t: 200 }, { d: '30s', t: 500 }, { d: '10s', t: 0 }], path: '/' },
  spike:   { stages: [{ d: '3s', t: 400 }, { d: '40s', t: 400 }, { d: '3s', t: 0 }], path: '/' },
  cpubomb: { stages: [{ d: '5s', t: 20 }, { d: '45s', t: 20 }, { d: '5s', t: 0 }], path: '/?work=400000' },
  dbflood: { stages: [{ d: '10s', t: 30 }, { d: '45s', t: 80 }, { d: '10s', t: 0 }], path: '/?dbslow=300' },
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
