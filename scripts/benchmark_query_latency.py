"""
Mini SIEM — Benchmark độ trễ truy vấn API (p50 / p95 / p99).

Đo hai lớp:
  - client_ms: thời gian vòng đời HTTP (requests, gần với trải nghiệm người dùng)
  - server_ms: query_latency_ms từ JSON (thời gian phần Elasticsearch trong API)

Chạy sau khi đã có đủ dữ liệu index (vd. sau stress_test hoặc seed).
"""

from __future__ import annotations

import argparse
import math
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

DEFAULT_API = "http://localhost:8000"


def percentile_linear(sorted_values: List[float], p: float) -> float:
    """Phân vị p ∈ [0, 100], nội suy tuyến tính (tương tự numpy.percentile)."""
    xs = sorted_values
    n = len(xs)
    if n == 0:
        return 0.0
    if n == 1:
        return float(xs[0])
    rank = (p / 100.0) * (n - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return float(xs[lo])
    w = rank - lo
    return float(xs[lo] * (1 - w) + xs[hi] * w)


@dataclass
class Scenario:
    name: str
    path: str
    params: Optional[Dict[str, Any]] = None


def build_scenarios(now: datetime) -> List[Scenario]:
    """Các kịch bản tương ứng TEST_GUIDE + thêm time range."""
    t0 = (now - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z")
    t1 = now.strftime("%Y-%m-%dT23:59:59Z")
    return [
        Scenario("search_simple", "/search", {"size": 10}),
        Scenario(
            "search_filtered",
            "/search",
            {"event_type": "ids_alert", "severity_min": 4, "size": 50},
        ),
        Scenario("search_fulltext", "/search", {"q": "SQL Injection", "size": 50}),
        Scenario(
            "search_time_ip",
            "/search",
            {
                "time_from": t0,
                "time_to": t1,
                "src_ip": "192.168.1.10",
                "size": 50,
            },
        ),
        Scenario("stats_agg", "/stats", {"interval": "1h"}),
        Scenario("recent", "/recent", {"limit": 50}),
    ]


def run_one(
    session: requests.Session,
    base: str,
    scenario: Scenario,
) -> Tuple[float, Optional[float], bool]:
    """
    Trả về (client_ms, server_ms_or_none, ok).
    """
    url = base.rstrip("/") + scenario.path
    params = scenario.params or {}
    t0 = time.perf_counter()
    try:
        r = session.get(url, params=params, timeout=120)
        client_ms = (time.perf_counter() - t0) * 1000.0
        if r.status_code != 200:
            return client_ms, None, False
        data = r.json()
        server_ms = data.get("query_latency_ms")
        if server_ms is not None:
            server_ms = float(server_ms)
        return client_ms, server_ms, True
    except requests.RequestException:
        client_ms = (time.perf_counter() - t0) * 1000.0
        return client_ms, None, False


def summarize_ms(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"n": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    xs = sorted(values)
    return {
        "n": len(xs),
        "mean": float(statistics.mean(xs)),
        "p50": percentile_linear(xs, 50),
        "p95": percentile_linear(xs, 95),
        "p99": percentile_linear(xs, 99),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark query latency (p50/p95/p99)")
    parser.add_argument("--url", default=DEFAULT_API, help="Base URL API (default: %(default)s)")
    parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=100,
        help="Số lần lặp mỗi kịch bản (default: %(default)s)",
    )
    parser.add_argument(
        "-w",
        "--warmup",
        type=int,
        default=5,
        help="Số request khởi động (bỏ qua khi tính thống kê, default: %(default)s)",
    )
    parser.add_argument(
        "--min-docs",
        type=int,
        default=0,
        help="Cảnh báo nếu health.total_indexed_logs < giá trị này (0 = tắt)",
    )
    args = parser.parse_args()
    base = args.url.rstrip("/")

    session = requests.Session()

    try:
        h = session.get(f"{base}/health", timeout=10).json()
        indexed = h.get("total_indexed_logs", 0)
        print(f"Health: overall={h.get('overall')} | indexed_logs={indexed:,}")
        if args.min_docs > 0 and indexed < args.min_docs:
            print(
                f"⚠️  Cảnh báo: indexed ({indexed:,}) < --min-docs ({args.min_docs:,}) — "
                "p95 có thể không phản ánh tải lớn."
            )
    except Exception as e:
        print(f"❌ Không gọi được /health: {e}")
        return

    now = datetime.now(timezone.utc)
    scenarios = build_scenarios(now)

    print("=" * 72)
    print("  BENCHMARK QUERY LATENCY — Mini SIEM")
    print("=" * 72)
    print(f"  API:         {base}")
    print(f"  Iterations:  {args.iterations}  |  Warmup (bỏ qua): {args.warmup}")
    print("=" * 72)

    for sc in scenarios:
        client_vals: List[float] = []
        server_vals: List[float] = []
        errors = 0

        for i in range(args.warmup + args.iterations):
            c_ms, s_ms, ok = run_one(session, base, sc)
            if not ok:
                errors += 1
                continue
            if i < args.warmup:
                continue
            client_vals.append(c_ms)
            if s_ms is not None:
                server_vals.append(s_ms)

        c_stat = summarize_ms(client_vals)
        s_stat = summarize_ms(server_vals)

        print(f"\n▶ {sc.name}  ({sc.path})")
        if sc.params:
            print(f"  params: {sc.params}")
        print(
            f"  client_ms (HTTP round-trip):  n={c_stat['n']:,}  "
            f"mean={c_stat['mean']:.2f}  p50={c_stat['p50']:.2f}  "
            f"p95={c_stat['p95']:.2f}  p99={c_stat['p99']:.2f}"
        )
        if server_vals:
            print(
                f"  server_ms (query_latency_ms): n={s_stat['n']:,}  "
                f"mean={s_stat['mean']:.2f}  p50={s_stat['p50']:.2f}  "
                f"p95={s_stat['p95']:.2f}  p99={s_stat['p99']:.2f}"
            )
        else:
            print("  server_ms: (endpoint không trả query_latency_ms)")
        if errors:
            print(f"  ⚠️  failed requests (warmup+iter): {errors}")

    print("\n" + "=" * 72)
    print("  Hoàn tất.")
    print("=" * 72)


if __name__ == "__main__":
    main()
