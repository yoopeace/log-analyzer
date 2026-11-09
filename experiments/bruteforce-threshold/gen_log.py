import random
from datetime import datetime, timedelta
from pathlib import Path

# 어디서 실행하든 스크립트와 같은 폴더(experiments/)에 만든다
OUTPUT = Path(__file__).parent / 'test.log'

# ── 실험 설정 ──────────────────────────
NORMAL_MAX_FAILS = 5      # 정상 사용자가 10분 안에 최대 몇 번 틀리는가
SLOW_ATTACK_FAILS = 8     # 잠금 정책 의식해 천천히 시도하는 공격
FAST_ATTACK_FAILS = 40    # 대놓고 하는 공격
NORMAL_USER_COUNT = 12    # 정상 사용자 수
SEED = 42                 # 고정하면 매번 같은 로그가 나온다
# ───────────────────────────────────────

random.seed(SEED)
base = datetime(2026, 8, 9, 9, 0, 0)
events = []      # (시각, IP)
truth = {}       # IP → 'normal' / 'attack'  ← 정답지

def add_burst(ip, start_offset_min, count, spread_min, label):
    """한 IP가 spread_min분에 걸쳐 count회 실패하도록 이벤트 생성"""
    truth[ip] = label
    start = base + timedelta(minutes=start_offset_min)
    for _ in range(count):
        t = start + timedelta(seconds=random.uniform(0, spread_min * 60))
        events.append((t, ip))

# 정상 사용자: 비밀번호 오타. 8분에 걸쳐 흩어져서 몇 번.
for i in range(NORMAL_USER_COUNT):
    ip = f'192.168.1.{10 + i}'
    add_burst(ip, i * 7, random.randint(1, NORMAL_MAX_FAILS), 8, 'normal')

# 조심스러운 공격: 탐지 피하려고 천천히 (9분에 걸쳐)
add_burst('203.0.113.50', 20, SLOW_ATTACK_FAILS, 9, 'attack')
add_burst('203.0.113.51', 45, SLOW_ATTACK_FAILS, 9, 'attack')

# 노골적인 공격: 3분에 몰아서
add_burst('198.51.100.7', 70, FAST_ATTACK_FAILS, 3, 'attack')

events.sort()

with open(OUTPUT, 'w') as f:
    for t, ip in events:
        f.write(f"{t.strftime('%Y-%m-%d %H:%M:%S')} LOGIN_FAIL ip={ip} user=admin\n")

print(f'{OUTPUT} 생성 완료 ({len(events)}줄)\n')
print('=== 정답지 ===')
for ip, label in sorted(truth.items()):
    count = sum(1 for _, e_ip in events if e_ip == ip)
    print(f'{ip:16s} {label:7s} 총 {count}회')
