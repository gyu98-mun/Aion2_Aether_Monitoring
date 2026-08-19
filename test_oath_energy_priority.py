"""
1값 형식(header1=0x08) CHANGE 이벤트 해석에 대한 회귀 테스트. 2026-08-08 하루에만 세 번
고쳐졌다 - 아래에 세 사건을 순서대로 남긴다.

**사건 1 (되돌림): "기본오드 우선 소모" 분기, 1차 시도.** 사용자가 알려준 게임 메커니즘
("오드에너지 소모는 기본오드부터 먼저 깎이고, 기본이 0이 된 뒤에야 추가오드가 깎인다")을 근거로
"known_base>0이면 패킷값을 통째로 새 기본오드로 대입"하는 분기를 추가했다가, 같은 날 바로
되돌렸다 - 정기 충전 시뮬레이션이 known_base를 허위로 계속 부풀려서(대부분의 캐릭터가 항상
known_base>0), 원래 정상 동작하던 순수 추가오드 소모(아이템 소모 등)까지 전부 "기본이 줄어든
것"으로 잘못 해석해버리는 회귀가 실사용에서 발생했다. **원인은 메커니즘 자체가 아니라 구현이었다**
(패킷값을 그대로 새 기본으로 대입해버려서, 감소량이 기본보다 작을 때도 완전히 틀린 값이 들어감) -
이건 사건 3에서 재확인된다.

**사건 2 (재정정): 값의 의미 자체가 "새 추가오드"가 아니라 "새 총량"이었다.** 기본오드=40,
추가오드=600(총 640)인 상태에서 오드 80이 줄었는데, 패킷에 온 값은 560이었다. "새 추가오드"로
보면 안 맞지만(600->560이면 -40, 실제 감소량 80과 불일치), "새 총량"으로 보면 맞아떨어진다
(640-80=560). 이 필드는 aion2_core.py 최초 발견 당시 주석에도 "새총량"이라 적혀 있었는데,
2026-07-07에 "추가오드만 가리키는 것으로 보인다"고 재정정했던 게 오히려 틀렸다 - 그 재정정은
기본오드가 우연히 0인 테스트 캐릭터만으로 내린 결론이라 "새총량"과 "새 추가오드"가 산술적으로
구분이 안 되는 케이스였다(0+추가=추가=총량). **수정:** `dynamic = new_total - known_base`로
역산(기본은 그대로 둔다는 가정).

**사건 3 (같은 날 두 번째 재정정): 총량(560)만으로는 "기본 불변" 해석과 "기본-우선-소모" 해석을
구분할 수 없었다.** 둘 다 총 560이 나오기 때문이다(기본40 그대로+추가520=560, 또는 기본0+추가
560=560). 사용자에게 그 감소 직후 게임 화면의 기본/추가 개별 숫자를 물어봤고, **"0/560"**이라는
답을 받았다 - 즉 사건 1의 메커니즘(기본-우선-소모)이 맞았다는 게 최종 확정됐다. 다만 사건 1의
구현은 틀렸었다(패킷값을 통째로 새 기본으로 대입) - 이번엔 `known_base`/`last_dynamic`으로 실제
감소량을 역산해서(구총량-신총량) 기본부터 정확히 그만큼만 깎고, 남으면 추가로 넘기는 올바른
부분드레인 공식(`_resolve_decrease_split`, `aion2_live_monitor.py`)을 쓴다. 정기충전 시뮬레이션이
이미 죽은코드로 격리되어 known_base가 더 이상 허위로 부풀지 않는다는 전제 위에서 동작하므로, 사건
1의 회귀 원인(known_base가 항상 부풀어 있어 이 분기가 정상적인 소모까지 가로챔)은 이제 없다.
**부수 수정:** delta 계산도 "추가오드만의 변화량"에서 "총량의 변화량"으로 바꿨다 - 기본-우선-소모로
기본만 깎이고 추가는 안 바뀌는 경우, 예전 방식(dynamic 차이만 봄)으로는 실제 소모가 있었는데도
delta=0으로 잘못 나온다.

자세한 경위는 memory의 aion2_packet_reverse_engineering.md 참고.

실행: python test_oath_energy_priority.py
"""
import queue
import sys
import tempfile

sys.path.insert(0, ".")
import aion2_core as core
from aion2_live_monitor import LiveCapture
from aion2_storage import CharacterStore

PASS = []
FAIL = []


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}  {detail}")


def make_fake_capture(known_base, last_dynamic, nickname="테스트캐릭"):
    """LiveCapture.__init__을 그대로 쓰면 실제 네트워크/기본 oath_energy_data.json을 건드리므로,
    필요한 속성만 최소로 채운 인스턴스를 직접 만든다."""
    fc = LiveCapture.__new__(LiveCapture)
    fc.event_queue = queue.Queue()
    fc.status_queue = queue.Queue()
    fc.known_oath_id = 51591
    fc.known_base = known_base
    fc.last_dynamic = last_dynamic
    fc.current_nickname = nickname
    fc.current_server = 1001
    fc.current_job = 14
    fc.pending_oath = {}
    fc.combat_power_grace_until = None
    fc._switch_epoch = 0
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    fc.store = CharacterStore(tmp.name)
    return fc


def drain_status(fc):
    msgs = []
    while True:
        try:
            msgs.append(fc.status_queue.get_nowait())
        except queue.Empty:
            break
    return msgs


print("=== 1. (핵심 재확정 테스트) 사용자 실측값: 기본40/추가600, 80감소 -> 패킷값 560 ===")
print("     게임 화면 실측 확인: 감소 후 기본0/추가560 (기본-우선-소모 메커니즘 최종 확정)")
fc = make_fake_capture(known_base=40, last_dynamic=600)
ev = core.OathEnergyEvent(entity_id=51591, new_total=560, delta=None, raw_packet=b"", arrived_at=1.0)
fc._on_oath_energy(ev)
check("known_base가 0으로 전부 소진됨(40 전부 감소분에 흡수)", fc.known_base == 0, f"실제: {fc.known_base}")
check("last_dynamic이 560으로 갱신됨(기본을 다 쓰고 남은 40이 추가에서 깎임)",
      fc.last_dynamic == 560, f"실제: {fc.last_dynamic}")
check("최종 표시 total은 패킷값 그대로 560", ev.new_total == 560, f"실제: {ev.new_total}")
check("delta가 -80으로 정확히 계산됨(총량 기준, 실제 감소량과 일치)", ev.delta == -80, f"실제: {ev.delta}")

print("\n=== 2. 감소량이 기본보다 작을 때 - 기본만 깎이고 추가는 그대로 ===")
fc = make_fake_capture(known_base=40, last_dynamic=600)
# 총 640에서 10 감소 -> 패킷값 630
ev = core.OathEnergyEvent(entity_id=51591, new_total=630, delta=None, raw_packet=b"", arrived_at=1.5)
fc._on_oath_energy(ev)
check("known_base가 30으로만 줄어듦(40-10)", fc.known_base == 30, f"실제: {fc.known_base}")
check("last_dynamic은 600 그대로(감소분이 기본만으로 다 흡수됨)",
      fc.last_dynamic == 600, f"실제: {fc.last_dynamic}")
check("delta가 -10으로 계산됨(총량 기준 - 예전 방식이면 dynamic 변화 없어 0으로 잘못 나왔을 것)",
      ev.delta == -10, f"실제: {ev.delta}")

print("\n=== 2b. 감소량이 기본과 정확히 같을 때(경계값) - 기본이 정확히 0, 추가는 그대로 ===")
fc = make_fake_capture(known_base=40, last_dynamic=600)
ev = core.OathEnergyEvent(entity_id=51591, new_total=600, delta=None, raw_packet=b"", arrived_at=1.6)
fc._on_oath_energy(ev)
check("known_base가 정확히 0", fc.known_base == 0, f"실제: {fc.known_base}")
check("last_dynamic은 600 그대로(경계값에서도 추가는 안 건드림)",
      fc.last_dynamic == 600, f"실제: {fc.last_dynamic}")

print("\n=== 3. known_base가 이미 0일 때 - 예전 확인된 캡처들과 동일하게 순수 추가오드 감소 ===")
fc = make_fake_capture(known_base=0, last_dynamic=300)
ev = core.OathEnergyEvent(entity_id=51591, new_total=250, delta=None, raw_packet=b"", arrived_at=2.0)
fc._on_oath_energy(ev)
check("known_base는 0 그대로", fc.known_base == 0, f"실제: {fc.known_base}")
check("last_dynamic이 250으로 갱신됨(기본이 이미 0이라 전부 추가에서 깎임)",
      fc.last_dynamic == 250, f"실제: {fc.last_dynamic}")
check("delta가 -50으로 계산됨", ev.delta == -50, f"실제: {ev.delta}")

print("\n=== 4. 이번 세션 첫 이벤트(직전 상태 모름) - 드레인 계산 불가, 기존 폴백(기본 동결) ===")
fc = make_fake_capture(known_base=500, last_dynamic=None)
ev = core.OathEnergyEvent(entity_id=51591, new_total=560, delta=None, raw_packet=b"", arrived_at=1.0)
fc._on_oath_energy(ev)
check("known_base는 500 그대로(직전 상태를 몰라 드레인 계산을 못 함)",
      fc.known_base == 500, f"실제: {fc.known_base}")
check("last_dynamic이 60으로 갱신됨(새총량 560 - 기본 500)", fc.last_dynamic == 60, f"실제: {fc.last_dynamic}")

print("\n=== 5. known 상태가 오래돼서(stale) '감소'인데 총량이 오히려 늘어난 경우 - 안전장치 ===")
fc = make_fake_capture(known_base=40, last_dynamic=60)  # 구총량 100
ev = core.OathEnergyEvent(entity_id=51591, new_total=150, delta=None, raw_packet=b"", arrived_at=1.2)
fc._on_oath_energy(ev)
msgs = drain_status(fc)
check("known_base는 안 건드림(폴백 - 기본 동결)", fc.known_base == 40, f"실제: {fc.known_base}")
check("last_dynamic이 110으로 계산됨(150-40, 폴백 방식)", fc.last_dynamic == 110, f"실제: {fc.last_dynamic}")
check("[의심] 로그가 남음(총량이 오히려 증가했다는 신호)",
      any("의심" in m and "증가" in m for m in msgs), f"실제 메시지들: {msgs}")

print("\n=== 6. 2값 형식(header1=0x0c)은 항상 그대로 동작 (기본/추가 둘 다 명시된 경우) ===")
fc = make_fake_capture(known_base=500, last_dynamic=300)
ev = core.OathEnergyEvent(entity_id=51591, new_total=999, delta=None, raw_packet=b"", arrived_at=4.0)
ev.base = 450   # 2값 형식이면 base가 명시적으로 옴
ev.dynamic = 60
fc._on_oath_energy(ev)
check("known_base가 패킷의 명시적 base(450)로 갱신됨", fc.known_base == 450, f"실제: {fc.known_base}")
check("dynamic도 패킷의 명시적 dynamic(60)으로 갱신됨(최종 total=510)",
      ev.new_total == 510, f"실제: {ev.new_total}")
check("delta가 -290으로 계산됨(총량 기준: 510 - 800)", ev.delta == -290, f"실제: {ev.delta}")

print("\n=== 7. 1값 증가 이벤트는 여전히 기본 동결 + 총량에서 역산(기본 우선 충전 여부 미확인) ===")
fc = make_fake_capture(known_base=100, last_dynamic=300)
ev = core.OathEnergyEvent(entity_id=51591, new_total=440, delta=40, raw_packet=b"", arrived_at=5.0)
fc._on_oath_energy(ev)
check("known_base는 100 그대로(증가 이벤트는 기본을 절대 안 건드림)", fc.known_base == 100, f"실제: {fc.known_base}")
check("last_dynamic이 340으로 갱신됨(440-100)", fc.last_dynamic == 340, f"실제: {fc.last_dynamic}")
check("최종 표시 total은 패킷값 그대로 440", ev.new_total == 440, f"실제: {ev.new_total}")

print("\n=== 8. 예전 확정 캡처(11.pcapng)의 검증 결과가 안 깨지는지 - base=0 가정 재현 ===")
print("     (11.pcapng는 증가 이벤트라 delta가 패킷에 직접 옴, base 개념이 생기기 전 재현)")
fc = make_fake_capture(known_base=0, last_dynamic=None)
ev = core.OathEnergyEvent(entity_id=51591, new_total=1625, delta=40, raw_packet=b"", arrived_at=8.1)
fc._on_oath_energy(ev)
check("총량 1625, delta +40 그대로 재현됨(기존 검증 안 깨짐)",
      ev.new_total == 1625 and ev.delta == 40, f"실제: total={ev.new_total} delta={ev.delta}")

print(f"\n총 {len(PASS)}개 통과, {len(FAIL)}개 실패")
if FAIL:
    print("실패 목록:", FAIL)
    sys.exit(1)
else:
    print("전부 통과.")
