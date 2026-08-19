# -*- coding: utf-8 -*-
"""
AION2 오드에너지 실시간 모니터

화면에 현재 오드에너지 값만 크게 보여주는 CS 프로그램.
opcode (0x0C, 0x61) 패킷을 실시간으로 잡아서 파싱한다 (자세한 프로토콜 설명은 aion2_core.py 참고).

사용법 (Windows, 반드시 "관리자 권한"으로 실행):
    pip install scapy lz4
    python aion2_live_monitor.py

    # 사용 가능한 네트워크 인터페이스 목록 확인 (캡처가 전혀 안 잡힐 때 먼저 확인):
    python aion2_live_monitor.py --list-ifaces

    # 인터페이스를 못 찾으면 직접 지정:
    python aion2_live_monitor.py --iface "이더넷"

    # 서버 IP/포트가 다르면 (기본은 206.127.156.0/24 대역 전체를 감시):
    python aion2_live_monitor.py --server 206.127.156.0/24 --port 13328

    # 콘솔에 디버그 정보(수신 패킷 수 등) 출력:
    python aion2_live_monitor.py --no-gui --debug

    # 캡처 파일(.pcapng)로 코드만 검증해보고 싶을 때 (실제 네트워크 캡처 없이 재생):
    python aion2_live_monitor.py --replay 11.pcapng --no-gui

필수 조건:
    - Npcap 설치 (WinPcap API-compatible Mode 체크 권장)
    - 반드시 "관리자 권한"으로 실행해야 raw socket 캡처가 됨 (안 그러면 조용히 아무 것도 안 잡힘)
    - pip install scapy lz4

주의:
    - opcode (0x0C, 0x61) 은 "오드에너지가 바뀔 때"만 옴 (절대값 스냅샷이 아니라 변경 이벤트).
    - opcode (0x0B, 0x61) 은 캐릭터가 월드에 들어올 때(로딩 완료 시점) 1회 오는 "전체 스탯 동기화"
      패킷으로, 여기에 로그인 시점의 오드에너지 절대값이 들어있다.
    - 아무 반응이 없으면: (1) 관리자 권한으로 실행했는지, (2) --iface 로 올바른 인터페이스를
      지정했는지, (3) --debug 로 서버 패킷 자체가 잡히는지부터 확인할 것.
    - 캐릭터 닉네임(OwnNickname, opcode 0x33/0x36)의 entity_id 는 접속할 때마다 바뀌는 작은
      임시 id 라서 오드에너지 entity_id(계정 공용값)와 숫자로 매칭되지 않는다. 그래서 "같은 접속
      세션 동안 확인한 닉네임"을 오드에너지 이벤트가 올 때 그 이벤트의 entity_id 에 붙이는
      방식으로 연결한다 (LiveCapture.current_nickname / replay_pcap 의 current 딕셔너리 참고).
    - **저장소는 닉네임을 키로 쓴다 (2026-07-08 변경).** entity_id는 계정/슬롯 공용값이라 여러
      캐릭터가 같은 id를 공유한다 - entity_id를 키로 쓰면 캐릭터를 바꿀 때마다 같은 레코드가
      계속 덮어써진다(사용자 실측: "JSON 구조가 좀 이상해 하나의 data만 계속 갱신되는 것 같아").
      그래서 오드에너지/전투력 데이터는 "이번 세션에서 확인된 닉네임"(current_nickname)이 있을
      때만 저장소에 쓰고, 아직 모르면(캐릭터 접속 직후 5~6초 텀) pending_oath에 메모리로만
      들고 있다가 닉네임이 확인되는 순간 병합해서 저장한다 - 잘못된 캐릭터 이름 아래 데이터가
      쓰이는 일이 구조적으로 불가능해진다.
    - opcode (0x0C, 0x61) 은 오드에너지 말고 다른 것(맵 이벤트/카운터 등)에도 재사용된다는 게
      실제 캡처(각성전1/2.pcapng)로 확인됨 - "감소" 서브타입(delta 필드 없음)은 총량 값 하나만
      가지고 있어 자체적으로는 진짜인지 검증할 방법이 없다. 그래서 "이전에 실제로 오드에너지로
      확인된 entity_id"와 다르면 무시하도록 되어있다 (자세한 원리는 LiveCapture._is_trusted_oath_event
      참고).
"""

import argparse
import datetime
import ipaddress
import queue
import struct
import sys
import threading
import time
import types

from aion2_core import StreamProcessor, StreamAssembler, LiveTcpReassembler
from aion2_storage import CharacterStore
import aion2_uploader  # 2026-08-13 추가, 2단계 서버 업로드 - server_config.json 없으면 전부 no-op

# exe로 묶을 때(--noconsole/--windowed) 콘솔이 없으면 sys.stdout/stderr 가 None이 되어
# print() 호출이 그대로 죽는다 (AttributeError: 'NoneType' object has no attribute 'write').
# 콘솔 유무와 상관없이 항상 안전하게 동작하도록 더미 스트림으로 대체한다.
if getattr(sys, "frozen", False) and (sys.stdout is None or sys.stderr is None):
    import io
    if sys.stdout is None:
        sys.stdout = io.StringIO()
    if sys.stderr is None:
        sys.stderr = io.StringIO()

DEFAULT_SERVER_NET = "206.127.156.0/24"
DEFAULT_PORT = 13328

# 2026-07-09 추가(열두 번째 버그 수정): 로그인 스냅샷 직후 전투력이 몇 번 연속으로 요동치다가
# 마지막 값에 정착하는 짧은 버스트가 실측으로 확인됨 - 사용자가 업로드한
# "살성전투력 받아오는 패킷 점검용 (전투력 404.6K).pcapng" 리플레이 분석 결과, 스냅샷 -1.43초에
# 도착한 값(240725)은 남이었고, 스냅샷 +0.44초 이내에 도착한 마지막 값(404618)이 사용자가
# 게임 화면에서 직접 확인한 진짜 값(파일명 "404.6K")이었다. 이 유예 시간(초) 이내에 스냅샷
# 이후 도착하는 전투력은 닉네임이 아직 미확인이어도 신뢰한다 - 그 시간을 벗어나면(닉네임 확인까지
# 보통 5~6초 걸림) 열 번째 버그에서 확인된 캐릭터선택 화면 미리보기 노이즈와 구분이 안 되므로
# 기존처럼 무시한다.
# 2026-07-09 재조정: 실측된 버스트는 스냅샷 후 0.44초 이내에 끝났다. 처음엔 여유를 넉넉히
# 두고 1.0초로 잡았었는데, 사용자가 "닉네임 없는 값을 허용하면 오드가 또 망가질 수 있지
# 않냐"고 정확히 지적함 - 이 창이 넓을수록 열 번째 버그의 미리보기 노이즈(닉네임 확인까지
# 5~6초 동안 아무 때나 올 수 있음)를 잘못 받아들일 여지가 커진다. 그래서 실측값(0.44초)에
# 여유를 조금만 두고 0.6초로 좁힌다 - 관찰된 버스트는 여전히 확실히 덮으면서, 창을 최대한
# 좁게 유지해 노이즈가 섞여 들어올 시간을 줄인다.
COMBAT_POWER_SNAPSHOT_GRACE = 0.6

# 2026-07-09 추가(배포 전 마무리): 캐릭터 전환 직전(스냅샷이 뜨기 몇백 ms 전) 다음 캐릭터의
# 전투력 패킷이 아직 안 리셋된 current_nickname(이전 캐릭터) 아래로 화면에 잠깐 잘못 찍히는
# 게 실측됨 - 저장소에는 안 남지만(다음 스냅샷이 pending_oath를 통째로 비움) 콘솔/GUI에는
# 이전 캐릭터 이름으로 엉뚱한 값이 순간적으로 보인다. 배포 전 마무리 단계라 이 표시 잔상도
# 없애기로 함(사용자 확인: "지금은 거의 완성단계라 해결하고 배포하는게 맞을것 같아"). 값을
# 즉시 화면에 반영하지 않고 이 시간(초)만큼 늦춰서 내보내고, 그 사이에 캐릭터 전환이 감지되면
# (아래 _switch_epoch 참고) 아예 내보내지 않는다 - 정상적인(전환 없는) 상황에서는 사람이
# 체감하기 힘든 짧은 지연이라 실시간성에 미치는 영향은 거의 없다.
COMBAT_POWER_DISPLAY_DEBOUNCE = 0.4


def _resolve_decrease_split(known_base, last_dynamic, new_total, status_queue):
    """1값 감소 이벤트(opcode 0x0C,0x61, header1=0x08, delta 필드 없음)의 실제 총량(new_total)
    으로부터 기본/추가 분할을 역산한다.

    2026-08-08 두 번째 재정정(사용자 실측 확인): 오드에너지 소모는 기본오드를 먼저 깎고,
    기본이 0이 된 뒤에야 추가오드가 깎이는 "기본-우선-소모" 순서다. 실측: 기본40/추가600
    (총640) 상태에서 80 감소 -> 게임 화면에 찍힌 결과는 기본0/추가560 이었다(기본을
    총 560으로 그대로 유지한 게 아니라, 기본이 먼저 40 전부 소진되고 남은 40이 추가에서
    깎였다). 총량(560)만으로는 "기본 불변+추가만 -80" 해석과 "기본-우선-소모" 해석이
    산술적으로 구분이 안 됐지만(둘 다 총 560), 사용자가 게임 화면에서 직접 확인한 개별
    기본/추가 숫자(0/560)로 후자가 맞다는 게 확정됐다.

    같은 날 오전에 이 메커니즘 자체를 구현했다가 되돌린 적이 있는데([[aion2_packet_reverse_engineering]]
    "REVERTED" 섹션 참고), 그건 메커니즘이 틀려서가 아니라 구현이 틀려서였다 - 그때는
    패킷값을 무조건 "새 기본"으로 통째로 대입해버려서 감소량이 기본보다 작을 때도 완전히
    틀린 값이 들어갔고, 게다가 정기충전(+15/3h) 시뮬레이션이 known_base를 허위로 계속
    부풀려서 이 분기가 정상적인 순수-추가오드 소모까지 잘못 가로챘다. 이번엔 (a) known_base/
    last_dynamic으로 실제 감소량을 역산해서 기본부터 정확히 그만큼만 깎고 남으면 추가로
    넘기는 올바른 드레인 계산을 쓰고, (b) 정기충전 시뮬레이션이 이미 죽은코드로 격리되어
    known_base가 더 이상 허위로 부풀지 않는다는 전제 위에서 동작한다.

    반환: (new_known_base, new_dynamic).
    """
    if last_dynamic is None:
        # 이번 세션 첫 이벤트라 직전 상태(baseline)를 몰라 드레인 계산이 불가능 - 기존처럼
        # 기본은 그대로 두고 총량에서 역산(재정정 1차 수정과 동일 폴백).
        dynamic = new_total - known_base
        if dynamic < 0:
            status_queue.put(
                f"[의심] 새총량({new_total})에서 기본({known_base})을 뺐더니 "
                f"추가오드가 음수({dynamic}) - known_base가 오래됐을 수 있음"
            )
        return known_base, dynamic

    old_total = known_base + last_dynamic
    decrease_amount = old_total - new_total
    if decrease_amount < 0:
        # "감소" 서브타입인데 총량이 오히려 늘어남 - known 상태가 오래됐다는 신호. 드레인
        # 계산의 전제(old_total이 정확함)가 깨졌으므로, 패킷을 신뢰하고 기존 폴백으로 처리.
        status_queue.put(
            f"[의심] 감소 이벤트인데 총량이 오히려 증가함(구총량{old_total}->신총량{new_total}) "
            f"- known 상태가 오래됐을 수 있음"
        )
        return known_base, new_total - known_base
    if decrease_amount <= known_base:
        # 감소량이 기본만으로 전부 흡수됨 - 추가오드는 안 건드림.
        return known_base - decrease_amount, last_dynamic
    # 기본을 다 쓰고도 모자라 추가까지 넘어감 - 기본은 0, 나머지는 전부 추가오드에 반영된
    # 새 총량 그 자체(기본이 0이므로 총량=추가오드).
    return 0, new_total


def parse_network(spec):
    """'206.127.156.142' 같은 단일 IP 나 '206.127.156.0/24' 같은 대역 모두 허용."""
    if "/" not in spec:
        spec = spec + "/32"
    return ipaddress.ip_network(spec, strict=False)


def parse_eth_ipv4_tcp(raw: bytes):
    """scapy 의 자동 계층 해석(dissect)에 기대지 않고, 캡처된 raw Ethernet 프레임 바이트를
    직접 struct 로 파싱한다.

    일부 Windows/Npcap 조합에서 scapy 가 "Unable to guess datalink type" 경고를 내면서
    IP/TCP 레이어를 전혀 만들어주지 않는 버그가 있다 (라이브러리 버그, 우리 코드 문제 아님).
    그래도 raw 바이트 자체는 정상적으로 캡처되므로, 그 bytes 를 직접 해석하면 우회 가능하다.
    """
    if len(raw) < 14:
        return None
    eth_type = struct.unpack_from("!H", raw, 12)[0]
    offset = 14
    if eth_type == 0x8100:  # 802.1Q VLAN 태그
        if len(raw) < 18:
            return None
        eth_type = struct.unpack_from("!H", raw, 16)[0]
        offset = 18
    if eth_type != 0x0800:  # IPv4 아니면 무시
        return None
    if len(raw) < offset + 20:
        return None
    ver_ihl = raw[offset]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl:
        return None
    total_len = struct.unpack_from("!H", raw, offset + 2)[0]
    protocol = raw[offset + 9]
    if protocol != 6:  # TCP 아니면 무시
        return None
    src_ip = ".".join(str(b) for b in raw[offset + 12:offset + 16])
    dst_ip = ".".join(str(b) for b in raw[offset + 16:offset + 20])
    tcp_off = offset + ihl
    if len(raw) < tcp_off + 20:
        return None
    sport, dport, seq = struct.unpack_from("!HHI", raw, tcp_off)
    doff_flags = struct.unpack_from("!H", raw, tcp_off + 12)[0]
    data_offset = (doff_flags >> 12) * 4
    flags = doff_flags & 0x3F  # FIN,SYN,RST,PSH,ACK,URG
    payload_start = tcp_off + data_offset
    ip_end = offset + total_len
    payload_end = min(ip_end, len(raw))
    payload = raw[payload_start:payload_end] if payload_end > payload_start else b""
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "sport": sport, "dport": dport,
        "seq": seq, "flags": flags,
        "payload": payload,
    }


# ---------------------------------------------------------------------------
# 실시간 캡처 (scapy)
# ---------------------------------------------------------------------------

class LiveCapture:
    """scapy sniff 를 백그라운드 스레드에서 돌리면서, 서버->클라이언트 TCP 스트림을
    LiveTcpReassembler 로 흘려보낸다. 새로운 TCP 연결(SYN)이 보이면 재조립 상태를 리셋한다.
    디버깅을 위해 status_queue 로 텍스트 상태 메시지도 흘려보낸다 (매칭된 패킷 수, 에러 등).
    """

    def __init__(self, server_net, port, event_queue, status_queue, iface=None, debug=False):
        self.server_net = server_net
        self.port = port
        self.event_queue = event_queue
        self.status_queue = status_queue
        self.iface = iface
        self.debug = debug
        self.live_reassembler = None
        self.matched_packet_count = 0
        self.first_packet_seen = False
        self.last_dynamic = None  # 직전에 확인된 "오른쪽 숫자"(누적분, delta 필드 없는 패킷용)
        # 2026-08-13 추가: on_change 콜백으로 aion2_uploader.enqueue_upload를 연결한다 - 서버가
        # 설정 안 돼있으면(server_config.json 없음/server_url 빈값) enqueue_upload 자체가
        # 조용히 no-op이므로, 이 줄은 서버 기능을 안 쓰는 기존 사용자에게 아무 영향도 없다.
        # replay_pcap은 이 콜백을 넘기지 않음 - 리플레이가 실제 네트워크 부작용을 내면 안 됨
        # (정기충전을 replay에 안 붙인 것과 같은 원칙, aion2_project_roadmap 참고).
        self.store = CharacterStore(
            on_change=lambda record: aion2_uploader.enqueue_upload(record, status_queue)
        )  # 캐릭터별 오드에너지 로컬 저장소 (oath_energy_data.json, 닉네임 키)

        # 2026-07-08: 저장소가 닉네임 키로 바뀌면서, "지난 세션에 마지막으로 활동한 캐릭터"를
        # 이어받아 콜드스타트를 완화한다. entity_id/base는 패킷 신뢰 검증과 총량 계산용 참고값일
        # 뿐, 실제로 이 캐릭터가 이번 세션에도 접속했는지는 아래에서 확인되는 닉네임으로 재검증된다.
        last_nickname = self.store.most_recent_character()
        last_record = self.store.data.get(last_nickname, {}) if last_nickname else {}
        _last_id = last_record.get("entity_id")
        # 2026-07-09: 예전 버그로 이미 entity_id=0이 저장돼버린 JSON을 이어받으면, 여기서 그대로
        # known_oath_id=0으로 시작해버려서 코드를 고쳐도 다음 실행부터 계속 재발한다(0을 절대
        # 신뢰하지 않는 이유는 _is_trusted_oath_event 주석 참고). 0이면 모르는 상태(None)로 시작.
        self.known_oath_id = _last_id if _last_id != 0 else None
        self.known_base = last_record.get("oath_energy_base") or 0

        self._build_pipeline()
        self._stop = threading.Event()
        self._thread = None

    def _build_pipeline(self):
        proc = StreamProcessor(
            on_oath_energy=self._on_oath_energy,
            on_nickname=self._on_nickname,
            on_unknown=self._on_unknown if self.debug else None,
            get_known_oath_id=lambda: self.known_oath_id,
            on_combat_power=self._on_combat_power,
            on_item_level=self._on_item_level,
        )
        assembler = StreamAssembler(proc)
        self.live_reassembler = LiveTcpReassembler(assembler)
        # OwnNickname 의 entity_id 는 세션마다 바뀌는 작은 임시 id라서 오드에너지의
        # 계정 공용 id 와 숫자로 직접 매칭이 안 된다 (aion2_core.py의 parse_own_nickname_packet
        # 문서 참고). 대신 "같은 접속 세션 동안 확인한 닉네임"을 오드에너지 이벤트가 올 때
        # 그 이벤트의 entity_id 에 붙여주는 방식으로 연결한다. 새 연결(재접속)마다 리셋 -
        # 재접속은 캐릭터 전환(캐릭터 선택 화면 경유)일 수 있으므로, 예전 닉네임을 새로 들어오는
        # 오드에너지 데이터에 잘못 붙이지 않기 위해서다.
        self.current_nickname = None
        self.current_server = None
        self.current_job = None
        # 2026-07-08 추가: 닉네임이 아직 확인 안 된 entity_id의 오드에너지/전투력 데이터를 메모리에만
        # 들고 있는 임시 보관함. 닉네임이 확인되면(_on_nickname) 병합해서 저장소에 반영한다 - 저장소는
        # "닉네임이 확정된 데이터만 받는다"는 계약을 지켜서, entity_id가 계정 공용이라 생기는
        # "엉뚱한 캐릭터 이름 아래 데이터가 쓰이는" 문제를 구조적으로 막는다.
        self.pending_oath = {}
        # 2026-07-09 추가(열두 번째 버그 수정): 로그인 스냅샷 시각 + COMBAT_POWER_SNAPSHOT_GRACE
        # 까지는 닉네임 미확인이어도 전투력을 신뢰하는 유예 시각. is_snapshot 처리 때마다 갱신됨.
        self.combat_power_grace_until = None
        # 2026-07-09 추가(배포 전 마무리): 캐릭터 전환(is_snapshot)이 감지될 때마다 1씩 증가하는
        # 세대 번호. _on_combat_power가 "현재 캐릭터" 이름으로 화면 표시를 예약할 때 이 값을 같이
        # 찍어두고, 예약된 시간이 되어 실제로 내보낼 때 세대 번호가 그대로인지 확인한다 - 그 사이에
        # 전환이 감지됐으면(세대 번호가 바뀌었으면) 이미 낡은 값이므로 조용히 버린다.
        self._switch_epoch = 0

    def _on_oath_energy(self, ev):
        # 2026-07-07 추가: id 신뢰 검증. delta 필드가 있는 "증가" 타입은 total/delta 두 값이
        # 서로 교차검증되므로 그 자체로 신뢰; 그 외("감소" 타입, 또는 known_id와 다른 스냅샷)는
        # 이미 확인된 오드에너지 entity_id와 같을 때만 신뢰한다. 아직 아무 id도 모르면(콜드스타트)
        # 이번 이벤트를 일단 신뢰하고 그 id를 앞으로의 기준으로 삼는다.
        if not self._is_trusted_oath_event(ev):
            self.status_queue.put(
                f"[의심] opcode는 오드에너지와 같지만 알고 있는 캐릭터(id={self.known_oath_id})와 "
                f"달라서 무시됨: id={ev.entity_id} total={ev.new_total}"
            )
            return

        # 2026-08-08 두 번째 재정정: 아래에서 known_base/last_dynamic이 바뀌기 전의 "이전 상태"를
        # 미리 저장해둔다 - delta를 "추가오드만의 변화량"이 아니라 "총량의 변화량"으로 계산하기
        # 위함(기본-우선-소모로 기본만 깎이고 추가는 안 바뀌는 경우, 예전 방식(dynamic 차이만
        # 보는 것)으로는 실제로 소모가 있었는데도 delta=0으로 잘못 나온다).
        prev_base = self.known_base
        prev_dynamic = self.last_dynamic

        # 2026-07-07 추가: "왼쪽 숫자"(정기 충전분, base) + "오른쪽 숫자"(누적분, dynamic) 합산 버그 수정.
        # 스냅샷 이벤트는 base/dynamic 을 둘 다 직접 주므로 그대로 반영. 일반 변경 이벤트는 dynamic 만
        # 갱신하는 것으로 보이므로(아이템/던전 등은 오른쪽 숫자만 건드림), 마지막으로 알고 있던 base 를
        # 그대로 더해서 진짜 총량을 계산한다. base 를 아직 모르면(로그인 스냅샷을 못 잡은 세션) 0으로
        # 취급 - 예전 동작(오른쪽 숫자만 total로 취급)과 동일하게 자연 폴백된다.
        if getattr(ev, "is_snapshot", False):
            self.known_base = getattr(ev, "base", 0) or 0
            dynamic = getattr(ev, "dynamic", ev.new_total)
            # 2026-07-08 수정: 로그인 스냅샷 = 캐릭터가 (재)입장했다는 신호. entity_id가
            # 계정 공용이라 이 시점에 이전 캐릭터의 current_nickname이 그대로 남아있으면
            # 새 캐릭터의 데이터가 이전 캐릭터 이름 아래에 잘못 저장된다. 닉네임이 다시
            # 확인될 때까지 pending_oath로 돌리기 위해 여기서 리셋한다.
            self.current_nickname = None
            self.current_server = None
            self.current_job = None
            # GUI 표는 entity_id -> 마지막 확인 닉네임(entity_nickname)을 별도로 캐싱해서
            # 닉네임 없는 이벤트를 라우팅한다. 이 캐시는 core의 current_nickname과 독립적이라
            # 여기서 리셋만 해선 안 지워지고, 그러면 표에서 "이전 캐릭터 행"이 새 캐릭터
            # 데이터로 잘못 덮어써진다(저장소는 정상이어도 화면만 오염됨). forget_entity_id
            # 이벤트로 GUI 쪽 캐시도 함께 무효화한다.
            self.event_queue.put(types.SimpleNamespace(forget_entity_id=ev.entity_id))
            # 2026-07-09 추가(배포 전 마무리): 전환이 감지된 순간 세대 번호를 올려서, 이 시점
            # 이전에 "이전 캐릭터" 이름으로 예약돼있던 전투력 화면 표시를 전부 무효화한다.
            self._switch_epoch += 1
            # 2026-07-08 수정(열한 번째 버그, 실측): entity_id가 계정 공용이라
            # pending_oath[entity_id]는 여러 캐릭터에 걸쳐 재사용되는 딕셔너리다. 위에서
            # current_nickname은 리셋했지만 pending_oath 자체는 지운 적이 없어서, 직전
            # 캐릭터가 활동 중일 때 미처 플러시되지 못한 채 남아있던 combat_power(예:
            # 이전 캐릭터의 전투력, 또는 아직 신뢰 못 하는 캐릭터선택 미리보기 잔재)가
            # 그대로 살아남아 이번에 새로 로그인한 캐릭터의 레코드에 섞여 들어갔다(실측:
            # 활성성 접속 시 무관한 전투력 472736이 붙어서 나옴, 사용자 지적 "전투력은
            # 다른사람의 전투력을 착각한거 같다"). 로그인 스냅샷은 "이 entity_id에 대해
            # 완전히 새로운 캐릭터 세션이 시작됐다"는 확실한 신호이므로, 이 시점에 이전
            # 세션의 잔재를 통째로 비운다 - 그래야 이후 pending에 쌓이는 값은 전부 이번
            # 캐릭터 것이라고 보장할 수 있다.
            self.pending_oath.pop(ev.entity_id, None)
            # 2026-07-09 추가(열두 번째 버그, 실측 - 사용자 확정 "실측에 맞게 가자"): 스냅샷
            # 시각 기준 COMBAT_POWER_SNAPSHOT_GRACE 초 이내는 닉네임 미확인이어도 전투력을
            # 신뢰하는 유예 구간으로 연다 - _on_combat_power 참고.
            self.combat_power_grace_until = (ev.arrived_at if ev.arrived_at is not None else time.time()) + COMBAT_POWER_SNAPSHOT_GRACE
        else:
            if getattr(ev, "base", None) is not None:
                # 2026-07-09 추가(열세 번째 버그 수정): opcode(0x0C,0x61)의 "증가" 타입에
                # 값 2개짜리 변형(header1=0x0c)이 있다는 게 실측으로 확인됨 - "추가오드" 아이템
                # 사용 캡처(쌍검성, 4회 연속)에서 매번 왼쪽 숫자(v1=360, 변화 없음)와 오른쪽
                # 숫자(v2, 델타 40씩 증가)를 같이 실어보냄. 예전엔 헤더가 `01 08 01`이 아니라는
                # 이유만으로 이 opcode 전체가 무시돼서(사용자 실측: 아이템 먹어도 콘솔에 아무
                # 로그도 안 남음) 이 아이템으로 얻는 오드에너지 증가가 통째로 안 잡히는 버그였다.
                # 이 변형은 스냅샷처럼 왼쪽 숫자도 같이 알려주므로 known_base를 갱신한다.
                # 주의: ev.new_total은 aion2_core.py 파서에서 이미 v1+v2로 계산돼 있으므로,
                # 여기서 그대로 dynamic으로 쓰면 안 된다(base가 중복 계산됨) - ev.dynamic(오른쪽
                # 숫자만)을 따로 꺼내 쓴다.
                self.known_base = ev.base
                dynamic = ev.dynamic
            else:
                # 2026-08-08 재정정: 1값 형식(header1=0x08)의 값은 "새 추가오드"가 아니라
                # "새 총량"이다(기본40/추가600에서 80감소 시 패킷값 560=640-80 실측 확인).
                # 자세한 경위는 [[aion2_packet_reverse_engineering]] 참고.
                if ev.delta is None:
                    # 감소: 기본-우선-소모 메커니즘 반영 (같은 날 두 번째 재정정, 실측
                    # 기본0/추가560 확인) - _resolve_decrease_split 문서 참고.
                    self.known_base, dynamic = _resolve_decrease_split(
                        self.known_base, self.last_dynamic, ev.new_total, self.status_queue,
                    )
                else:
                    # 증가: 기본을 우선 채우는지는 아직 실측 확인 안 됨 - 기본은 그대로 두고
                    # 총량에서 역산하는 기존 방식 유지.
                    dynamic = ev.new_total - self.known_base
                    if dynamic < 0:
                        self.status_queue.put(
                            f"[의심] 새총량({ev.new_total})에서 기본({self.known_base})을 뺐더니 "
                            f"추가오드가 음수({dynamic}) - known_base가 오래됐을 수 있음"
                        )

        if ev.delta is None and prev_dynamic is not None:
            # 총량 기준 변화량(2026-08-08 두 번째 재정정) - 기본만 깎이고 추가는 안 바뀐
            # 경우에도 실제 소모량이 delta에 정확히 반영된다.
            ev.delta = (self.known_base + dynamic) - (prev_base + prev_dynamic)
        self.last_dynamic = dynamic
        ev.new_total = self.known_base + dynamic

        if getattr(ev, "is_snapshot", False):
            self.status_queue.put(
                f"캐릭터 진입 - 오드에너지 초기값 확인: {ev.new_total} "
                f"(정기충전 {self.known_base} + 누적 {dynamic})"
            )

        self.known_oath_id = ev.entity_id

        # 2026-07-08 재구성: 저장소는 닉네임 키다. 이번 세션에서 이 entity_id의 닉네임이 이미
        # 확인됐으면(self.current_nickname) 바로 저장하고, 아직이면 pending_oath에만 담아둔다
        # (저장소엔 안 씀 - 닉네임 확인 전에 저장하면 "이전 캐릭터 이름" 아래 새 데이터가 쓰이는
        # 예전 버그가 재발한다).
        if self.current_nickname:
            self.store.update_character_info(
                self.current_nickname, entity_id=ev.entity_id,
                server=self.current_server, job=self.current_job,
            )
            self.store.update_oath_energy(
                self.current_nickname, ev.new_total, ev.delta,
                base=self.known_base, dynamic=dynamic, entity_id=ev.entity_id,
            )
            # 2026-07-08 수정(중요 버그, 실측): 전투력 패킷은 자체 entity_id가 없어서
            # "새 캐릭터 것인지" 독자적으로 판단 못 하고 _on_combat_power가 pending_oath에만
            # 담아둔다 (아래 참고). 캐릭터 전환 직후 전투력 패킷이 이 오드에너지 이벤트보다
            # 먼저 도착하는 경우가 실측으로 확인됐는데(예: 창법성→유틸성 전환 시 유틸성의
            # 전투력이 창법성 이름으로 잘못 저장됨), 여기서 "이 오드에너지가 확실히
            # current_nickname 것"이라고 확정된 시점에 밀려있던 전투력도 같이 반영해준다.
            pending_cp = self.pending_oath.get(ev.entity_id)
            if pending_cp and pending_cp.get("combat_power") is not None:
                self.store.update_combat_power(
                    self.current_nickname, pending_cp["combat_power"], entity_id=ev.entity_id,
                )
                pending_cp.pop("combat_power", None)
                pending_cp.pop("combat_power_updated", None)
            # 2026-07-19 추가: 템레벨(item_level)도 combat_power와 완전히 같은 이유로
            # pending_oath에 보류됐다가 여기서(오드에너지 이벤트가 이 캐릭터인 걸 확정하는
            # 시점) 같이 반영된다 - 같은 pending_cp 딕셔너리를 그대로 재사용.
            if pending_cp and pending_cp.get("item_level") is not None:
                self.store.update_item_level(
                    self.current_nickname, pending_cp["item_level"], entity_id=ev.entity_id,
                )
                pending_cp.pop("item_level", None)
                pending_cp.pop("item_level_updated", None)
            ev.display_name = self.current_nickname
            ev.record = dict(self.store.data.get(self.current_nickname, {}))
        else:
            pending = self.pending_oath.setdefault(ev.entity_id, {})
            pending.update({
                "oath_energy": ev.new_total,
                "oath_energy_base": self.known_base,
                "oath_energy_dynamic": dynamic,
                "last_delta": ev.delta,
                "last_updated": datetime.datetime.now().isoformat(timespec="seconds"),
            })
            ev.display_name = f"캐릭터(id={ev.entity_id})"
            ev.record = {"entity_id": ev.entity_id, "nickname": None, **pending}

        # 이 이벤트 자체는 닉네임을 새로 확인해준 이벤트가 아니다 (GUI의 upsert_status_row 참고).
        ev.nickname_confirmed = False
        self.event_queue.put(ev)

    def _is_trusted_oath_event(self, ev):
        # 2026-07-08 수정(중요 버그): 예전엔 delta 필드가 있는 "증가" 타입이면 entity_id를
        # 아예 확인 안 하고 무조건 신뢰했다 ("total/delta 두 값이 자체 교차검증된다"는 이유였는데,
        # 실제로는 그 교차검증을 코드가 수행하지 않고 그냥 통과시키기만 했다). opcode(0x0C,0x61)가
        # 오드에너지 말고 다른 카운터(각성전 티켓 등)에도 재사용되는 걸 이미 알고 있었는데, 그런
        # 패킷이 우연히 "증가" 타입 구조(delta 필드 있음)로 오면 entity_id가 완전히 다른데도
        # known_oath_id를 그 엉뚱한 id로 덮어써버렸다 - 실측으로 확인됨(id=74292가 known으로
        # 등록되어 그 뒤 진짜 51591 이벤트가 전부 "[의심]"으로 무시됨, 오드정보가 None으로
        # 빠지는 버그의 근본 원인). 51591은 여러 캐릭터/세션에 걸쳐 항상 동일한 계정 고정값으로
        # 실측 확인됐으므로, 한 번 기준 id가 정해지면 델타 유무와 상관없이 반드시 그 id와
        # 일치해야만 신뢰한다 - 콜드스타트(아직 기준 id 없음)일 때만 예외.
        # 2026-07-09 수정(실측: 친구 PC, 신규/빈 oath_energy_data.json 상태): 콜드스타트 상태에서
        # 무조건 첫 이벤트를 신뢰하면, 그 "첫 이벤트"가 우연히 opcode(0x0C,0x61) 재사용 카운터
        # (74292 사례와 동급)일 경우 entity_id=0 같은 말이 안 되는 값이 영구 기준으로 등록돼버린다.
        # 실측: 캐릭터 "불비"가 entity_id=0/오드 전부 0으로 저장되고, 그 뒤에 온 진짜 51591 이벤트가
        # 전부 "[의심]"으로 계속 무시됨. entity_id=0은 지금까지의 모든 실측 계정에서 단 한 번도
        # 정상값으로 관측된 적이 없으므로(실제 계정 고정값은 항상 0이 아닌 값, 예: 51591) 콜드스타트
        # 여도 0은 신뢰하지 않는다 - known_oath_id가 여전히 None으로 남으므로 다음 이벤트에서 다시
        # 판단하게 된다.
        if self.known_oath_id is None:
            return ev.entity_id != 0  # 콜드스타트: 0만 제외하고 첫 이벤트를 기준으로 삼음
        return ev.entity_id == self.known_oath_id

    def _on_nickname(self, ev):
        self.current_nickname = ev.nickname
        self.current_server = ev.server
        self.current_job = ev.job
        self.status_queue.put(f"캐릭터 닉네임 확인: {ev.nickname}")

        # 닉네임(OwnNickname)은 실측상 오드에너지 로그인 스냅샷보다 5~6초 "늦게" 온다. 이미
        # 추적 중인 오드에너지 entity_id를 알고 있으면(known_oath_id), pending_oath에 쌓아둔
        # 데이터를 이 닉네임으로 즉시 병합/반영하고 GUI에도 바로 알린다 - 다음 오드에너지
        # 이벤트를 기다리지 않는다.
        if self.known_oath_id is not None:
            self.store.update_character_info(
                ev.nickname, entity_id=self.known_oath_id, server=ev.server, job=ev.job,
            )
            pending = self.pending_oath.pop(self.known_oath_id, None)
            if pending:
                # 2026-07-08 수정(중요 버그): pending에 combat_power만 있고 오드에너지 데이터가
                # 없는 경우(예: 닉네임 재확인 대기 중 전투력 이벤트만 옴)에도 예전엔 무조건
                # update_oath_energy를 호출했다 - new_total=None이 그대로 넘어가서 저장소의
                # oath_energy를 None으로 덮어썼다 (실측: 표에 "None"으로 표시됨). pending에
                # 오드에너지 데이터가 실제로 있을 때만 호출하도록 수정.
                if pending.get("oath_energy") is not None:
                    self.store.update_oath_energy(
                        ev.nickname, pending.get("oath_energy"), pending.get("last_delta"),
                        base=pending.get("oath_energy_base"), dynamic=pending.get("oath_energy_dynamic"),
                        entity_id=self.known_oath_id,
                    )
                if pending.get("combat_power") is not None:
                    self.store.update_combat_power(
                        ev.nickname, pending["combat_power"], entity_id=self.known_oath_id,
                    )
                # 2026-07-19 추가: 템레벨도 닉네임 확인 시점에 같이 플러시 (combat_power와 동일 이유).
                if pending.get("item_level") is not None:
                    self.store.update_item_level(
                        ev.nickname, pending["item_level"], entity_id=self.known_oath_id,
                    )
            record_snapshot = dict(self.store.data.get(ev.nickname, {}))
            self.event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=True))

    def _on_combat_power(self, ev):
        # 2026-07-08: opcode(0x56,0x36)엔 entity_id 필드가 없어서(닉네임과 동일한 상황), 지금
        # 추적 중인 오드에너지 entity_id(known_oath_id)에 그대로 붙인다. 확정된 설계: 캐릭터
        # 인식(known_oath_id)이 아예 안 된 상태면 전투력도 무시한다 ("캐릭터 인식이 되어있어야
        # 전투력이 인식되는것이 좋아" - 사용자 확인).
        #
        # 2026-07-08 수정(중요 버그, 실측): 예전엔 current_nickname이 설정돼 있으면 바로
        # 저장소에 썼다 - 그런데 전투력 패킷은 자체 entity_id가 없어서 "이게 새로 전환한
        # 캐릭터 것인지" 독자적으로 판단할 방법이 전혀 없다. 캐릭터를 전환하면 새 캐릭터의
        # 전투력 패킷이 오드에너지 스냅샷(전환 감지 신호, current_nickname 리셋의 유일한
        # 계기)보다 먼저 도착하는 경우가 실측으로 확인됐다(예: 창법성 활동 중 → 유틸성 접속
        # → 유틸성의 첫 전투력 패킷이 아직 안 리셋된 current_nickname="창법성"에 붙어서
        # 창법성 기록이 유틸성 전투력으로 잘못 바뀜). 그래서 이제 전투력은 절대 즉시 쓰지
        # 않고 항상 pending_oath에만 담아둔다 - 실제 저장은 (a) 오드에너지 이벤트가 "이건
        # 확실히 current_nickname 것"이라고 확정해줄 때(_on_oath_energy 참고) 또는 (b) 닉네임이
        # 막 확인될 때(_on_nickname) 두 시점에서만 이뤄진다. 둘 다 이미 신뢰 검증을 거친
        # 시점이라 안전하다.
        if self.known_oath_id is None:
            return
        # 2026-07-08 수정(열 번째 버그, 실측): 닉네임이 아직 확인 안 된 상태(current_nickname
        # is None)에서 들어오는 전투력 패킷은 신뢰할 수 없다는 게 콘솔 로그로 확인됨 - 같은
        # 1초 안에 서로 다른 전투력 값이 3번 연속으로 들어옴(472736 → 664074 → 773369).
        # 실제 플레이 중인 캐릭터라면 전투력이 그렇게 짧은 시간에 여러 번 바뀔 이유가 없고,
        # 캐릭터 선택 화면에서 목록의 여러 캐릭터를 훑으며 각각의 전투력을 미리 흘려보내는
        # 패킷으로 추정된다(사용자 지적: "여기에 전투력 날라오는게 문제인거같다 이때 전투력은
        # 갱신하지 않도록 해야할것 같다"). 그래서 닉네임이 확인되기 전에는 원칙적으로 무시한다.
        #
        # 2026-07-09 수정(열두 번째 버그, 실측 - "실측에 맞게 가자" 사용자 확정): 위 규칙을
        # 그대로 적용하면 로그인 스냅샷 직후 도착하는 진짜 값도 같이 버려진다는 게 실측으로
        # 드러났다 - 사용자가 올린 "전투력 404.6K" 캡처에서 스냅샷 -1.43초에 온 값(240725)은
        # 남의 것이었지만, 스냅샷 +0.44초에 온 마지막 값(404618)은 게임 화면에서 직접 확인한
        # 진짜 값이었다. 그래서 스냅샷 시각 기준 COMBAT_POWER_SNAPSHOT_GRACE 초 이내는
        # 예외적으로 신뢰한다(닉네임 미확인이어도) - 그 구간을 벗어나면(닉네임 확인까지 보통
        # 5~6초 걸리므로 이 유예 시간보다 훨씬 길다) 열 번째 버그의 미리보기 노이즈와 구분이
        # 안 되므로 기존처럼 무시한다.
        if self.current_nickname is None:
            now = ev.arrived_at if ev.arrived_at is not None else time.time()
            if self.combat_power_grace_until is None or now > self.combat_power_grace_until:
                return
            # 2026-07-09 추가: 이 예외 경로를 탄 값은 콘솔에 표시로 남겨서, 나중에 문제가 생기면
            # "유예구간 예외로 들어온 값이었다"는 걸 바로 구분할 수 있게 한다 (사용자 지적:
            # "닉네임없는 값을 허용하면 오드가 또 망가질수 있을것 같은데" - 오드에너지 자체는
            # 이 코드와 별개의 entity_id 신뢰검증(_is_trusted_oath_event)으로 보호되어 이 변경의
            # 영향을 받지 않지만, 전투력 값 자체의 신뢰도를 추적할 수 있도록 가시성을 남겨둔다).
            self.status_queue.put(
                f"[유예구간] 닉네임 미확인 상태지만 스냅샷 직후라 전투력 신뢰: {ev.combat_power}"
            )
        pending = self.pending_oath.setdefault(self.known_oath_id, {})
        pending["combat_power"] = ev.combat_power
        pending["combat_power_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        # 2026-07-09 수정: grace 구간에서는 current_nickname이 아직 None일 수 있으므로(위 가드
        # 통과), None일 때는 (열 번째 버그 이전과 동일하게) nickname=None인 임시 레코드를 만든다.
        if self.current_nickname:
            # 2026-07-09 추가(배포 전 마무리, 실측): current_nickname이 설정돼 있어도, 다음
            # 캐릭터로 전환되기 직전(스냅샷이 뜨기 몇백 ms 전)에 다음 캐릭터의 전투력 패킷이
            # 먼저 도착하면 아직 안 리셋된 이전 캐릭터 이름 아래로 화면에 잘못 찍히는 게
            # 실측됨(쌍검성 아래 472736, 활성성 아래 185157 - 둘 다 저장은 안 됐지만 콘솔에
            # 잔상으로 남음). 저장(store.update_combat_power)은 애초에 여기서 안 하므로
            # (열 번째 버그 이전부터 pending_oath 경유로만 저장됨) 안전하지만, 화면 표시만은
            # 즉시 내보내지 않고 COMBAT_POWER_DISPLAY_DEBOUNCE 초 뒤로 미룬다 - 그 사이에
            # 전환이 감지되면(_switch_epoch 증가) 낡은 값으로 판단해 조용히 버린다. 정상적인
            # 상황(전환 없이 그냥 장비 교체 등)에서는 사람이 체감 못 할 짧은 지연일 뿐이다.
            nickname_at_send = self.current_nickname
            epoch_at_send = self._switch_epoch
            cp_value = ev.combat_power
            cp_updated = pending["combat_power_updated"]

            def _emit_if_still_valid():
                if self._switch_epoch != epoch_at_send:
                    return  # 그 사이에 캐릭터 전환이 감지됨 - 이미 낡은 값, 화면에 안 보여줌
                record_snapshot = {**dict(self.store.data.get(nickname_at_send, {})),
                                   "combat_power": cp_value,
                                   "combat_power_updated": cp_updated}
                self.event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

            threading.Timer(COMBAT_POWER_DISPLAY_DEBOUNCE, _emit_if_still_valid).start()
        else:
            record_snapshot = {"entity_id": self.known_oath_id, "nickname": None, **pending}
            self.event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

    def _on_item_level(self, ev):
        """템레벨(opcode 0x1D,0x56) 갱신 - _on_combat_power와 완전히 같은 이유로 같은 구조를
        그대로 따른다: entity_id가 없는 패킷이라 "본인" 것으로 간주하고 known_oath_id에 붙이며,
        캐릭터 전환 시 오염을 막기 위해 (a) 닉네임 미확인 상태에선 로그인 스냅샷 직후
        COMBAT_POWER_SNAPSHOT_GRACE(같은 유예 구간을 재사용 - 템레벨도 로그인 시점에 같이 오는
        정보라 같은 타이밍 특성을 가짐) 이내만 신뢰하고, (b) 실제 저장은 절대 즉시 하지 않고
        pending_oath에 담아뒀다가 오드에너지 이벤트/닉네임 확인 시점에만 반영한다
        (_on_oath_energy/_on_nickname의 item_level 플러시 참고).

        2026-07-19 발견 - 실측 캡처 1건("활성성 템레벨 5529 테스트.pcapng")으로만 확인됨,
        combat_power 만큼 여러 번 교차검증되지 않았으므로 화면 표시 디바운스(전환 직전 잔상
        방지)는 아직 적용 안 함 - 필요하면(실제로 전환 시 잔상이 관측되면) combat_power와
        동일하게 COMBAT_POWER_DISPLAY_DEBOUNCE를 적용할 것.
        """
        if self.known_oath_id is None:
            return
        if self.current_nickname is None:
            now = ev.arrived_at if ev.arrived_at is not None else time.time()
            if self.combat_power_grace_until is None or now > self.combat_power_grace_until:
                return
            self.status_queue.put(
                f"[유예구간] 닉네임 미확인 상태지만 스냅샷 직후라 템레벨 신뢰: {ev.item_level}"
            )
        pending = self.pending_oath.setdefault(self.known_oath_id, {})
        pending["item_level"] = ev.item_level
        pending["item_level_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        if self.current_nickname:
            record_snapshot = {**dict(self.store.data.get(self.current_nickname, {})),
                               "item_level": ev.item_level,
                               "item_level_updated": pending["item_level_updated"]}
            self.event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))
        else:
            record_snapshot = {"entity_id": self.known_oath_id, "nickname": None, **pending}
            self.event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

    def _on_unknown(self, opcode, packet, arrived_at):
        self.status_queue.put(f"[debug] 알 수 없는 opcode {opcode} 프레임 수신 (len={len(packet)})")

    def _packet_callback(self, pkt):
        # scapy 의 계층 자동 해석에 의존하지 않고 raw 바이트를 직접 파싱한다.
        # (일부 환경에서 scapy 가 datalink 타입을 못 알아내 IP/TCP 레이어를 아예
        #  만들어주지 않는 버그가 있어서, bytes(pkt) 만 신뢰하고 나머지는 직접 처리)
        try:
            raw = bytes(pkt)
        except Exception:
            return
        parsed = parse_eth_ipv4_tcp(raw)
        if parsed is None:
            return

        try:
            src_addr = ipaddress.ip_address(parsed["src_ip"])
            dst_addr = ipaddress.ip_address(parsed["dst_ip"])
        except ValueError:
            return

        sport = parsed["sport"]
        dport = parsed["dport"]
        flags = parsed["flags"]
        seq = parsed["seq"]
        payload = parsed["payload"]

        # 새 연결이 시작되면(클라이언트->서버 SYN) 재조립 상태 리셋
        if dst_addr in self.server_net and dport == self.port and (flags & 0x02):
            self._build_pipeline()
            self.status_queue.put("새 연결 감지 (SYN) - 스트림 재조립 초기화")
            return

        if not (src_addr in self.server_net and sport == self.port):
            return

        self.matched_packet_count += 1
        if not self.first_packet_seen:
            self.first_packet_seen = True
            self.status_queue.put(f"서버({parsed['src_ip']}:{sport}) 패킷 수신 시작 - 캡처 정상 동작 중")

        if self.debug and self.matched_packet_count % 50 == 0:
            self.status_queue.put(f"[debug] 지금까지 서버 패킷 {self.matched_packet_count}개 수신")

        if not payload:
            return
        self.live_reassembler.feed(seq, payload, time.time())

    def start(self):
        from scapy.sendrecv import sniff

        bpf = f"tcp and net {self.server_net} and port {self.port}"

        def run():
            try:
                sniff(
                    filter=bpf,
                    prn=self._packet_callback,
                    store=False,
                    iface=self.iface,
                    stop_filter=lambda p: self._stop.is_set(),
                )
            except Exception as e:
                self.status_queue.put(
                    f"[에러] 캡처 스레드 종료됨: {e!r}  "
                    f"(관리자 권한/Npcap/인터페이스 문제일 가능성이 높음)"
                )

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

        # 몇 초 지나도 매칭 패킷이 하나도 없으면 안내 메시지
        def watchdog():
            time.sleep(6)
            if not self.first_packet_seen:
                self.status_queue.put(
                    f"[안내] 6초간 {self.server_net}:{self.port} 트래픽이 전혀 안 잡힘. "
                    f"관리자 권한 실행 여부 / --iface 지정 / 서버 IP 대역 확인 필요."
                )

        threading.Thread(target=watchdog, daemon=True).start()

    def stop(self):
        self._stop.set()


def _npcap_installed():
    """레지스트리에서 Npcap 드라이버 설치 여부를 확인한다 (Windows 전용).
    2026-07-08 추가: 개발자가 아닌 사람에게 exe만 공유했을 때, Npcap이 없으면 캡처가
    조용히 아무것도 안 잡히는 것보다는 미리 명확하게 안내하는 게 낫다. 무료 Npcap은
    라이선스상 재배포(설치파일을 우리 exe/설치 프로그램에 끼워넣는 것)가 금지되어 있어서
    (5대까지만 무료, Nmap/Wireshark/Defender for Identity와 함께 쓰는 경우만 예외) - 자동
    설치는 못 시키고, "감지 후 안내"까지만 한다.
    """
    if sys.platform != "win32":
        return True  # Windows가 아니면 이 검사 자체가 의미 없음 (개발 중 다른 OS 테스트 대비)
    import winreg
    for hive_path in (r"SOFTWARE\WOW6432Node\Npcap", r"SOFTWARE\Npcap"):
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive_path)
            return True
        except OSError:
            continue
    return False


def _warn_npcap_missing_gui():
    import tkinter as tk
    from tkinter import messagebox
    import webbrowser
    tmp_root = tk.Tk()
    tmp_root.withdraw()
    open_page = messagebox.askyesno(
        "Npcap 설치 필요",
        "패킷 캡처에 필요한 Npcap 드라이버가 설치되어 있지 않은 것 같습니다.\n"
        "설치 없이는 오드에너지 데이터를 잡을 수 없습니다.\n\n"
        "지금 Npcap 다운로드 페이지를 열까요?\n"
        "(설치 시 'WinPcap API-compatible Mode' 체크 권장, 설치 후 이 프로그램 재실행)",
    )
    if open_page:
        webbrowser.open("https://npcap.com/#download")
    tmp_root.destroy()


def list_interfaces():
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            print(f"- name={iface.get('name')!r}  desc={iface.get('description')!r}  "
                  f"guid={iface.get('guid')!r}")
    except Exception:
        from scapy.all import get_if_list
        for name in get_if_list():
            print(f"- {name}")


# ---------------------------------------------------------------------------
# 리플레이 모드 (실제 네트워크 없이 저장된 .pcapng 로 코드 검증)
# ---------------------------------------------------------------------------

def replay_pcap(path, server_net, port, event_queue, status_queue, speed=0.0):
    from scapy.utils import rdpcap
    from scapy.layers.inet import TCP, IP

    pkts = rdpcap(path)
    if not pkts:
        status_queue.put("빈 캡처 파일입니다.")
        return
    t0 = float(pkts[0].time)

    last_dynamic_holder = {"v": None}
    store = CharacterStore()
    # OwnNickname 의 entity_id 는 세션마다 바뀌는 작은 임시 id라서 오드에너지의 계정 공용 id 와
    # 직접 매칭이 안 된다 (aion2_core.py 문서 참고). 리플레이 중 확인한 닉네임을 "현재
    # 세션의 닉네임"으로 들고 있다가, 오드에너지 이벤트가 올 때 그 이벤트의 entity_id 에 붙인다.
    current = {"nickname": None, "server": None, "job": None}
    # 2026-07-08: 저장소가 닉네임 키라서, 마지막으로 활동한 캐릭터를 이어받아 콜드스타트를 완화한다
    # (LiveCapture.__init__ 과 동일한 로직).
    last_nickname = store.most_recent_character()
    last_record = store.data.get(last_nickname, {}) if last_nickname else {}
    known = {"id": last_record.get("entity_id")}
    known["base"] = last_record.get("oath_energy_base") or 0
    # 2026-07-09: 로그인 스냅샷 직후 유예 구간 마감 시각 (LiveCapture.combat_power_grace_until와 동일).
    known["cp_grace_until"] = None
    # 2026-07-09: 전환 세대 번호 (LiveCapture._switch_epoch와 동일).
    known["switch_epoch"] = 0
    # 2026-07-08: 닉네임 확인 전 오드에너지/전투력 데이터 임시 보관함 (LiveCapture.pending_oath와 동일).
    pending_oath = {}

    def is_trusted(ev):
        # LiveCapture._is_trusted_oath_event 와 동일한 이유로 수정 (2026-07-08) - delta 유무로
        # entity_id 검증을 건너뛰면 안 됨. (2026-07-09) 콜드스타트여도 entity_id=0은 신뢰 안 함 -
        # 이유는 LiveCapture._is_trusted_oath_event의 주석 참고 (친구 PC 실측: id=0이 잘못 기준으로
        # 등록되어 진짜 51591 이벤트가 전부 무시됨).
        if known["id"] is None:
            return ev.entity_id != 0
        return ev.entity_id == known["id"]

    def on_oath(ev):
        if not is_trusted(ev):
            status_queue.put(
                f"[의심] opcode는 오드에너지와 같지만 알고 있는 캐릭터(id={known['id']})와 "
                f"달라서 무시됨: id={ev.entity_id} total={ev.new_total}"
            )
            return

        # LiveCapture._on_oath_energy 와 동일한 이유로 이전 상태 저장 (2026-08-08 두 번째 재정정) -
        # delta를 "총량의 변화량"으로 계산하기 위함.
        prev_base = known["base"]
        prev_dynamic = last_dynamic_holder["v"]

        if getattr(ev, "is_snapshot", False):
            known["base"] = getattr(ev, "base", 0) or 0
            dynamic = getattr(ev, "dynamic", ev.new_total)
            # LiveCapture._on_oath_energy 와 동일한 이유로 리셋 (2026-07-08).
            current["nickname"] = None
            current["server"] = None
            current["job"] = None
            # GUI의 entity_nickname 캐시도 함께 무효화 (동일 이유, LiveCapture 쪽 주석 참고).
            event_queue.put(types.SimpleNamespace(forget_entity_id=ev.entity_id))
            # LiveCapture._on_oath_energy 와 동일한 이유로 수정 (열한 번째 버그, 2026-07-08):
            # pending_oath[entity_id]는 계정 공용이라 캐릭터 전환 후에도 이전 캐릭터의
            # 미처 플러시되지 못한 combat_power가 남아있을 수 있다 - 로그인 스냅샷 시점에
            # 통째로 비워서 이후 pending에 쌓이는 값은 전부 이번 캐릭터 것으로 보장한다.
            pending_oath.pop(ev.entity_id, None)
            # LiveCapture._on_oath_energy 와 동일한 이유로 수정 (열두 번째 버그, 2026-07-09):
            # 스냅샷 시각 기준 COMBAT_POWER_SNAPSHOT_GRACE 초 이내는 닉네임 미확인이어도
            # 전투력을 신뢰하는 유예 구간으로 연다.
            known["cp_grace_until"] = (ev.arrived_at if ev.arrived_at is not None else 0) + COMBAT_POWER_SNAPSHOT_GRACE
            # LiveCapture._on_oath_energy 와 동일한 이유로 수정 (배포 전 마무리, 2026-07-09).
            known["switch_epoch"] += 1
        else:
            if getattr(ev, "base", None) is not None:
                # LiveCapture._on_oath_energy 와 동일한 이유로 수정 (열세 번째 버그, 2026-07-09).
                known["base"] = ev.base
                dynamic = ev.dynamic
            else:
                # LiveCapture._on_oath_energy 와 완전히 동일한 이유로 수정 (2026-08-08 재정정,
                # 및 같은 날 두 번째 재정정: 기본-우선-소모 드레인 계산) - _resolve_decrease_split
                # 문서 참고.
                if ev.delta is None:
                    known["base"], dynamic = _resolve_decrease_split(
                        known["base"], last_dynamic_holder["v"], ev.new_total, status_queue,
                    )
                else:
                    dynamic = ev.new_total - known["base"]
                    if dynamic < 0:
                        status_queue.put(
                            f"[의심] 새총량({ev.new_total})에서 기본({known['base']})을 뺐더니 "
                            f"추가오드가 음수({dynamic}) - known_base가 오래됐을 수 있음"
                        )

        if ev.delta is None and prev_dynamic is not None:
            ev.delta = (known["base"] + dynamic) - (prev_base + prev_dynamic)
        last_dynamic_holder["v"] = dynamic
        ev.new_total = known["base"] + dynamic

        if getattr(ev, "is_snapshot", False):
            status_queue.put(
                f"캐릭터 진입 - 오드에너지 초기값 확인: {ev.new_total} "
                f"(정기충전 {known['base']} + 누적 {dynamic})"
            )

        known["id"] = ev.entity_id

        if current["nickname"]:
            store.update_character_info(
                current["nickname"], entity_id=ev.entity_id,
                server=current["server"], job=current["job"],
            )
            store.update_oath_energy(
                current["nickname"], ev.new_total, ev.delta,
                base=known["base"], dynamic=dynamic, entity_id=ev.entity_id,
            )
            # 2026-07-08: 전투력 패킷은 자체 entity_id가 없어서 캐릭터 전환 중 오드에너지
            # 스냅샷보다 먼저 도착하면 이전 캐릭터에게 잘못 붙는 문제(창법성→유틸성 오염
            # 실측)가 있었다. on_combat_power가 이제 항상 pending_oath에 보류하므로,
            # 여기서 신원이 확정되는 시점에 같은 entity_id로 보류된 전투력을 같이 반영한다.
            pending_cp = pending_oath.get(ev.entity_id)
            if pending_cp and pending_cp.get("combat_power") is not None:
                store.update_combat_power(
                    current["nickname"], pending_cp["combat_power"], entity_id=ev.entity_id,
                )
                pending_cp.pop("combat_power", None)
                pending_cp.pop("combat_power_updated", None)
            # 2026-07-19 추가: 템레벨도 combat_power와 동일한 이유로 여기서 같이 반영.
            if pending_cp and pending_cp.get("item_level") is not None:
                store.update_item_level(
                    current["nickname"], pending_cp["item_level"], entity_id=ev.entity_id,
                )
                pending_cp.pop("item_level", None)
                pending_cp.pop("item_level_updated", None)
            ev.display_name = current["nickname"]
            ev.record = dict(store.data.get(current["nickname"], {}))
        else:
            pending = pending_oath.setdefault(ev.entity_id, {})
            pending.update({
                "oath_energy": ev.new_total,
                "oath_energy_base": known["base"],
                "oath_energy_dynamic": dynamic,
                "last_delta": ev.delta,
                "last_updated": datetime.datetime.now().isoformat(timespec="seconds"),
            })
            ev.display_name = f"캐릭터(id={ev.entity_id})"
            ev.record = {"entity_id": ev.entity_id, "nickname": None, **pending}

        ev.nickname_confirmed = False
        event_queue.put(ev)

    def on_nickname(ev):
        current["nickname"] = ev.nickname
        current["server"] = ev.server
        current["job"] = ev.job
        status_queue.put(f"캐릭터 닉네임 확인: {ev.nickname}")

        if known["id"] is not None:
            store.update_character_info(
                ev.nickname, entity_id=known["id"], server=ev.server, job=ev.job,
            )
            pending = pending_oath.pop(known["id"], None)
            if pending:
                # LiveCapture._on_nickname 과 동일한 이유로 수정 (2026-07-08).
                if pending.get("oath_energy") is not None:
                    store.update_oath_energy(
                        ev.nickname, pending.get("oath_energy"), pending.get("last_delta"),
                        base=pending.get("oath_energy_base"), dynamic=pending.get("oath_energy_dynamic"),
                        entity_id=known["id"],
                    )
                if pending.get("combat_power") is not None:
                    store.update_combat_power(ev.nickname, pending["combat_power"], entity_id=known["id"])
                # 2026-07-19 추가: 템레벨도 닉네임 확인 시점에 같이 플러시.
                if pending.get("item_level") is not None:
                    store.update_item_level(ev.nickname, pending["item_level"], entity_id=known["id"])
            record_snapshot = dict(store.data.get(ev.nickname, {}))
            event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=True))

    def on_combat_power(ev):
        # 2026-07-08 수정(전투력 오염 버그): 전투력 패킷엔 entity_id가 없어서, 캐릭터 전환
        # 중 current["nickname"]을 그대로 믿고 바로 저장하면 "아직 리셋 안 된 이전 캐릭터
        # 닉네임"에 새 캐릭터의 전투력이 잘못 저장될 수 있다(실측: 창법성 → 유틸성 전환 시
        # 창법성의 전투력이 이상하게 바뀜). LiveCapture._on_combat_power와 동일하게, 항상
        # pending_oath에 보류해두고 on_oath(신원 확정 시점)나 on_nickname에서만 실제로 반영한다.
        if known["id"] is None:
            return
        # 2026-07-08 수정(열 번째 버그, 실측 - LiveCapture._on_combat_power와 동일 이유):
        # 닉네임 미확인 상태(current["nickname"] is None)에서 오는 전투력은 원칙적으로 신뢰
        # 불가 - 같은 1초 안에 서로 다른 값이 연속으로 들어오는 게 실측됨(캐릭터 선택 화면에서
        # 목록을 훑을 때 각 캐릭터 전투력을 미리 흘려보내는 것으로 추정).
        #
        # 2026-07-09 수정(열두 번째 버그, 실측 - LiveCapture._on_combat_power와 동일 이유):
        # 단, 로그인 스냅샷 시각 기준 COMBAT_POWER_SNAPSHOT_GRACE 초 이내는 예외 - 그 안에
        # 도착하는 값은 실제 캐릭터의 진짜 값으로 확인됨("전투력 404.6K" 캡처).
        if current["nickname"] is None:
            now = ev.arrived_at if ev.arrived_at is not None else 0
            grace = known.get("cp_grace_until")
            if grace is None or now > grace:
                return
            # LiveCapture._on_combat_power와 동일한 이유로 콘솔에 표시 (2026-07-09).
            status_queue.put(
                f"[유예구간] 닉네임 미확인 상태지만 스냅샷 직후라 전투력 신뢰: {ev.combat_power}"
            )
        pending = pending_oath.setdefault(known["id"], {})
        pending["combat_power"] = ev.combat_power
        pending["combat_power_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        if current["nickname"]:
            # LiveCapture._on_combat_power와 동일한 이유로 화면 표시를 디바운스 (배포 전
            # 마무리, 2026-07-09) - 전환 직전 잔상 방지.
            nickname_at_send = current["nickname"]
            epoch_at_send = known["switch_epoch"]
            cp_value = ev.combat_power
            cp_updated = pending["combat_power_updated"]

            def _emit_if_still_valid():
                if known["switch_epoch"] != epoch_at_send:
                    return
                record_snapshot = {
                    **dict(store.data.get(nickname_at_send, {})),
                    "combat_power": cp_value,
                    "combat_power_updated": cp_updated,
                }
                event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

            threading.Timer(COMBAT_POWER_DISPLAY_DEBOUNCE, _emit_if_still_valid).start()
        else:
            record_snapshot = {"entity_id": known["id"], "nickname": None, **pending}
            event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

    def on_item_level(ev):
        # LiveCapture._on_item_level과 완전히 동일한 구조 (2026-07-19 추가) - 자세한 이유는
        # 그쪽 docstring 참고.
        if known["id"] is None:
            return
        if current["nickname"] is None:
            now = ev.arrived_at if ev.arrived_at is not None else 0
            grace = known.get("cp_grace_until")
            if grace is None or now > grace:
                return
            status_queue.put(
                f"[유예구간] 닉네임 미확인 상태지만 스냅샷 직후라 템레벨 신뢰: {ev.item_level}"
            )
        pending = pending_oath.setdefault(known["id"], {})
        pending["item_level"] = ev.item_level
        pending["item_level_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        if current["nickname"]:
            record_snapshot = {
                **dict(store.data.get(current["nickname"], {})),
                "item_level": ev.item_level,
                "item_level_updated": pending["item_level_updated"],
            }
            event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))
        else:
            record_snapshot = {"entity_id": known["id"], "nickname": None, **pending}
            event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

    proc = StreamProcessor(on_oath_energy=on_oath, on_nickname=on_nickname,
                            get_known_oath_id=lambda: known["id"],
                            on_combat_power=on_combat_power,
                            on_item_level=on_item_level)
    assembler = StreamAssembler(proc)
    live = LiveTcpReassembler(assembler)

    last_t = 0.0
    matched = 0
    for p in pkts:
        if IP in p and TCP in p:
            ip = p[IP]
            tcp = p[TCP]
            try:
                src_addr = ipaddress.ip_address(ip.src)
            except ValueError:
                continue
            if src_addr in server_net and tcp.sport == port:
                matched += 1
                rel_t = float(p.time) - t0
                if speed > 0:
                    wait = (rel_t - last_t) / speed
                    if wait > 0:
                        time.sleep(wait)
                    last_t = rel_t
                ip_total_len = ip.len
                ip_hdr_len = ip.ihl * 4
                tcp_hdr_len = tcp.dataofs * 4
                payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len
                raw_payload = bytes(tcp.payload)[:payload_len] if payload_len > 0 else b''
                if raw_payload:
                    live.feed(tcp.seq, raw_payload, rel_t)
    status_queue.put(f"리플레이 완료. (서버->클라이언트 매칭 패킷 {matched}개)")


# ---------------------------------------------------------------------------
# GUI (Tkinter) - 대시보드와 같은 내용(닉네임/총량/왼쪽·오른쪽/최근 이력)을 창 안에서 바로 표시
# ---------------------------------------------------------------------------

def _fmt_info_cell(value):
    """현황 표의 "기본"/"추가" 칸 공용 포맷터 (2026-07-09: 기존엔 오드 총량 하나만 보여주는
    "오드 정보" 단일 칸이었는데, 사용자 요청으로 oath_energy_base("기본")와
    oath_energy_dynamic("추가")를 별도 두 칸으로 나눠 보여주도록 변경 - 두 칸 모두 이 함수를
    그대로 재사용한다 (단순히 값이 있으면 문자열로, 없으면 "-").

    value가 None일 때(전투력 이벤트가 닉네임보다 먼저 와서 오드에너지 데이터 없이 행이 먼저
    생기는 경우 - 2026-07-08, entity_id 신뢰 버그 수정 이후 실측으로 확인됨) 예전엔 문자열
    "None"이 그대로 표에 찍혔다 - 전투력 칸의 "-"와 통일해서 아직 값 없음을 명확히 표시한다."""
    if value is None:
        return "-"
    return f"{value}"


def _fmt_date_cell(ts):
    """현황 표의 "갱신날짜" 칸: ISO8601("...T...") 을 보기 좋게 공백으로 바꾼다."""
    if not ts:
        return ""
    return ts.replace("T", " ")


def _fmt_combat_power_cell(value):
    """현황 표의 "전투력" 칸: 게임 UI와 같은 "345.6K" 형태로 표시 (2026-07-08 추가)."""
    if value is None:
        return "-"
    if value >= 1000:
        return f"{value / 1000:.1f}K"
    return str(value)


STATUS_ROW_CAP = 100  # 표에 유지할 최대 캐릭터 수 (그 이상이면 가장 오래 안 갱신된 것부터 정리)


def run_gui(event_queue, status_queue, opacity=0.88):
    import tkinter as tk
    from tkinter import ttk

    BG = "#101010"
    FG_DIM = "#888888"
    FG_LABEL = "#CCCCCC"
    ACCENT = "#7CFC00"

    root = tk.Tk()
    root.title("AION2 오드에너지")
    root.attributes("-topmost", True)
    root.geometry("460x520")
    root.minsize(360, 360)
    root.configure(bg=BG)

    # 2026-07-18 추가: 반투명 창(사용자 요청, 다른 DPS미터류 오버레이 참고 이미지 제공 -
    # 배경이 게임 화면 위에 은은하게 비치는 느낌). Tkinter의 -alpha는 창 전체(배경+글자+표)를
    # 균일하게 반투명 처리하는 방식(Windows layered window의 상수 알파 블렌딩) - 배경만
    # 완전히 투명하게 뚫고 글자만 선명하게 남기는 진짜 오버레이 방식(-transparentcolor, 특정
    # 색만 완전 투명/클릭통과)과는 다르다. 사용자가 보여준 참고 이미지(다른 DPS미터 오버레이)는
    # 어두운 패널이 게임 배경과 옅게 섞여 보이는 형태라 -alpha 쪽이 더 가까운 느낌이라 이걸로
    # 구현함 - 대신 텍스트/표 글자도 배경과 함께 살짝 비쳐 보인다(참고 이미지처럼 글자만
    # 완전히 또렷하진 않음). 0.3~1.0 사이로 클램프(너무 낮으면 창이 사실상 안 보여서 조작
    # 자체가 불가능해지는 걸 방지). --opacity CLI 옵션으로 조절 가능(main() 참고, 기본 0.88).
    try:
        root.attributes("-alpha", max(0.3, min(1.0, opacity)))
    except tk.TclError:
        pass  # 일부 환경(리눅스 특정 창관리자 등)에서 -alpha 미지원일 수 있음 - 조용히 무시

    value_var = tk.StringVar(value="대기 중...")
    delta_var = tk.StringVar(value="아이템을 사용하거나 캐릭터로 접속하면 표시됩니다")
    breakdown_var = tk.StringVar(value="")
    updated_var = tk.StringVar(value="")
    status_var = tk.StringVar(value="")

    tk.Label(root, textvariable=value_var, font=("Segoe UI", 34, "bold"),
              fg=ACCENT, bg=BG).pack(pady=(16, 0))

    tk.Label(root, textvariable=delta_var, font=("Segoe UI", 11),
              fg=FG_DIM, bg=BG).pack(pady=(0, 4))

    tk.Label(root, textvariable=breakdown_var, font=("Segoe UI", 11),
              fg=FG_DIM, bg=BG).pack(pady=(0, 2))

    tk.Label(root, textvariable=updated_var, font=("Segoe UI", 9),
              fg=FG_DIM, bg=BG).pack(pady=(0, 8))

    tk.Label(root, text="캐릭터 현황", font=("Segoe UI", 10, "bold"),
              fg=FG_LABEL, bg=BG).pack(anchor="w", padx=16)

    # 다크 테마에 맞춘 표(Treeview) 스타일 - 기본 ttk 테마는 배경색 지정이 안 먹혀서
    # "clam" 테마로 바꾼 뒤 색을 직접 지정한다.
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Dark.Treeview", background="#181818", fieldbackground="#181818",
                     foreground="#DDDDDD", rowheight=22, borderwidth=0)
    style.configure("Dark.Treeview.Heading", background="#262626", foreground=FG_LABEL,
                     borderwidth=0, relief="flat")
    style.map("Dark.Treeview", background=[("selected", "#333333")])

    hist_frame = tk.Frame(root, bg=BG)
    hist_frame.pack(fill="both", expand=True, padx=16, pady=(2, 8))

    hist_scroll = ttk.Scrollbar(hist_frame, orient="vertical")
    hist_scroll.pack(side="right", fill="y")

    hist_tree = ttk.Treeview(
        hist_frame, columns=("nickname", "base", "extra", "combat_power", "updated"), show="headings",
        yscrollcommand=hist_scroll.set, style="Dark.Treeview",
    )
    hist_tree.heading("nickname", text="닉네임")
    hist_tree.heading("base", text="기본")
    hist_tree.heading("extra", text="추가")
    hist_tree.heading("combat_power", text="전투력")
    hist_tree.heading("updated", text="갱신날짜")
    hist_tree.column("nickname", width=80, anchor="w")
    hist_tree.column("base", width=70, anchor="w")
    hist_tree.column("extra", width=70, anchor="w")
    hist_tree.column("combat_power", width=80, anchor="w")
    hist_tree.column("updated", width=140, anchor="w")
    hist_tree.pack(side="left", fill="both", expand=True)
    hist_scroll.config(command=hist_tree.yview)

    status_label = tk.Label(
        root, textvariable=status_var, font=("Segoe UI", 9),
        fg="#666666", bg=BG, wraplength=430, justify="left",
    )
    status_label.pack(pady=(0, 10), padx=16, fill="x")

    # 표 행은 닉네임으로 식별한다 (2026-07-08). entity_id는 계정/슬롯 단위로 재사용되므로
    # entity_id로 행을 구분하면 다른 캐릭터로 접속해도 새 행이 안 생기고 기존 행이 그 캐릭터
    # 데이터로 덮어써지는 문제가 있었음.
    row_by_nickname = {}  # nickname -> treeview row id

    # entity_id -> 그 entity_id로 마지막으로 확인된 닉네임 (이번 GUI 세션 내 캐시). 닉네임 없는
    # 패킷이 왔을 때 "지금 이 entity_id가 어느 캐릭터를 가리키고 있는지" 알아내는 데 쓴다.
    entity_nickname = {}

    # entity_id -> 그 entity_id로 아직 닉네임을 한 번도 못 받은 상태에서 들어온 레코드 임시 보관함.
    pending_records = {}

    def _remove_row(iid):
        for nick, v in list(row_by_nickname.items()):
            if v == iid:
                del row_by_nickname[nick]
        hist_tree.delete(iid)

    def upsert_status_row(record, nickname_confirmed=False):
        """캐릭터 현황 표 갱신. 행은 닉네임 기준(row_by_nickname)이고, entity_id는 "닉네임
        없는 패킷이 왔을 때 어느 캐릭터 것인지" 찾는 보조 키(entity_nickname)로만 쓴다.

        record["nickname"]이 아니라 호출부가 명시적으로 넘겨주는 nickname_confirmed(이 이벤트가
        실제 OwnNickname 패킷에서 온 것인지)만 보고 판단한다 - record는 이제 저장소가 닉네임
        확정 전에는 아예 쓰지 않으므로 nickname 필드가 항상 정확하지만(2026-07-08 저장소 재구성),
        그래도 이 GUI 레벨의 이중 방어는 유지한다.
        """
        entity_id = record.get("entity_id")
        if entity_id is None:
            return

        if nickname_confirmed:
            nickname = record.get("nickname")
            if not nickname:
                return
            entity_nickname[entity_id] = nickname

            pending = pending_records.pop(entity_id, None)
            merged = {**pending, **record} if pending else record

            values = (
                nickname,
                _fmt_info_cell(merged.get("oath_energy_base")),
                _fmt_info_cell(merged.get("oath_energy_dynamic")),
                _fmt_combat_power_cell(merged.get("combat_power")),
                _fmt_date_cell(merged.get("last_updated")),
            )
            iid = row_by_nickname.get(nickname)
            if iid is not None and hist_tree.exists(iid):
                hist_tree.item(iid, values=values)
                hist_tree.move(iid, "", 0)  # 방금 갱신된 캐릭터를 맨 위로
            else:
                new_iid = hist_tree.insert("", 0, values=values)
                row_by_nickname[nickname] = new_iid
                children = hist_tree.get_children()
                if len(children) > STATUS_ROW_CAP:
                    for old_id in children[STATUS_ROW_CAP:]:
                        _remove_row(old_id)
            return

        known_nick = entity_nickname.get(entity_id)
        iid = row_by_nickname.get(known_nick) if known_nick else None
        if known_nick is None or iid is None or not hist_tree.exists(iid):
            pending_records[entity_id] = record
            return
        values = (
            known_nick,
            _fmt_info_cell(record.get("oath_energy_base")),
            _fmt_info_cell(record.get("oath_energy_dynamic")),
            _fmt_combat_power_cell(record.get("combat_power")),
            _fmt_date_cell(record.get("last_updated")),
        )
        hist_tree.item(iid, values=values)
        hist_tree.move(iid, "", 0)

    def render_summary(record):
        """record: oath_energy_data.json 의 캐릭터 레코드 하나(dict). 화면 상단(총량/분리/
        마지막 갱신)만 갱신한다 - 표(캐릭터 현황)는 upsert_status_row 가 별도로 관리한다."""
        total = record.get("oath_energy")
        value_var.set(f"오드에너지 {total}" if total is not None else "대기 중...")

        base = record.get("oath_energy_base")
        dynamic = record.get("oath_energy_dynamic")
        if base is not None and dynamic is not None:
            breakdown_var.set(f"기본 {base} + 추가 {dynamic} = {base + dynamic}")
        else:
            breakdown_var.set("왼쪽/오른쪽 값 아직 확인 안 됨")

        last_updated = record.get("last_updated")
        updated_var.set(f"마지막 갱신: {last_updated}" if last_updated else "")

        last_delta = record.get("last_delta")
        if last_delta is None:
            delta_var.set("(변화량 알 수 없음, 최초 값)")
        else:
            sign = "+" if last_delta >= 0 else ""
            delta_var.set(f"{sign}{last_delta}")

    # 시작하자마자 "대기" 상태로 텅 비어 보이지 않도록, 이전 실행에서 이미 저장된
    # oath_energy_data.json 내용으로 초기 화면을 채운다. 표는 캐릭터당 한 행(현황)이므로,
    # 저장된 모든 캐릭터를 last_updated 오래된 순으로 upsert 해서 최신이 맨 위로 오게 한다.
    try:
        initial_store = CharacterStore()
        initial_nickname = initial_store.most_recent_character()
        if initial_nickname is not None:
            render_summary(initial_store.data.get(initial_nickname, {}))

        records = list(initial_store.data.values())
        records.sort(key=lambda r: r.get("last_updated") or "")  # 오래된 것부터
        for rec in records:
            upsert_status_row(rec, nickname_confirmed=True)
    except Exception:
        pass  # 저장 파일이 없거나 읽기 실패해도 GUI 자체는 정상적으로 뜨도록 조용히 무시

    def _console_ts():
        return datetime.datetime.now().strftime("%H:%M:%S")

    def poll_queue():
        try:
            while True:
                ev = event_queue.get_nowait()

                forget_id = getattr(ev, "forget_entity_id", None)
                if forget_id is not None:
                    entity_nickname.pop(forget_id, None)
                    # 2026-07-08: GUI 창의 상태 라벨(status_var)은 문자열 하나만 덮어쓰므로
                    # 지나간 이벤트가 화면에서 사라진다. 사용자가 "모든 행동이 콘솔에 알림
                    # 뜨도록" 요청 - GUI 모드에서도 콘솔(있으면)에 모든 이벤트/상태를 그대로
                    # print해서, exe 콘솔 창을 보면 무슨 일이 일어났는지 전부 기록으로 남게 함.
                    print(f"[{_console_ts()}] [알림] entity_id={forget_id} 닉네임 캐시 초기화 (캐릭터 전환 감지)")
                    continue

                record = getattr(ev, "record", None)
                if record:
                    render_summary(record)
                    nickname_confirmed = getattr(ev, "nickname_confirmed", False)
                    upsert_status_row(record, nickname_confirmed)
                    nick = record.get("nickname") or f"캐릭터(id={record.get('entity_id')})"
                    print(
                        f"[{_console_ts()}] [갱신] {nick}  "
                        f"오드={record.get('oath_energy')}  전투력={record.get('combat_power')}  "
                        f"닉네임확인={'예' if nickname_confirmed else '아니오'}"
                    )
                else:
                    # record 스냅샷이 없는 예외적인 경우를 위한 최소한의 폴백
                    value_var.set(f"오드에너지 {ev.new_total}")
                    print(f"[{_console_ts()}] [오드에너지] 총량={ev.new_total} (레코드 스냅샷 없음)")
        except queue.Empty:
            pass
        try:
            while True:
                msg = status_queue.get_nowait()
                status_var.set(msg)
                print(f"[{_console_ts()}] [상태] {msg}")
        except queue.Empty:
            pass
        root.after(150, poll_queue)

    root.after(150, poll_queue)
    root.mainloop()


def run_console(event_queue, status_queue):
    print("콘솔 모드로 실행 중. 오드에너지 변경 이벤트 및 상태 메시지를 여기에 출력합니다.")

    def status_loop():
        while True:
            msg = status_queue.get()
            print(f"[상태] {msg}")

    threading.Thread(target=status_loop, daemon=True).start()

    while True:
        ev = event_queue.get()
        # 2026-07-18 추가: GUI 모드(poll_queue)는 2026-07-09에 추가된 forget_entity_id
        # SimpleNamespace 이벤트(캐릭터 전환 감지 시 GUI 닉네임 캐시 무효화용, delta 필드 없음)를
        # 처리하지만 콘솔 모드(run_console)는 그때 같이 안 고쳐져서 이 이벤트를 받으면
        # `ev.delta` 접근에서 AttributeError로 그대로 죽었다("살육성 오드0 실험.pcapng" 리플레이
        # 검증 중 실제로 재현됨, --no-gui 모드 전용 크래시라 GUI 모드에서는 안 드러났었음).
        forget_id = getattr(ev, "forget_entity_id", None)
        if forget_id is not None:
            print(f"[알림] entity_id={forget_id} 닉네임 캐시 초기화 (캐릭터 전환 감지)")
            continue
        name = getattr(ev, "display_name", None) or "캐릭터"
        if ev.delta is None:
            print(f"[오드에너지] {name}  총량={ev.new_total}  변화=알 수 없음(최초 값)")
        else:
            sign = "+" if ev.delta >= 0 else ""
            print(f"[오드에너지] {name}  총량={ev.new_total}  변화={sign}{ev.delta}")


# ---------------------------------------------------------------------------
# 정기 충전(왼쪽 숫자) 시뮬레이션 - 실제 패킷 없이 시간 기준으로 추정 (2026-07-09 추가)
# ---------------------------------------------------------------------------

# 오드에너지 정기 충전 시각 (사용자 확인, 2026-07-07): 02/05/08/11/14/17/20/23시마다 왼쪽
# 숫자에 +10(무구독) 또는 +15(로얄구독권)가 자동으로 붙는다. 프로그램이 구독권 활성 여부를
# 알 방법이 없어서(게임 UI에서만 확인 가능, 패킷으로는 아직 못 찾음) 사용자 확정에 따라
# +15로 고정한다 - "일단 자체 증가하는 수치는 15로 고정하고 실제 값은 로그인 하거나 특정
# 이밴트시에 갱신 하면 될것 같아 이 작업의 용도는 오랫동안 안들어간 캐릭터에 대해서 오드량을
# 예상하기위한 것이야".
PERIODIC_REGEN_HOURS = (2, 5, 8, 11, 14, 17, 20, 23)
PERIODIC_REGEN_AMOUNT = 15


def _next_periodic_regen_time(now=None):
    """PERIODIC_REGEN_HOURS 중 now 이후로 가장 가까운 정각(분/초 0)을 반환."""
    now = now or datetime.datetime.now()
    candidates = []
    for day_offset in (0, 1):
        base_day = now + datetime.timedelta(days=day_offset)
        for hour in PERIODIC_REGEN_HOURS:
            cand = base_day.replace(hour=hour, minute=0, second=0, microsecond=0)
            if cand > now:
                candidates.append(cand)
    return min(candidates)


def _schedule_periodic_regen(store, status_queue):
    """프로그램이 켜져 있는 동안 정기 충전 시각마다 저장된 모든 캐릭터의 왼쪽 숫자(기본
    오드)를 실제 패킷 없이 자동으로 +15 해준다 (사용자 요청, 2026-07-09) - "우리 프로그램이
    돌고있는동안 2시 5시 8시 11시 오전 오후로 15씩 증가하는 로직은 추가할수 있지 않아?".

    실측값과 필드 상 구분하지 않고 그대로 합산한다(CharacterStore.catch_up_periodic_regen 참고,
    사용자 확정: "구분 없이 그냥 합산해서 json에 담아 넣는데 대신 시간마다 증가되는 오드는
    추가 오드가 아닌 기본(왼쪽)오드"). 다음에 실제 로그인/이 문서의 [[Thirteenth bug]] 2값
    변형 이벤트 등으로 진짜 값이 확인되면 그 값이 그대로 덮어써지므로 자연히 보정된다.

    적용 대상은 저장된 모든 캐릭터(사용자 확정: "저장된 모든 캐릭터한테 적용") - 리플레이
    모드(replay_pcap)에는 연결하지 않는다. 리플레이는 과거 캡처 재생/검증용이라 지금 이 순간의
    실제 벽시계 시각 기준 정기 충전을 적용하면 검증 결과가 왜곡된다.

    **2026-07-18 수정: 프로그램을 껐다 켠 사이에 지나간 정기 충전도 이제 소급 적용된다.**
    예전엔 다음 예약 시각을 항상 "지금 이후 가장 가까운 시각"으로만 계산해서 꺼져있던 동안의
    충전을 그냥 놓쳤는데, 사용자가 "15가 올라간 시간을 갱신날짜로 기록해놓고 exe가 스타트될때
    그 갱신날짜를 기반으로 시간 계산을 한 다음 갱신 시켜놓으면 되는거 아니냐"고 제안 - 실제
    서버는 우리 프로그램 실행 여부와 무관하게 계속 충전해왔을 것이므로 타당한 지적이라 반영함.
    `CharacterStore.catch_up_periodic_regen()`이 캐릭터별 체크포인트 기준으로 지난 정기충전
    횟수를 세서 한 번에 몰아 적용한다 - 이 함수는 이제 그 메서드를 매 예약 시각마다 호출하는
    역할만 하고(기존 타이머 스케줄 유지, 3시간마다 재예약), 실제 소급/적용 로직은
    `catch_up_periodic_regen`에 있다. 프로그램 시작 직후에도 별도로 한 번 호출해서(main() 참고)
    꺼져있던 동안의 공백을 즉시 메운다.
    """
    def _fire():
        try:
            store.catch_up_periodic_regen(PERIODIC_REGEN_AMOUNT, PERIODIC_REGEN_HOURS)
            status_queue.put(
                f"[정기충전] 저장된 모든 캐릭터의 왼쪽 숫자(기본 오드)에 +{PERIODIC_REGEN_AMOUNT}"
                f"(경과분 소급 포함) 추정 반영"
            )
        except Exception as e:
            status_queue.put(f"[정기충전][에러] 적용 실패: {e!r}")
        _schedule_periodic_regen(store, status_queue)  # 다음 시각으로 재예약

    next_time = _next_periodic_regen_time()
    delay = max((next_time - datetime.datetime.now()).total_seconds(), 1.0)
    threading.Timer(delay, _fire).start()


def _start_periodic_regen(capture, status_queue):
    """정기 충전(+15, 3시간마다) 시뮬레이션을 실제로 켜는 진입점 - 시작 시 소급 반영 1회 +
    3시간 주기 재예약(_schedule_periodic_regen)까지 묶어서 여기 하나로 격리했다 (2026-08-08,
    원래 main() 안에 인라인으로 있던 코드를 그대로 옮긴 것).

    **2026-08-08~2026-08-13: 죽은 코드였다가 재활성화됨.** 2026-08-08에 사용자 요청으로 격리:
    "3시간마다 기본오드 15충전로직 제대로 동작도 못하는데 일단 따로 함수로 묶여서
    격리시켜두고 죽은코드로 만들어둬 나중에 정리한다". 계기: 이 시뮬레이션이 실제 패킷과
    무관하게 known_base를 계속 올려버리는 부작용이 있어서(오래 켜둘수록 거의 모든 캐릭터가
    known_base>0 상태가 됨), 같은 날 있었던 "기본-우선-소모" 분기 시도(당시 known_base>0이면
    감소 패킷 원값을 그대로 base에 덮어씀)가 이것 때문에 실사용에서 회귀를 냈다(memory의
    aion2_packet_reverse_engineering.md "REVERTED" 절 참고).

    이후 그 분기가 `_resolve_decrease_split()`로 완전히 재구현되어 known_base의 절대적 크기가
    아니라 (old_total-new_total)로 역산한 정확한 소모량만 base에서 차감하는 방식으로
    바뀌었으므로, 2026-08-12 사용자 결정에 따라 2026-08-13 main()에서 다시 호출하도록
    재활성화함(memory "Decision: re-enable the periodic-regen dead code next session" 참고).
    """
    try:
        capture.store.catch_up_periodic_regen(PERIODIC_REGEN_AMOUNT, PERIODIC_REGEN_HOURS)
        status_queue.put("[정기충전] 시작 시 경과분 소급 반영 완료")
    except Exception as e:
        status_queue.put(f"[정기충전][에러] 시작 시 소급 반영 실패: {e!r}")
    _schedule_periodic_regen(capture.store, status_queue)


def main():
    parser = argparse.ArgumentParser(description="AION2 오드에너지 실시간 모니터")
    parser.add_argument("--server", default=DEFAULT_SERVER_NET,
                         help="게임 서버 IP 또는 대역 (기본: 206.127.156.0/24)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="게임 서버 포트")
    parser.add_argument("--iface", default=None, help="캡처할 네트워크 인터페이스 (미지정시 자동)")
    parser.add_argument("--list-ifaces", action="store_true", help="사용 가능한 인터페이스 목록 출력 후 종료")
    parser.add_argument("--replay", default=None, help="실시간 캡처 대신 저장된 .pcapng 파일로 재생/검증")
    parser.add_argument("--replay-speed", type=float, default=0.0,
                         help="리플레이 재생 속도 배율 (0=최대한 빠르게, 1=원래 속도)")
    parser.add_argument("--no-gui", action="store_true", help="GUI 없이 콘솔 출력만")
    parser.add_argument("--debug", action="store_true", help="디버그 상태 메시지 출력 (수신 패킷 수 등)")
    parser.add_argument("--opacity", type=float, default=0.88,
                         help="GUI 창 반투명도, 0.3~1.0 (1.0=완전 불투명, 기본 0.88) - 2026-07-18 추가")
    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
        return

    server_net = parse_network(args.server)
    event_queue = queue.Queue()
    status_queue = queue.Queue()

    if args.replay:
        t = threading.Thread(
            target=replay_pcap,
            args=(args.replay, server_net, args.port, event_queue, status_queue, args.replay_speed),
            daemon=True,
        )
        t.start()
    else:
        if not _npcap_installed():
            status_queue.put(
                "[안내] Npcap이 설치되어 있지 않은 것 같습니다. https://npcap.com 에서 설치 후 재실행하세요."
            )
            if not args.no_gui:
                try:
                    _warn_npcap_missing_gui()
                except Exception:
                    pass  # 감지가 틀렸을 수도 있으니(레지스트리 경로가 다른 경우 등) 조용히 무시하고 계속 진행
        capture = LiveCapture(server_net, args.port, event_queue, status_queue,
                               iface=args.iface, debug=args.debug)
        capture.start()
        print(f"실시간 캡처 시작: {server_net}:{args.port} (관리자 권한 필요)")
        # 2026-08-13: 정기 충전(+15, 3시간마다) 시뮬레이션 재활성화 (사용자 결정, 2026-08-12
        # memory "Decision: re-enable the periodic-regen dead code next session" 참고).
        # 2026-08-08에 격리(죽은코드화)했던 이유는 당시 known_base>0이면 감소 패킷의 원값을
        # 그대로 base에 덮어쓰는 별개의 버그("기본-우선-소모" 1차 시도)가 정기충전 때문에
        # 상시 발동해 정상적인 dynamic-only 소모까지 망가뜨렸기 때문 (memory의
        # aion2_packet_reverse_engineering.md "REVERTED" 절 참고). 그 버그는 이후
        # _resolve_decrease_split()로 완전히 다른 방식(정확한 소모량을 old_total-new_total로
        # 역산 후 base부터 차감)으로 재구현되어 known_base의 절대값 크기에 더 이상 의존하지
        # 않으므로, 정기충전이 known_base를 올려도 같은 회귀가 재발하지 않을 것으로 판단됨.
        _start_periodic_regen(capture, status_queue)

    if args.no_gui:
        run_console(event_queue, status_queue)
    else:
        # 2026-07-18 추가: PySide6(Qt) 기반 새 GUI(aion2_gui_qt.py)를 먼저 시도한다 -
        # 사용자가 참고 이미지를 보여주며 "전체 디자인까지 이 느낌으로 재단장"을 요청,
        # PySide6로 전체 재작성하기로 확정함(AskUserQuestion). 여기서 지연 임포트하는 이유:
        # aion2_gui_qt.py가 모듈 최상단에서 이 파일(aion2_live_monitor)의 포맷터 함수/
        # STATUS_ROW_CAP을 가져다 쓰는데, main() 안에서 임포트하면 그 시점엔 이 파일이
        # 이미 다 로드된 뒤라 순환 참조가 안 생긴다. PySide6 미설치거나 실행 중 에러가 나면
        # 기존 Tkinter GUI(run_gui)로, 그것도 실패하면 콘솔 모드로 2단계 폴백한다.
        try:
            from aion2_gui_qt import run_gui_qt
            # 2026-07-19 수정: 삭제 버튼 기능을 위해 GUI가 자기만의 CharacterStore를 새로
            # 만들지 않고 LiveCapture가 이미 갖고 있는 capture.store를 그대로 공유하게 함 -
            # 주기적 오드 재생 스케줄러(_schedule_periodic_regen)가 같은 이유로 capture.store를
            # 재사용하는 것과 동일한 패턴. 두 인스턴스가 따로 놀면 삭제해도 LiveCapture 쪽의
            # 옛 메모리 상태가 다음 저장 때 되살려버리는 문제가 생긴다.
            run_gui_qt(event_queue, status_queue, opacity=args.opacity, store=capture.store)
        except Exception as e:
            print(f"PySide6 GUI 실행 실패 ({e}), 기존 Tkinter GUI로 전환합니다.")
            try:
                run_gui(event_queue, status_queue, opacity=args.opacity)
            except Exception as e2:
                print(f"GUI 실행 실패 ({e2}), 콘솔 모드로 전환합니다.")
                run_console(event_queue, status_queue)


if __name__ == "__main__":
    main()
