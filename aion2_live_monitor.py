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
        self.store = CharacterStore()  # 캐릭터별 오드에너지 로컬 저장소 (oath_energy_data.json, 닉네임 키)

        # 2026-07-08: 저장소가 닉네임 키로 바뀌면서, "지난 세션에 마지막으로 활동한 캐릭터"를
        # 이어받아 콜드스타트를 완화한다. entity_id/base는 패킷 신뢰 검증과 총량 계산용 참고값일
        # 뿐, 실제로 이 캐릭터가 이번 세션에도 접속했는지는 아래에서 확인되는 닉네임으로 재검증된다.
        last_nickname = self.store.most_recent_character()
        last_record = self.store.data.get(last_nickname, {}) if last_nickname else {}
        self.known_oath_id = last_record.get("entity_id")
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
        else:
            dynamic = ev.new_total

        if ev.delta is None and self.last_dynamic is not None:
            ev.delta = dynamic - self.last_dynamic
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
        if ev.delta is not None:
            return True  # "증가" 타입: total과 delta 두 필드가 있어 자체 교차검증됨
        if self.known_oath_id is None:
            return True  # 콜드스타트: 아직 기준 id가 없으면 일단 신뢰하고 기준으로 삼음
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
                self.store.update_oath_energy(
                    ev.nickname, pending.get("oath_energy"), pending.get("last_delta"),
                    base=pending.get("oath_energy_base"), dynamic=pending.get("oath_energy_dynamic"),
                    entity_id=self.known_oath_id,
                )
                if pending.get("combat_power") is not None:
                    self.store.update_combat_power(
                        ev.nickname, pending["combat_power"], entity_id=self.known_oath_id,
                    )
            record_snapshot = dict(self.store.data.get(ev.nickname, {}))
            self.event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=True))

    def _on_combat_power(self, ev):
        # 2026-07-08: opcode(0x56,0x36)엔 entity_id 필드가 없어서(닉네임과 동일한 상황), 지금
        # 추적 중인 오드에너지 entity_id(known_oath_id)에 그대로 붙인다. 확정된 설계: 캐릭터
        # 인식(known_oath_id)이 아예 안 된 상태면 전투력도 무시한다 ("캐릭터 인식이 되어있어야
        # 전투력이 인식되는것이 좋아" - 사용자 확인). 닉네임이 아직 확인 전이면(current_nickname
        # 없음) pending_oath에만 담아두고 저장소엔 안 쓴다 (오드에너지와 동일한 이유).
        if self.known_oath_id is None:
            return
        if self.current_nickname:
            self.store.update_combat_power(self.current_nickname, ev.combat_power, entity_id=self.known_oath_id)
            record_snapshot = dict(self.store.data.get(self.current_nickname, {}))
        else:
            pending = self.pending_oath.setdefault(self.known_oath_id, {})
            pending["combat_power"] = ev.combat_power
            pending["combat_power_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
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
    # 2026-07-08: 닉네임 확인 전 오드에너지/전투력 데이터 임시 보관함 (LiveCapture.pending_oath와 동일).
    pending_oath = {}

    def is_trusted(ev):
        if ev.delta is not None:
            return True
        if known["id"] is None:
            return True
        return ev.entity_id == known["id"]

    def on_oath(ev):
        if not is_trusted(ev):
            status_queue.put(
                f"[의심] opcode는 오드에너지와 같지만 알고 있는 캐릭터(id={known['id']})와 "
                f"달라서 무시됨: id={ev.entity_id} total={ev.new_total}"
            )
            return

        if getattr(ev, "is_snapshot", False):
            known["base"] = getattr(ev, "base", 0) or 0
            dynamic = getattr(ev, "dynamic", ev.new_total)
            # LiveCapture._on_oath_energy 와 동일한 이유로 리셋 (2026-07-08).
            current["nickname"] = None
            current["server"] = None
            current["job"] = None
            # GUI의 entity_nickname 캐시도 함께 무효화 (동일 이유, LiveCapture 쪽 주석 참고).
            event_queue.put(types.SimpleNamespace(forget_entity_id=ev.entity_id))
        else:
            dynamic = ev.new_total

        if ev.delta is None and last_dynamic_holder["v"] is not None:
            ev.delta = dynamic - last_dynamic_holder["v"]
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
                store.update_oath_energy(
                    ev.nickname, pending.get("oath_energy"), pending.get("last_delta"),
                    base=pending.get("oath_energy_base"), dynamic=pending.get("oath_energy_dynamic"),
                    entity_id=known["id"],
                )
                if pending.get("combat_power") is not None:
                    store.update_combat_power(ev.nickname, pending["combat_power"], entity_id=known["id"])
            record_snapshot = dict(store.data.get(ev.nickname, {}))
            event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=True))

    def on_combat_power(ev):
        if known["id"] is None:
            return
        if current["nickname"]:
            store.update_combat_power(current["nickname"], ev.combat_power, entity_id=known["id"])
            record_snapshot = dict(store.data.get(current["nickname"], {}))
        else:
            pending = pending_oath.setdefault(known["id"], {})
            pending["combat_power"] = ev.combat_power
            pending["combat_power_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
            record_snapshot = {"entity_id": known["id"], "nickname": None, **pending}
        event_queue.put(types.SimpleNamespace(record=record_snapshot, nickname_confirmed=False))

    proc = StreamProcessor(on_oath_energy=on_oath, on_nickname=on_nickname,
                            get_known_oath_id=lambda: known["id"],
                            on_combat_power=on_combat_power)
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

def _fmt_info_cell(total, delta):
    """현황 표의 "오드 정보" 칸: 총량만 보여준다 (2026-07-08 - 사용자 요청으로 변화량(delta)
    표시는 제거함. delta 파라미터는 호출부 호환을 위해 남겨두되 더는 사용하지 않는다)."""
    return f"{total}"


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


def run_gui(event_queue, status_queue):
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
        hist_frame, columns=("nickname", "info", "combat_power", "updated"), show="headings",
        yscrollcommand=hist_scroll.set, style="Dark.Treeview",
    )
    hist_tree.heading("nickname", text="닉네임")
    hist_tree.heading("info", text="오드 정보")
    hist_tree.heading("combat_power", text="전투력")
    hist_tree.heading("updated", text="갱신날짜")
    hist_tree.column("nickname", width=80, anchor="w")
    hist_tree.column("info", width=110, anchor="w")
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
                _fmt_info_cell(merged.get("oath_energy"), merged.get("last_delta")),
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
            _fmt_info_cell(record.get("oath_energy"), record.get("last_delta")),
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

    def poll_queue():
        try:
            while True:
                ev = event_queue.get_nowait()

                forget_id = getattr(ev, "forget_entity_id", None)
                if forget_id is not None:
                    entity_nickname.pop(forget_id, None)
                    continue

                record = getattr(ev, "record", None)
                if record:
                    render_summary(record)
                    nickname_confirmed = getattr(ev, "nickname_confirmed", False)
                    upsert_status_row(record, nickname_confirmed)
                else:
                    # record 스냅샷이 없는 예외적인 경우를 위한 최소한의 폴백
                    value_var.set(f"오드에너지 {ev.new_total}")
        except queue.Empty:
            pass
        try:
            while True:
                msg = status_queue.get_nowait()
                status_var.set(msg)
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
        name = getattr(ev, "display_name", None) or "캐릭터"
        if ev.delta is None:
            print(f"[오드에너지] {name}  총량={ev.new_total}  변화=알 수 없음(최초 값)")
        else:
            sign = "+" if ev.delta >= 0 else ""
            print(f"[오드에너지] {name}  총량={ev.new_total}  변화={sign}{ev.delta}")


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

    if args.no_gui:
        run_console(event_queue, status_queue)
    else:
        try:
            run_gui(event_queue, status_queue)
        except Exception as e:
            print(f"GUI 실행 실패 ({e}), 콘솔 모드로 전환합니다.")
            run_console(event_queue, status_queue)


if __name__ == "__main__":
    main()
