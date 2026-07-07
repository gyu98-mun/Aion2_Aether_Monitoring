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
      패킷으로, 여기에 로그인 시점의 오드에너지 절대값이 들어있다 (999.pcapng 로 검증: 로그인 직전
      확인한 실제 값 1370과 정확히 일치). 캡처를 캐릭터 선택 화면에서부터 미리 켜두면 이 패킷을 잡아서
      프로그램을 켠 직후부터 바로 정확한 절대값이 표시된다. 다만 이 패킷의 정확한 바이트 구조가
      세션마다 100% 동일하진 않아서(확인된 예외: 888888.pcapng), 못 잡는 세션도 있을 수 있음 -
      그런 경우엔 기존처럼 다음 아이템 사용/소모 이벤트가 올 때까지 절대값을 알 수 없다.
    - 아무 반응이 없으면: (1) 관리자 권한으로 실행했는지, (2) --iface 로 올바른 인터페이스를
      지정했는지, (3) --debug 로 서버 패킷 자체가 잡히는지부터 확인할 것.
    - 캐릭터 닉네임(OwnNickname, opcode 0x33/0x36)의 entity_id 는 접속할 때마다 바뀌는 작은
      임시 id 라서 오드에너지 entity_id(영속값)와 숫자로 매칭되지 않는다. 그래서 "같은 접속
      세션 동안 확인한 닉네임"을 오드에너지 이벤트가 올 때 그 이벤트의 entity_id 에 붙이는
      방식으로 연결한다 (LiveCapture.current_nickname / replay_pcap 의 current 딕셔너리 참고).
    - opcode (0x0C, 0x61) 은 오드에너지 말고 다른 것(맵 이벤트/카운터 등)에도 재사용된다는 게
      실제 캡처(각성전1/2.pcapng)로 확인됨 - "감소" 서브타입(delta 필드 없음)은 총량 값 하나만
      가지고 있어 자체적으로는 진짜인지 검증할 방법이 없다. 그래서 "이전에 실제로 오드에너지로
      확인된 entity_id"와 다르면 무시하도록 되어있다 (자세한 원리는 LiveCapture._is_trusted_oath_event
      참고). oath_energy_data.json 에 이미 기록이 있으면 그 id를 기준으로 삼고, 완전히 처음 실행
      (파일이 비어있음)이면 첫 이벤트를 일단 신뢰하고 그 id를 기준으로 삼는다 - 이 경우 아주 드물게
      (파일이 비어있는 상태에서 세션 첫 오드에너지 이벤트가 하필 이 재사용 패킷과 겹치면) 잘못된
      id가 기준으로 잡힐 수 있음. 그럴 땐 오드에너지가 갑자기 이상한 값(1 근처)으로 보이고 그 뒤로도
      계속 그 상태면, oath_energy_data.json 에서 잘못 잡힌 항목을 지우고 다시 실행하면 된다.
"""

import argparse
import ipaddress
import queue
import struct
import sys
import threading
import time

from aion2_core import StreamProcessor, StreamAssembler, LiveTcpReassembler
from aion2_storage import CharacterStore

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
        self.store = CharacterStore()  # 캐릭터별 오드에너지 로컬 저장소 (oath_energy_data.json)
        # 2026-07-07 추가: opcode(0x0C,0x61)가 오드에너지가 아닌 다른 용도(맵 이벤트 카운터 등)로도
        # 재사용된다는 게 실제 캡처(각성전1/2.pcapng)에서 확인됨 - "이번에 추적 중인 진짜 오드에너지
        # entity_id"를 알고 있으면, 그와 다른 id로 온 (교차검증 불가능한) "감소" 타입 이벤트를 걸러낸다.
        # 재실행 시 이전 세션에서 확인된 id를 저장소에서 이어받아 시작 (콜드스타트 완화).
        # 새 TCP 연결(재접속)에도 리셋하지 않는다 - "어떤 캐릭터를 추적 중인가"는 세션과 무관.
        self.known_oath_id = self.store.most_recent_oath_entity_id()
        # 2026-07-07 추가: "왼쪽 숫자"(정기 충전분) 버그 수정. 실제 총 오드에너지 = base(왼쪽) +
        # dynamic(오른쪽). base 는 로그인 스냅샷(opcode 0x0B,0x61)에서만 얻을 수 있고, 평소
        # opcode(0x0C,0x61) 변경 이벤트는 dynamic 만 갱신한다 (아래 _on_oath_energy 참고).
        # 저장소에 이전에 확인된 base 가 있으면 이어받아 콜드스타트를 완화한다.
        self.known_base = self.store.get_known_base(self.known_oath_id) if self.known_oath_id else 0
        self._build_pipeline()
        self._stop = threading.Event()
        self._thread = None

    def _build_pipeline(self):
        proc = StreamProcessor(
            on_oath_energy=self._on_oath_energy,
            on_nickname=self._on_nickname,
            on_unknown=self._on_unknown if self.debug else None,
            get_known_oath_id=lambda: self.known_oath_id,
        )
        assembler = StreamAssembler(proc)
        self.live_reassembler = LiveTcpReassembler(assembler)
        # OwnNickname 의 entity_id 는 세션마다 바뀌는 작은 임시 id라서 오드에너지의
        # 영속 id 와 숫자로 직접 매칭이 안 된다 (aion2_core.py의 parse_own_nickname_packet
        # 문서 참고). 대신 "같은 접속 세션 동안 확인한 닉네임"을 오드에너지 이벤트가 올 때
        # 그 이벤트의 entity_id 에 붙여주는 방식으로 연결한다. 새 연결(재접속)마다 리셋.
        self.current_nickname = None
        self.current_server = None
        self.current_job = None

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
        if self.current_nickname:
            self.store.update_nickname(ev.entity_id, self.current_nickname, self.current_server, self.current_job)
        self.store.update_oath_energy(ev.entity_id, ev.new_total, ev.delta, base=self.known_base, dynamic=dynamic)
        ev.display_name = self.store.get_display_name(ev.entity_id)
        # GUI가 대시보드와 같은 내용(닉네임/왼쪽·오른쪽 분리/최근 이력)을 보여줄 수 있도록,
        # 저장 직후의 레코드 전체를 이벤트에 실어 보낸다 (2026-07-08 추가). history 리스트는
        # 캡처 스레드가 이후 계속 append 할 수 있으므로 얕은 복사로 스냅샷을 떠서 넘긴다.
        record = self.store.data.get(str(ev.entity_id), {})
        ev.record = {**record, "history": list(record.get("history", []))}
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
    # OwnNickname 의 entity_id 는 세션마다 바뀌는 작은 임시 id라서 오드에너지의 영속 id 와
    # 직접 매칭이 안 된다 (aion2_core.py 문서 참고). 리플레이 중 확인한 닉네임을 "현재
    # 세션의 닉네임"으로 들고 있다가, 오드에너지 이벤트가 올 때 그 이벤트의 entity_id 에 붙인다.
    current = {"nickname": None, "server": None, "job": None}
    # 2026-07-07 추가: opcode(0x0C,0x61) 오탐 방지용 - LiveCapture._on_oath_energy 와 동일한 로직
    # (id 신뢰 검증). 저장소에 이전에 확인된 id가 있으면 그걸로 콜드스타트를 완화한다.
    known = {"id": store.most_recent_oath_entity_id()}
    # 2026-07-07 추가: "왼쪽 숫자"(base, 정기 충전분) + "오른쪽 숫자"(dynamic, 누적분) 합산 버그 수정
    # - LiveCapture._on_oath_energy 와 동일한 로직 (자세한 설명은 그쪽 주석 참고).
    known["base"] = store.get_known_base(known["id"]) if known["id"] else 0

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
            store.update_nickname(ev.entity_id, current["nickname"], current["server"], current["job"])
        store.update_oath_energy(ev.entity_id, ev.new_total, ev.delta, base=known["base"], dynamic=dynamic)
        ev.display_name = store.get_display_name(ev.entity_id)
        # 라이브 모드와 동일하게, GUI가 저장된 레코드 전체(닉네임/왼쪽·오른쪽/이력)를 볼 수 있게
        # 스냅샷을 실어 보낸다 (2026-07-08 추가).
        record = store.data.get(str(ev.entity_id), {})
        ev.record = {**record, "history": list(record.get("history", []))}
        event_queue.put(ev)

    def on_nickname(ev):
        current["nickname"] = ev.nickname
        current["server"] = ev.server
        current["job"] = ev.job
        status_queue.put(f"캐릭터 닉네임 확인: {ev.nickname}")

    proc = StreamProcessor(on_oath_energy=on_oath, on_nickname=on_nickname,
                            get_known_oath_id=lambda: known["id"])
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

def _fmt_history_entry(h):
    ts = h.get("timestamp") or ""
    t = ts[11:19] if len(ts) >= 19 else ts  # "YYYY-MM-DDTHH:MM:SS" -> "HH:MM:SS"
    delta = h.get("delta")
    if delta is None:
        delta_text = "최초"
    else:
        delta_text = f"+{delta}" if delta >= 0 else str(delta)
    total = h.get("oath_energy")
    return f"{t}   {delta_text:>6}   → {total}"


def run_gui(event_queue, status_queue):
    import tkinter as tk

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

    nickname_var = tk.StringVar(value="캐릭터 확인 중...")
    value_var = tk.StringVar(value="대기 중...")
    delta_var = tk.StringVar(value="아이템을 사용하거나 캐릭터로 접속하면 표시됩니다")
    breakdown_var = tk.StringVar(value="")
    updated_var = tk.StringVar(value="")
    status_var = tk.StringVar(value="")

    tk.Label(root, textvariable=nickname_var, font=("Segoe UI", 14, "bold"),
              fg=FG_LABEL, bg=BG).pack(pady=(14, 0))

    tk.Label(root, textvariable=value_var, font=("Segoe UI", 34, "bold"),
              fg=ACCENT, bg=BG).pack(pady=(4, 0))

    tk.Label(root, textvariable=delta_var, font=("Segoe UI", 11),
              fg=FG_DIM, bg=BG).pack(pady=(0, 4))

    tk.Label(root, textvariable=breakdown_var, font=("Segoe UI", 11),
              fg=FG_DIM, bg=BG).pack(pady=(0, 2))

    tk.Label(root, textvariable=updated_var, font=("Segoe UI", 9),
              fg=FG_DIM, bg=BG).pack(pady=(0, 8))

    tk.Label(root, text="최근 변경 이력", font=("Segoe UI", 10, "bold"),
              fg=FG_LABEL, bg=BG).pack(anchor="w", padx=16)

    hist_frame = tk.Frame(root, bg=BG)
    hist_frame.pack(fill="both", expand=True, padx=16, pady=(2, 8))

    hist_scroll = tk.Scrollbar(hist_frame)
    hist_scroll.pack(side="right", fill="y")

    hist_list = tk.Listbox(
        hist_frame, font=("Consolas", 10), bg="#181818", fg="#DDDDDD",
        selectbackground="#333333", borderwidth=0, highlightthickness=0,
        yscrollcommand=hist_scroll.set,
    )
    hist_list.pack(side="left", fill="both", expand=True)
    hist_scroll.config(command=hist_list.yview)

    status_label = tk.Label(
        root, textvariable=status_var, font=("Segoe UI", 9),
        fg="#666666", bg=BG, wraplength=430, justify="left",
    )
    status_label.pack(pady=(0, 10), padx=16, fill="x")

    def render_record(record):
        """record: oath_energy_data.json 의 캐릭터 레코드 하나(dict). 대시보드(index.html)의
        renderCard()와 같은 필드를 같은 방식으로 보여준다 - 화면이 서로 다를 뿐 내용은 동일해야 함."""
        entity_id = record.get("entity_id")
        nickname_var.set(record.get("nickname") or f"캐릭터(id={entity_id})")

        total = record.get("oath_energy")
        value_var.set(f"오드에너지 {total}" if total is not None else "대기 중...")

        base = record.get("oath_energy_base")
        dynamic = record.get("oath_energy_dynamic")
        if base is not None and dynamic is not None:
            breakdown_var.set(f"왼쪽 {base} + 오른쪽 {dynamic} = {base + dynamic}")
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

        hist_list.delete(0, tk.END)
        history = record.get("history") or []
        for h in reversed(history):  # 최신이 위로
            hist_list.insert(tk.END, _fmt_history_entry(h))
        if not history:
            hist_list.insert(tk.END, "  (기록 없음)")

    # 시작하자마자 "대기" 상태로 텅 비어 보이지 않도록, 이전 실행에서 이미 저장된
    # oath_energy_data.json 내용으로 초기 화면을 채운다 (2026-07-08 추가 - 사용자 요청:
    # "화면에서 데이터 저장된 현황을 보여주도록 해야해"). 새 이벤트가 오기 전까지는
    # 이 스냅샷이 그대로 유지된다.
    try:
        initial_store = CharacterStore()
        initial_id = initial_store.most_recent_oath_entity_id()
        if initial_id is not None:
            render_record(initial_store.data.get(str(initial_id), {}))
    except Exception:
        pass  # 저장 파일이 없거나 읽기 실패해도 GUI 자체는 정상적으로 뜨도록 조용히 무시

    def poll_queue():
        try:
            while True:
                ev = event_queue.get_nowait()
                record = getattr(ev, "record", None)
                if record:
                    render_record(record)
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
