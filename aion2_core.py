"""
AION2 오드에너지 실시간 파서 - 핵심 로직 (네트워크 캡처와 무관한 순수 파싱 부분).

프로토콜 요약 (TK-open-public/Aion2-Dps-Meter 소스 분석 + 실제 캡처 2회 교차검증으로 확정):
  - 프레임: [varint 길이][opcode 2바이트][payload...]
    실제길이 = varint값 + varint바이트수 - 4
  - 압축: opcode 자리에 FF FF 가 오면 LZ4 raw block 압축. 그 뒤 4바이트(LE)가 압축해제 후
    원본 길이, 그 다음이 LZ4 데이터. 압축 해제한 버퍼는 다시 같은 프레임 형식이 재귀적으로 들어있음.
  - 오드에너지 opcode = (0x0C, 0x61). 두 가지 서브타입 확인됨:
      "증가" (아이템 사용): 01 08 01 [varint id] [varint 새총량] [flag=01] [int32 LE 증가량] (13바이트)
      "감소" (던전 소모 등): 00 08 01 [varint id] [varint 새총량] [1바이트, 의미 미상]        (9바이트, delta 없음)
    id(51591)는 모든 캡처에서 동일 - 캐릭터/세션 고정값으로 추정. "감소" 타입은 delta 필드가 없어서
    직접 델타 값을 알 수 없고, 호출측이 이전에 알던 총량과의 차이로 계산해야 함 (parse_oath_energy_payload
    는 이 경우 delta=None 을 반환).
  - 로그인 시점 절대값 스냅샷 opcode = (0x0B, 0x61). 캐릭터가 월드에 들어올 때(로딩 완료 시점) 1회 오는
    "전체 스탯 동기화" 패킷이며, 그 안에 오드에너지의 로그인 시점 절대값이 들어있다 (999.pcapng로 검증:
    확인).
"""

import struct
import lz4.block

OATH_ENERGY_OPCODE = (0x0C, 0x61)
OWN_NICKNAME_OPCODE = (0x33, 0x36)  # 참고: TK-open-public/Aion2-Dps-Meter PropertyHandler.kt searchOwnNickname
OWN_STATS_SNAPSHOT_OPCODE = (0x0B, 0x61)  # 로그인/월드 진입 시 1회 오는 "전체 스탯 동기화" 패킷
COMBAT_POWER_OPCODE = (0x56, 0x36)  # 전투력 갱신 패킷 (2026-07-08, "전투력 변화 캡쳐.pcapng"로 확인)
ITEM_LEVEL_OPCODE = (0x1D, 0x56)  # 템레벨 갱신 패킷 (2026-07-19, "활성성 템레벨 5529 테스트.pcapng"로 확인)


class VarInt:
    __slots__ = ("value", "length")

    def __init__(self, value, length):
        self.value = value
        self.length = length


def read_varint(b: bytes, offset: int = 0) -> VarInt:
    value = 0
    shift = 0
    count = 0
    while True:
        if offset + count >= len(b):
            return VarInt(-1, -1)
        byte_val = b[offset + count]
        count += 1
        value |= (byte_val & 0x7F) << shift
        if (byte_val & 0x80) == 0:
            return VarInt(value, count)
        shift += 7
        if shift >= 32:
            return VarInt(-1, -1)


def _encode_varint(value: int) -> bytes:
    """`read_varint`의 인코딩을 그대로 반대로 - 특정 known_id를 페이로드에서 정확히 바이트
    매칭으로 찾을 때 씀 (2026-07-18 추가, `parse_own_stats_snapshot_payload`의 세 번째 형태
    검색에서 사용)."""
    out = bytearray()
    v = value
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


class OathEnergyEvent:
    def __init__(self, entity_id, new_total, delta, raw_packet, arrived_at=None):
        self.entity_id = entity_id
        self.new_total = new_total
        self.delta = delta  # None 이면 이 패킷엔 delta 필드가 없었다는 뜻 (호출측에서 이전 값과 비교해 계산)
        self.raw_packet = raw_packet
        self.arrived_at = arrived_at

    def __repr__(self):
        if self.delta is None:
            delta_str = "?"
        else:
            sign = "+" if self.delta >= 0 else ""
            delta_str = f"{sign}{self.delta}"
        return f"<OathEnergy id={self.entity_id} total={self.new_total} delta={delta_str}>"


def _is_plausible_oath_energy(value):
    """파싱된 total 값이 오드에너지로서 그럴듯한지 검증.

    opcode (0x0C,0x61)/(0x0B,0x61) 이 다른 종류의 패킷에 재사용되는 경우
    (실제로 OwnNickname opcode(0x33,0x36)가 다른 용도로도 쓰이는 걸 이미 한 번 확인한 바 있음),
    구조 자체는 그럴듯해 보여도 실제로는 오드에너지가 아닌 엉뚱한 값을 파싱하게 된다.

    **정정 (2026-07-08): 0을 걸러내면 안 된다.** 원래는 "지금까지 확인된 모든 실제값은
    1000~1700대였고 0이었던 적은 한 번도 없었다"는 관찰을 근거로 `0 < value`로 0을 걸러냈는데,
    이건 표본이 적어서 생긴 잘못된 가정이었다 - 캐릭터 "활성성"은 왼쪽 숫자(base)가 원래 0이고
    오른쪽 숫자(dynamic)도 다 써서 총 오드에너지가 진짜 0인 상태가 있는데, 이 경우 접속 시
    로그인 스냅샷(parse_own_stats_snapshot_payload)의 total(=0)이 여기서 걸러지면서 오드에너지
    갱신 자체가 아예 인식되지 않는 버그가 있었다 (사용자 실측: "활성성만 캐릭터 접속할때
    오드에너지 갱신이 안되는데... 수치가 0이면 인식을 못하는거 같기도하고"). 그래서 이제 0은
    허용하고, 음수(varint 오독/구조 불일치로만 나올 수 있음)만 걸러낸다. 위쪽 한도는 varint
    오독으로 나올 수 있는 터무니없이 큰 값만 걸러내는 넉넉한 안전판(실제 최대치를 모르므로 낮게
    잡지 않음).
    """
    return 0 <= value <= 50_000_000


def parse_oath_energy_payload(payload: bytes):
    """opcode(0x0C,0x61) 뒤의 payload 를 파싱. 실패하면(또는 구조/값이 의심스러우면) None 리턴.

    **중요 (2026-07-07 재정정): 이 이벤트의 new_total 은 "총 소지 오드에너지"가 아니라 그 중
    "사용/획득 누적분"(오른쪽 숫자) 만을 가리키는 것으로 보인다.** 실제 게임 UI는 오드에너지를
    "왼쪽 숫자(정기 충전분, 02시부터 3시간마다 +10/+15) + 오른쪽 숫자(아이템/던전 등으로 늘고 주는 분)"
    두 부분의 합으로 표시하는데(사용자가 궁예성/성령성/마술성 3개 캐릭터로 확인: 240+25=265,
    240+375=615, 385+200=585), 왼쪽 숫자는 이 opcode 에는 안 나오고 로그인 스냅샷 opcode(0x0B,0x61)
    에서만 나온다 (parse_own_stats_snapshot_payload 참고). 그동안 테스트 캐릭터 "활성성"은 왼쪽 숫자가
    우연히 0이어서(0 + 오른쪽 = 오른쪽) 이 값을 총량으로 착각해도 문제가 없었을 뿐이다.
    호출측(aion2_live_monitor.py)이 "왼쪽 숫자"(known_base, 로그인 스냅샷에서만 얻을 수 있음)를
    따로 들고 있다가 이 이벤트의 new_total 과 더해서 진짜 총량을 계산해야 한다.

    헤더의 2번째 바이트(header1)가 "값이 몇 개 들어있는지"를 가리킨다 - 로그인 스냅샷 opcode의
    tag 바이트(0x04=값 1개, 0x0c=값 2개)와 동일한 규칙:
      - header1=0x08 → 값 1개(new_total만, 왼쪽/오른쪽 분리 없음) - 원래 발견된 형태:
        01 08 01 [varint id] [varint new_total] [flag=01] [int32 LE delta]   (payload 13바이트, "증가")
        00 08 01 [varint id] [varint new_total] [단일 바이트, 의미 미상]      (payload 9바이트, "감소")
      - header1=0x0c → 값 2개(v1=왼쪽 숫자/base, v2=오른쪽 숫자/dynamic, new_total=v1+v2) - **2026-07-09
        추가 발견**, "추가오드" 아이템 사용 캡처(쌍검성, 4회 연속 사용)에서 확인됨:
        01 0c 01 [varint id] [varint v1] [varint v2] [flag=01] [int32 LE delta]  ("증가"의 2값 변형)
        실측 4개 샘플 전부 v1=360(쌍검성의 실제 base와 일치, 변화 없음), v2가 125→165→205→245로
        델타(40)만큼씩 정확히 증가 - 즉 v1은 스냅샷과 마찬가지로 "왼쪽 숫자"를 매번 재확인시켜주고,
        v2는 기존 "증가" 이벤트의 new_total과 같은 의미(오른쪽 숫자). **이 변형을 놓치면 헤더가
        `01 08 01`이 아니라는 이유만으로 완전히 무시되어(사용자 실측: 콘솔에 아무 로그도 안 남음,
        `--debug` 없이는 조용히 버려짐) 해당 아이템을 쓸 때마다 오드에너지 증가가 통째로 안 잡히는
        버그가 됨 - "감소"(header0=0x00) 쪽에 2값 변형이 있는지는 아직 실측 안 됐지만, 대칭적으로
        같이 지원해둔다(값이 안 맞으면 length/plausibility 검증에서 어차피 걸러짐).**

    두 타입 모두 앞 3바이트(header0/1/2)를 확인 후 varint id로 시작한다. 그 뒤 값 varint를
    header1에 따라 1개 또는 2개 읽고, 마지막으로 header0에 따라 flag+int32 delta(증가, 5바이트)가
    남거나 의미 미상 1바이트(감소)만 남아야 한다 - 셋 중 하나라도 구조/길이/값 범위가 안 맞으면
    None을 반환해 "이 패킷엔 오드에너지 정보가 없다"고 정직하게 실패한다.

    검증 로직(2026-07-07 추가, 2026-07-09 확장): 헤더 3바이트가 정확히 `0x/08/01` 또는
    `0x/0c/01`(0x는 0x00 또는 0x01)인지, id/값(들) varint를 읽고 남은 바이트 수가 서브타입에
    딱 맞는 길이(증가=5, 감소=1)인지, 최종 total 값이 오드에너지로 그럴듯한 범위인지
    (_is_plausible_oath_energy) 까지 확인해야 이벤트로 인정한다.
    """
    if len(payload) < 3:
        return None
    header0, header1, header2 = payload[0], payload[1], payload[2]
    if header2 != 0x01 or header0 not in (0x00, 0x01):
        return None
    if header1 not in (0x08, 0x0c):
        return None
    pos = 3
    id_vi = read_varint(payload, pos)
    if id_vi.length <= 0:
        return None
    pos += id_vi.length

    v1_vi = read_varint(payload, pos)
    if v1_vi.length <= 0:
        return None
    pos += v1_vi.length

    base = None
    dynamic = None
    if header1 == 0x0c:
        # 2026-07-09 추가: 값 2개짜리 변형 - v1=왼쪽 숫자(base), v2=오른쪽 숫자(dynamic)
        v2_vi = read_varint(payload, pos)
        if v2_vi.length <= 0:
            return None
        pos += v2_vi.length
        base = v1_vi.value
        dynamic = v2_vi.value
        total = base + dynamic
    else:
        dynamic = v1_vi.value
        total = dynamic

    remaining = len(payload) - pos
    delta = None
    if header0 == 0x01:
        # "증가" 타입: flag(1바이트) + int32 LE delta(4바이트) = 정확히 5바이트가 남아야 함
        if remaining != 5:
            return None
        delta = struct.unpack_from("<i", payload, pos + 1)[0]
    else:
        # "감소" 타입: 의미 미상 1바이트만 남아야 함
        if remaining != 1:
            return None

    if not _is_plausible_oath_energy(total):
        return None

    ev = OathEnergyEvent(id_vi.value, total, delta, payload)
    if base is not None:
        # 2026-07-09 추가: 값 2개짜리 변형은 왼쪽 숫자도 같이 알려주므로, 스냅샷과 동일하게
        # .base/.dynamic 속성을 채워서 호출측(aion2_live_monitor.py)이 known_base를 갱신할 수
        # 있게 한다 - 일반 1값짜리 변형(header1=0x08)은 이 속성이 아예 없음(기존 동작 유지).
        ev.base = base
        ev.dynamic = dynamic
    return ev


def parse_own_stats_snapshot_payload(payload: bytes, known_id=None):
    """opcode(0x0B,0x61) 은 캐릭터가 월드에 들어올 때(로딩 완료 시점) 한 번 오는 자기 캐릭터의
    "전체 스탯 동기화" 패킷이다.

    **구조 재정정 (2026-07-07, 궁예성/성령성/마술성.pcapng 3건 교차검증으로 확정):** payload 안에는
    `[tag][field_id][varint entity_id][value(s)...]` 형태의 레코드가 반복되어 있다. tag 는 이 레코드가
    값을 몇 개 담는지를 뜻하는 것으로 보인다 - `tag=0x04` 이면 단일 varint 값 1개, `tag=0x0c` 이면
    varint 값 2개. field_id=1 (오드에너지) 레코드는 `tag=0x0c` 타입이라 값이 **2개**(v1, v2) 들어있고,
    실제 게임 UI가 "왼쪽 숫자(v1, 정기 충전분) + 오른쪽 숫자(v2, 아이템/던전 등 누적분)"으로 표시하는
    총 오드에너지는 이 둘의 **합**이다. 3개 캐릭터로 정확히 검증됨: 궁예성 v1=240,v2=25→265,
    성령성 v1=240,v2=375→615, 마술성 v1=385,v2=200→585.

    (예전엔 `00 08 01` 3바이트를 찾아 값 1개만 읽는 방식이었음 - 999.pcapng 에서 우연히 total=1370과
    맞아떨어져서 "검증됨"으로 잘못 확정했었는데, 실제로는 field_id=1 레코드의 진짜 헤더가 아니라
    페이로드 어딘가에서 우연히 일치한 다른 바이트열이었을 가능성이 높다 - 888888.pcapng 에서 그 방식이
    안 통했던 것도(그때는 "예외"로 취급했었음) 사실은 그 캡처가 그냥 `0c 01` 정상 구조였기 때문일 것.
    테스트 캐릭터 "활성성"은 왼쪽 숫자(v1)가 우연히 0이라 값 1개짜리 방식으로도 총량이 맞아떨어져서
    이 오류가 그동안 드러나지 않았다.)

    반환하는 OathEnergyEvent 는 `.new_total`에 v1+v2 합계(진짜 총량)를 담고, 추가로 `.base`(v1, 정기
    충전분)와 `.dynamic`(v2, 누적분) 속성을 각각 담는다 - 호출측(aion2_live_monitor.py)이 `.base` 를
    따로 저장해뒀다가, 이후 오는 opcode(0x0C,0x61) 변경 이벤트(값 1개만 옴 = 그 누적분(v2)만 갱신하는
    것으로 추정)의 값과 다시 합산해서 진짜 총량을 계산하는 데 쓴다.

    **정정 (2026-07-08, 실제 "활성성 접속.pcapng" 캡처로 확인): `00 08 01` 단일값 형태도 여전히
    실제로 쓰인다 - 완전히 폐기된 게 아니었다.** 위 문단은 "우연한 오탐이었을 것"이라고 결론 냈었지만,
    활성성이 실제로 접속하는 캡처를 받아 바이트 단위로 뜯어보니 이 캐릭터의 로그인 스냅샷 field_id=1
    레코드는 `0c 01`(2값) 형태가 **아예 없고**, `00 08 01`+[varint entity_id][varint total] 단일값
    형태 **하나만** 정확히 한 번(entity_id=51591, total=780) 나타났다. 즉 "왼쪽 숫자(base)가 0인
    캐릭터는 서버가 필드 자체를 단일값 형태로 보낸다"는 게 실제 프로토콜 동작인 것으로 보인다 - 이게
    바로 예전에 "활성성은 우연히 값 1개짜리 방식으로도 맞아떨어졌다"고 잘못 해석했던 현상의 진짜 원인.
    그래서 이제 `0c 01`(2값, base+dynamic) 검색과 `00 08 01`(1값, base=0 암묵적) 검색을 **둘 다** 하고
    두 결과를 합쳐서 후보로 삼는다. `known_id`와 일치하는 후보가 있으면 그걸 우선 채택하고, 없으면
    (콜드스타트) 처음 찾은 후보를 채택한다 - 이 경우 콜백측의 2차 신뢰 검증(aion2_live_monitor.py)에서
    한 번 더 걸러질 수 있다. 후보가 하나도 없으면 None 을 반환해 "이 패킷엔 오드에너지 정보가 없다"고
    정직하게 실패한다 (기존 폴백 동작 유지). `00 08 01`은 흔한 3바이트열이라 오탐 가능성이 여전히
    있으므로, 이 형태로 찾은 후보는 known_id와 일치할 때만 신뢰하도록 호출측에서 추가 검증하는 게
    안전하다 (aion2_live_monitor.py의 `_is_trusted_oath_event`가 이미 델타 없는 이벤트에 대해 이
    역할을 하고 있음 - 로그인 스냅샷은 delta=None 이라 그 검증을 그대로 통과함).

    **세 번째 형태 추가 (2026-07-18, "살육성 기본오드15/30 추가오드0 테스트.pcapng" 2건 +
    "살육성 오드0 실험.pcapng"와의 3점 비교로 확정):** dynamic(추가오드)=0인 캐릭터는 위 두
    마커 자리에 아무것도 없고, 대신 known_id의 varint 바이트열 바로 앞에 판별 바이트가 붙는
    전혀 다른 레코드를 쓴다 - `[판별=0x00][0x01][varint id][단일 값(정체불명 상수, 실측 항상
    4, base와 무관)]`(base=0 암묵적) 또는 `[판별=0x04][0x01][varint id][varint base][그 상수]`
    (base=15/30으로 각각 정확히 일치 확인). dynamic은 이 레코드로는 알 수 없어 0으로 둔다 -
    dynamic이 0이 아니면서 이 형태를 쓰는 조합은 아직 관측된 적 없다(그 경우는 (1)번 `0c 01`
    마커가 정상 커버하는 것으로 보임 - 궁예성/마술성/성령성 모두 dynamic≠0이었고 그걸로 인식됨).
    오탐 방지를 위해 known_id가 있을 때만(정확한 varint 바이트 일치로 앵커링) 검색한다 -
    known_id 없는 콜드스타트에선 이 형태를 못 잡는다(Seventeenth bug의 "완전히 0" 폴백과
    동일한 한계).
    """
    candidates = []

    # (1) 2값 형태: base(v1) + dynamic(v2), 둘 다 varint로 명시됨
    marker_double = b"\x0c\x01"
    search_start = 0
    while True:
        idx = payload.find(marker_double, search_start)
        if idx == -1:
            break
        pos = idx + 2
        id_vi = read_varint(payload, pos)
        if id_vi.length > 0:
            pos2 = pos + id_vi.length
            v1 = read_varint(payload, pos2)
            if v1.length > 0:
                pos3 = pos2 + v1.length
                v2 = read_varint(payload, pos3)
                if v2.length > 0:
                    total = v1.value + v2.value
                    if _is_plausible_oath_energy(total):
                        candidates.append((id_vi.value, v1.value, v2.value, total))
        search_start = idx + 1

    # (2) 1값 형태: base가 0이라 서버가 그냥 생략하고 total(=dynamic) 하나만 보낸 경우
    #     (2026-07-08 추가, 활성성 실제 캡처로 확인 - 위 docstring 정정 참고)
    marker_single = b"\x00\x08\x01"
    search_start = 0
    while True:
        idx = payload.find(marker_single, search_start)
        if idx == -1:
            break
        pos = idx + 3
        id_vi = read_varint(payload, pos)
        if id_vi.length > 0:
            pos2 = pos + id_vi.length
            total_vi = read_varint(payload, pos2)
            if total_vi.length > 0:
                if _is_plausible_oath_energy(total_vi.value):
                    candidates.append((id_vi.value, 0, total_vi.value, total_vi.value))
        search_start = idx + 1

    # (3) 2026-07-18 추가: dynamic(추가오드)=0인 캐릭터가 쓰는 세 번째 형태 - "살육성 기본오드15
    # 추가오드0 테스트.pcapng"/"...기본오드30..." 두 캡처를 "완전히 0"인 캡처(Seventeenth bug
    # 섹션 참고)와 3점 비교로 확정. 이 형태는 위 두 마커(`0c 01`, `00 08 01`)가 있는 자리가
    # 아니라 known_id의 varint 바이트열 바로 앞에 "판별 바이트"가 붙는 별도 레코드다:
    #   판별 바이트=0x00 → `[0x00][0x01][varint id][단일 값]` - 뒤따르는 단일 값은 실측 3회
    #     모두 4로 고정(무슨 필드인지 불명, base와 무관 - 무시), base는 이 형태에선 암묵적 0.
    #   판별 바이트=0x04 → `[0x04][0x01][varint id][varint base][단일 값]` - 첫 번째 값이
    #     base(실측: 15, 30 정확히 일치), 두 번째 값은 역시 그 정체불명 상수 4(무시).
    # dynamic은 이 레코드에서 전혀 알 수 없다 - 실측 3회 전부 dynamic=0인 경우만 확인됐으므로
    # 0으로 둔다. dynamic이 0이 아니면서 이 판별-바이트 형태를 쓰는 조합은 아직 관측된 적
    # 없다(다른 조합에선 기존 (1)번 `0c 01` 2값 마커가 그대로 쓰이는 것으로 보임 - 궁예성/
    # 마술성/성령성 캡처 모두 dynamic이 0이 아니었고 그 마커로 정상 인식됐음).
    # known_id가 있을 때만 검색한다 - `\x01` 단일 바이트는 페이로드에 흔해서 known_id의 정확한
    # varint 바이트열과 함께 앵커링하지 않으면 오탐 위험이 큼(1값 형태의 `00 08 01`이 겪었던
    # 것과 같은 종류의 위험, 위 (2)번 주석 참고).
    if known_id is not None:
        id_bytes = _encode_varint(known_id)
        marker_disc = b"\x01" + id_bytes
        search_start = 0
        while True:
            idx = payload.find(marker_disc, search_start)
            if idx == -1:
                break
            if idx > 0:
                discriminator = payload[idx - 1]
                pos = idx + len(marker_disc)
                if discriminator == 0x04:
                    base_vi = read_varint(payload, pos)
                    if base_vi.length > 0 and _is_plausible_oath_energy(base_vi.value):
                        candidates.append((known_id, base_vi.value, 0, base_vi.value))
                elif discriminator == 0x00:
                    candidates.append((known_id, 0, 0, 0))
            search_start = idx + 1

    if not candidates:
        # 2026-07-18 추가: 오드에너지가 완전히 0(기본=0, 추가=0)인 캐릭터의 실제 캡처("살육성
        # 오드0 실험.pcapng", 게임 UI 확인 0/840)로 확인된 세 번째 케이스 - 기본/추가 둘 다 0이면
        # 서버가 field_id=1 레코드 자체를 payload에서 통째로 생략한다(2값 마커도 1값 마커도 전혀
        # 없음). 예전엔 이 경우 후보가 하나도 없으니 그냥 None을 반환해서 "이 스냅샷엔 오드에너지
        # 정보가 없다"고 정직하게 실패했는데, 그 결과 on_oath_energy 콜백 자체가 안 불려서 이
        # 캐릭터는 오드에너지 필드가 영원히 갱신되지 않는(GUI에 "-"로 남거나 이전 값이 그대로
        # 남는) 버그였다(사용자 실측: "인식을 못하는듯"). known_id(이미 확인된 계정 공용
        # entity_id)가 있으면 그 id로 "명시적 0" 이벤트를 만들어 반환한다 - 필드 생략 = 0이라는
        # 해석은 이 하나의 실측 사례에만 근거하므로 계속 재검증 필요(특히 "추가는 0인데 기본은
        # 0이 아닌" 케이스가 별도 마커를 쓰는지 아니면 이것도 똑같이 생략되는지는 아직 미확인).
        # known_id가 아예 없으면(콜드스타트) 이 id를 어느 캐릭터 것으로 볼지 알 방법이 없으므로
        # 기존과 동일하게 None을 반환한다(신규 배포 대상 첫 실행 때는 여전히 못 잡음 - 기존
        # 콜드스타트 제약과 동일선상).
        if known_id is not None:
            ev = OathEnergyEvent(known_id, 0, None, payload)
            ev.is_snapshot = True
            ev.base = 0
            ev.dynamic = 0
            return ev
        return None

    chosen = None
    if known_id is not None:
        for cand in candidates:
            if cand[0] == known_id:
                chosen = cand
                break
    if chosen is None:
        chosen = candidates[0]

    entity_id, base, dynamic, total = chosen
    ev = OathEnergyEvent(entity_id, total, None, payload)
    ev.is_snapshot = True
    ev.base = base
    ev.dynamic = dynamic
    return ev


class CombatPowerEvent:
    def __init__(self, combat_power, raw_packet, arrived_at=None):
        self.combat_power = combat_power
        self.raw_packet = raw_packet
        self.arrived_at = arrived_at

    def __repr__(self):
        return f"<CombatPower {self.combat_power}>"


def parse_combat_power_payload(payload: bytes):
    """opcode(0x56,0x36) 전투력 갱신 패킷 파싱.

    **구조 (2026-07-08, "전투력 변화 캡쳐.pcapng"로 확인):** payload 는 정확히 16바이트,
    8바이트 LE 정수 2개로 구성됨 - `[전투력(8바이트 LE)][?(8바이트 LE)]`. 값이 항상
    32비트 범위 안이라 상위 4바이트는 늘 0으로 관측됨(4바이트 LE로 읽어도 같은 값).

    앞쪽 8바이트가 "본인 전투력"임을 사용자가 직접 확인: 같은 장비 하나를 뺐다 꼈다 4번
    반복하는 캡처에서, 앞쪽 값만 331622 -> 331022 -> 345022 -> 345622 로 바뀌는 게 관측됐고
    (장비 탈부착에 반응해서 실시간으로 재계산됨), 뒤쪽 8바이트는 캡처 내내 345622 로 고정이었음
    (전투력과 무관한 다른 필드로 추정, 아직 의미 미상 - 무시).

    이 패킷엔 entity_id 필드가 없음 - 오드에너지 opcode(0x0C,0x61)와 달리 항상 "본인" 것으로
    간주하고, 호출측(aion2_live_monitor.py)이 현재 추적 중인 오드에너지 entity_id에 붙여서
    저장한다 (닉네임 처리와 동일한 패턴).
    """
    if len(payload) != 16:
        return None
    value = struct.unpack_from("<Q", payload, 0)[0]
    if not (0 < value <= 2_000_000_000):  # 전투력이 20억을 넘을 일은 없다고 보고 넉넉히 잡은 안전판
        return None
    return CombatPowerEvent(value, payload)


class ItemLevelEvent:
    def __init__(self, item_level, raw_packet, arrived_at=None):
        self.item_level = item_level
        self.raw_packet = raw_packet
        self.arrived_at = arrived_at

    def __repr__(self):
        return f"<ItemLevel {self.item_level}>"


def parse_item_level_payload(payload: bytes):
    """opcode(0x1D,0x56) 템레벨(장비 레벨) 패킷 파싱 (2026-07-19 발견).

    **구조:** payload는 정확히 8바이트, 4바이트 LE 정수 2개로 구성됨 -
    `[템레벨(4바이트 LE)][템레벨(4바이트 LE), 동일값 중복]`. 사용자가 업로드한
    "활성성 템레벨 5529 테스트.pcapng"(게임 UI에 표시된 실측값 5529)를 브루트포스로
    스캔해서 찾음 - combat_power 발견 때와 같은 방법(모든 leaf frame의 모든 바이트
    offset에서 varint/고정폭 LE 해석을 시도해 알고 있는 참값과 일치하는 지점을 찾음).
    같은 캡처 안에서 opcode(0x33,0x36)(OwnNickname, "활성성" 캐릭터 정보 큰 패킷으로
    재사용된 형태)의 페이로드 안에도 offset 28/32에 5529가 연속으로 두 번 나오는 걸
    확인했지만(자세한 내용은 memory 참고), 이 opcode(0x1D,0x56)는 오직 이 값만 담는
    작고 전용인 8바이트 페이로드라 훨씬 신뢰도 높은 추출 지점으로 판단해 이걸 채택함
    (전투력(0x56,0x36)이 자기만의 작은 전용 opcode를 갖는 것과 같은 패턴).

    이 패킷도 combat_power와 마찬가지로 entity_id 필드가 없음 - 항상 "본인" 것으로
    간주하고, 호출측이 현재 추적 중인 오드에너지 entity_id에 붙여서 저장한다(같은
    이유로 캐릭터 전환 시 오염 방지 로직도 combat_power와 동일하게 적용 - 자세한 내용은
    aion2_live_monitor.py의 _on_item_level 참고).

    **주의: 아직 실측 캡처 1건으로만 확인됨 - 두 번째 독립 캡처(다른 템레벨 값)로
    교차검증 안 됨.** 이 프로젝트의 원칙("단일 캡처 검증은 잠정적으로만 신뢰")에 따라,
    다른 템레벨 값을 가진 캐릭터의 캡처가 생기면 재검증할 것.
    """
    if len(payload) != 8:
        return None
    value = struct.unpack_from("<I", payload, 0)[0]
    if not (0 < value <= 100_000):  # 템레벨이 10만을 넘을 일은 없다고 보고 넉넉히 잡은 안전판
        return None
    return ItemLevelEvent(value, payload)


class NicknameEvent:
    def __init__(self, entity_id, nickname, server, job, arrived_at=None):
        self.entity_id = entity_id
        self.nickname = nickname
        self.server = server
        self.job = job
        self.arrived_at = arrived_at

    def __repr__(self):
        return f"<Nickname id={self.entity_id} name={self.nickname!r} server={self.server} job={self.job}>"


def _find_byte(data: bytes, target: int) -> int:
    for i, b in enumerate(data):
        if b == target:
            return i
    return -1


def _is_valid_nickname(s: str) -> bool:
    has_korean_or_english = any(
        ("가" <= ch <= "힣") or ("a" <= ch <= "z") or ("A" <= ch <= "Z")
        for ch in s
    )
    all_valid = all(
        ("가" <= ch <= "힣") or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch.isdigit()
        for ch in s
    )
    return has_korean_or_english and all_valid


def parse_own_nickname_packet(packet: bytes, length_info_length: int):
    """opcode(0x33,0x36) "OwnNickname" 프레임 파싱. 실패하면 None.

    최초에는 TK-open-public/Aion2-Dps-Meter의 PropertyHandler.kt::searchOwnNickname (0x07 바이트를
    찾아서 그 뒤가 닉네임이라고 가정하는 방식)을 그대로 포팅했으나, 실제 캡처 2건(다른 세션, 같은 캐릭터)
    에서 검증해보니 그 가정이 지금 게임 버전과는 안 맞았다 - 두 캡처 모두 0x07 바이트가 프리앰블에
    존재하지 않았다. 대신 실제 바이트를 직접 비교해서(두 세션에서 프리앰블 값 `5f ?? eb 08 37` 이
    거의 동일하게 반복되는 것을 확인) 아래처럼 **고정 5바이트 프리앰블**이라는 걸 확인했고, 이 방식으로
    두 세션 모두에서 닉네임("활성성"), 서버(1002), job(14)이 정확히 동일하게 나오는 것으로 검증 완료.

    구조: [opcode 2바이트][varint entity_id][고정 5바이트, 의미 미상][varint 닉네임길이][UTF-8 닉네임]
          [uint16 LE server][uint8 job]

    주의: 여기서 entity_id 는 세션마다 값이 달라지는 작은 임시 id (예: 2445, 6773 - OtherNickname 의
    entity_id 와 같은 부류, 190~15000대 범위)이고, 오드에너지 패킷의 entity_id(예: 51591, 세션이 바뀌어도
    동일했음)와는 완전히 다른 id 공간이다. 즉 이 둘을 숫자로 직접 매칭할 수 없다 - "같은 접속 세션 동안
    관측된 닉네임을 그 세션의 오드에너지 entity_id 에 붙여준다"는 시간적 연관으로 매칭해야 한다
    (aion2_live_monitor.py 의 LiveCapture.current_nickname 참고).
    """
    offset = length_info_length
    if offset + 1 >= len(packet):
        return None
    if packet[offset] != 0x33 or packet[offset + 1] != 0x36:
        return None
    offset += 2
    if len(packet) < offset:
        return None

    user_info = read_varint(packet, offset)
    if user_info.length < 0:
        return None
    offset += user_info.length

    offset += 5  # 고정 프리앰블 (경험적으로 확인됨, 의미 미상)
    if offset >= len(packet):
        return None

    name_length_info = read_varint(packet, offset)
    if name_length_info.length <= 0:
        return None
    if name_length_info.value < 1 or name_length_info.value > 71:
        return None
    offset += name_length_info.length
    if len(packet) < offset + name_length_info.value:
        return None

    name_bytes = packet[offset:offset + name_length_info.value]
    try:
        nickname = name_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _is_valid_nickname(nickname):
        return None

    offset += name_length_info.value
    server = -1
    job = -1
    if len(packet) >= offset + 2:
        server = struct.unpack_from("<H", packet, offset)[0]
        offset += 2
        if len(packet) >= offset + 1:
            job = packet[offset]

    return NicknameEvent(user_info.value, nickname, server, job)


class StreamProcessor:
    """varint 길이 프레임 + LZ4 압축 해제 + opcode 디스패치.
    오드에너지 opcode 를 만나면 on_oath_energy 콜백을 호출한다.
    """

    def __init__(self, on_oath_energy=None, on_nickname=None, on_unknown=None, get_known_oath_id=None,
                 on_combat_power=None, on_item_level=None):
        self.on_oath_energy = on_oath_energy
        self.on_nickname = on_nickname
        self.on_unknown = on_unknown
        self.on_combat_power = on_combat_power  # 2026-07-08 추가: 전투력 갱신 콜백
        self.on_item_level = on_item_level  # 2026-07-19 추가: 템레벨 갱신 콜백
        # 2026-07-07 추가: 로그인 스냅샷(0x0B,0x61) 파싱 시 "이전에 확인된 진짜 오드에너지 entity_id"를
        # 물어보기 위한 콜백 (parse_own_stats_snapshot_payload 의 known_id 힌트로 전달됨).
        self.get_known_oath_id = get_known_oath_id

    def on_packet_received(self, packet: bytes, arrived_at=None):
        if len(packet) == 3:
            return
        length_info = read_varint(packet)
        if length_info.length <= 0:
            return
        if length_info.length >= len(packet):
            return

        extra_flag = 0xF0 <= packet[length_info.length] < 0xFF

        if extra_flag:
            if (length_info.length + 2 < len(packet)
                    and packet[length_info.length + 1] == 0xFF
                    and packet[length_info.length + 2] == 0xFF):
                self._decompress_packet(packet, length_info.length, True, arrived_at)
                return
        else:
            if (length_info.length + 1 < len(packet)
                    and packet[length_info.length] == 0xFF
                    and packet[length_info.length + 1] == 0xFF):
                self._decompress_packet(packet, length_info.length, False, arrived_at)
                return

        opcode_offset = length_info.length + (1 if extra_flag else 0)
        if opcode_offset + 1 >= len(packet):
            return

        b1 = packet[opcode_offset]
        b2 = packet[opcode_offset + 1]
        payload = packet[opcode_offset + 2:]

        if (b1, b2) == OATH_ENERGY_OPCODE:
            ev = parse_oath_energy_payload(payload)
            if ev is not None:
                ev.arrived_at = arrived_at
                if self.on_oath_energy:
                    self.on_oath_energy(ev)
            elif self.on_unknown:
                # 검증 로직(구조/값 검사)에서 걸러진 경우도 포함 - opcode는 같지만 실제로는
                # 오드에너지 정보가 없는 패킷이었다는 뜻. --debug 로 확인 가능하게 알림.
                self.on_unknown((b1, b2), packet, arrived_at)
        elif (b1, b2) == OWN_NICKNAME_OPCODE:
            nick_ev = parse_own_nickname_packet(packet, length_info.length)
            if nick_ev is not None:
                nick_ev.arrived_at = arrived_at
                if self.on_nickname:
                    self.on_nickname(nick_ev)
            elif self.on_unknown:
                self.on_unknown((b1, b2), packet, arrived_at)
        elif (b1, b2) == OWN_STATS_SNAPSHOT_OPCODE:
            known_id = self.get_known_oath_id() if self.get_known_oath_id else None
            snap_ev = parse_own_stats_snapshot_payload(payload, known_id=known_id)
            if snap_ev is not None:
                snap_ev.arrived_at = arrived_at
                if self.on_oath_energy:
                    self.on_oath_energy(snap_ev)
            elif self.on_unknown:
                self.on_unknown((b1, b2), packet, arrived_at)
        elif (b1, b2) == COMBAT_POWER_OPCODE:
            cp_ev = parse_combat_power_payload(payload)
            if cp_ev is not None:
                cp_ev.arrived_at = arrived_at
                if self.on_combat_power:
                    self.on_combat_power(cp_ev)
            elif self.on_unknown:
                self.on_unknown((b1, b2), packet, arrived_at)
        elif (b1, b2) == ITEM_LEVEL_OPCODE:
            il_ev = parse_item_level_payload(payload)
            if il_ev is not None:
                il_ev.arrived_at = arrived_at
                if self.on_item_level:
                    self.on_item_level(il_ev)
            elif self.on_unknown:
                self.on_unknown((b1, b2), packet, arrived_at)
        elif self.on_unknown:
            self.on_unknown((b1, b2), packet, arrived_at)

    def _decompress_packet(self, packet: bytes, header_length: int, extra_flag: bool, arrived_at=None):
        try:
            offset = header_length + 2
            if extra_flag:
                offset += 1
            if offset + 4 > len(packet):
                return
            origin_length = struct.unpack_from("<I", packet, offset)[0]
            offset += 4
            compressed = packet[offset:]
            restored = lz4.block.decompress(compressed, uncompressed_size=origin_length)

            inner_offset = 0
            while inner_offset < len(restored):
                past = inner_offset
                length_info = read_varint(restored, inner_offset)
                if length_info.value == 0:
                    inner_offset += 1
                    continue
                if length_info.length <= 0:
                    break
                real_length = length_info.value + length_info.length - 4
                if real_length <= 0:
                    break
                if past + real_length > len(restored):
                    break
                self.on_packet_received(restored[past:past + real_length], arrived_at)
                inner_offset += real_length
        except Exception:
            pass


class PacketAccumulator:
    def __init__(self):
        self.buf = bytearray()

    def append(self, data: bytes):
        self.buf += data

    def peek(self, length: int) -> bytes:
        return bytes(self.buf[:length])

    def slice(self, start: int, length: int) -> bytes:
        return bytes(self.buf[start:start + length])

    def discard_bytes(self, length: int):
        del self.buf[:length]

    @property
    def size(self):
        return len(self.buf)


class StreamAssembler:
    """이미 seq 순서대로 정렬/중복제거된 바이트 청크를 받아 프레임 단위로 잘라
    StreamProcessor 에 넘긴다."""

    def __init__(self, processor: StreamProcessor):
        self.processor = processor
        self.buffer = PacketAccumulator()

    def process_chunk(self, chunk: bytes, arrived_at=None):
        self.buffer.append(chunk)

        while self.buffer.size > 0:
            header = self.buffer.peek(8)
            if len(header) == 0:
                return

            length_info = read_varint(header)
            if length_info.value == 0:
                self.buffer.discard_bytes(1)
                continue
            if length_info.value == -1:
                if self.buffer.size < 8:
                    return
                self.buffer = PacketAccumulator()
                break

            real_length = length_info.value + length_info.length - 4
            if real_length <= 0:
                self.buffer = PacketAccumulator()
                break

            if self.buffer.size < real_length:
                return

            packet = self.buffer.slice(0, real_length)
            self.processor.on_packet_received(packet, arrived_at)
            self.buffer.discard_bytes(real_length)


class LiveTcpReassembler:
    """실시간 캡처용: TCP seq 번호 기준으로 들어오는 순서가 뒤섞여도 버퍼링했다가
    연속된 만큼만 순서대로 StreamAssembler 에 흘려보낸다. 재전송(중복 seq)은 무시.
    """

    def __init__(self, assembler: StreamAssembler):
        self.assembler = assembler
        self.next_seq = None
        self.pending = {}

    def feed(self, seq: int, payload: bytes, arrived_at=None):
        if not payload:
            return
        if self.next_seq is None:
            self.next_seq = seq

        if seq < self.next_seq:
            # 이미 처리한 구간과 겹치는 재전송. 겹치지 않는 뒷부분만 있으면 그것만 취한다.
            overlap = self.next_seq - seq
            if overlap < len(payload):
                seq = self.next_seq
                payload = payload[overlap:]
            else:
                return  # 완전 중복, 버림

        self.pending[seq] = (payload, arrived_at)

        # 연속된 만큼 드레인
        while self.next_seq in self.pending:
            data, ts = self.pending.pop(self.next_seq)
            self.assembler.process_chunk(data, ts)
            self.next_seq += len(data)

        # 너무 오래된(이미 지나간) 잔여 항목 정리
        stale = [s for s in self.pending if s < self.next_seq]
        for s in stale:
            del self.pending[s]
