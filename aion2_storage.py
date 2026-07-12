"""
캐릭터별 오드에너지 데이터를 로컬 JSON 파일에 저장하는 간단한 저장소.

프로젝트 로드맵의 "1차 구조"(로컬 저장 + 로컬 웹 대시보드) 중 저장 부분 담당.
나중에 만들 대시보드 페이지가 이 JSON 파일을 그대로 읽어서 보여줄 예정이므로,
스키마를 함부로 바꾸지 말고 필드를 추가하는 방향으로만 확장할 것.

**스키마 키 변경 (2026-07-08): entity_id 대신 닉네임(nickname)으로 키를 잡는다.**
원래는 `entity_id`(문자열 변환)를 키로 썼는데, 실제 캡처들로 확인해보니 entity_id는
"캐릭터별 고유값"이 아니라 "이 계정/슬롯의 고정값"이었다(궁예성/마술성/성령성이 전부
entity_id=51591을 공유) - 그래서 entity_id로 키를 잡으면 계정 하나당 레코드 하나만 남고
캐릭터를 바꿀 때마다 그 하나뿐인 레코드가 새 캐릭터 데이터로 덮어써졌다(사용자 실측:
"JSON 구조가 좀 이상해 하나의 data만 계속 갱신하도록되어있는것 같아"). 닉네임은 실제로
캐릭터를 유일하게 식별하므로 이제 닉네임을 기본 키로 쓴다. entity_id는 각 레코드 안에
참고용 필드로만 남아있다 (여러 캐릭터가 같은 entity_id를 공유할 수 있음, 유일성 보장 없음).

패킷 순서상 오드에너지/전투력 데이터가 닉네임보다 먼저 도착하는 문제(캐릭터 접속 시
5~6초 텀) 때문에, "아직 닉네임을 모르는 entity_id"의 데이터를 저장소에 바로 쓸 수 없다.
이 경우 호출측(aion2_live_monitor.py)이 자체적으로 메모리에 들고 있다가(entity_nickname/
pending_oath 딕셔너리), 닉네임이 확인되는 순간 병합해서 저장소에 반영한다 - 저장소 자체는
"닉네임이 확정된 데이터만 받는다"는 단순한 계약을 유지한다.

스키마 (oath_energy_data.json):
{
  "<nickname>": {
    "nickname": str,
    "entity_id": int | null,          # 마지막으로 확인된 entity_id (참고용, 계정 공용이라
                                       # 여러 캐릭터가 같은 값을 가질 수 있음 - 유일 식별자 아님)
    "server": int | null,
    "job": int | null,
    "oath_energy": int | null,        # 총 소지량 = oath_energy_base + oath_energy_dynamic
    "oath_energy_base": int | null,   # "왼쪽 숫자" - 정기 충전분
    "oath_energy_dynamic": int | null,# "오른쪽 숫자" - 아이템/던전 등 누적분
    "last_delta": int | null,
    "last_updated": "ISO8601 문자열" | null,
    "combat_power": int | null,       # 전투력 (2026-07-08 추가, opcode(0x56,0x36))
    "combat_power_updated": "ISO8601 문자열" | null
  },
  ...
}

**2026-07-09 추가: oath_energy_base/oath_energy 에는 실측값 외에 "추정치"도 섞여 들어갈 수 있다.**
`apply_periodic_regen()` (aion2_live_monitor.py의 스케줄러가 02/05/08/11/14/17/20/23시마다 호출)이
정기 충전(+15, 왼쪽 숫자)을 실제 패킷 없이 시간 기준으로 흉내내서 이 필드들에 직접 더한다 -
사용자 요청으로 실측값과 필드 상으로는 구분하지 않는다(다음 실제 로그인/이벤트가 오면 그 값으로
덮어써지면서 자연히 보정됨).
"""

import json
import os
import sys
import datetime

# exe로 패키징(PyInstaller)했을 때 __file__ 은 매 실행마다 새로 풀리는 임시 폴더
# (sys._MEIPASS) 안을 가리켜서, 그 경로에 저장하면 껐다 켤 때마다 데이터가 사라진다.
# frozen 상태면 실행 파일(exe) 자체가 있는 폴더를 기준으로 삼는다.
if getattr(sys, "frozen", False):
    _BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_PATH = os.path.join(_BASE_DIR, "oath_energy_data.json")


class CharacterStore:
    def __init__(self, path=DEFAULT_PATH):
        self.path = path
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save(self):
        # 임시 파일에 먼저 쓰고 rename - 쓰는 도중 프로그램이 죽어도 파일이 깨지지 않게
        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, self.path)

    def _get_or_create(self, nickname):
        if nickname not in self.data:
            self.data[nickname] = {
                "nickname": nickname,
                "entity_id": None,
                "server": None,
                "job": None,
                "oath_energy": None,
                "oath_energy_base": None,
                "oath_energy_dynamic": None,
                "last_delta": None,
                "last_updated": None,
                "combat_power": None,
                "combat_power_updated": None,
            }
        return self.data[nickname]

    def update_character_info(self, nickname, entity_id=None, server=None, job=None):
        """닉네임 확인 시점에 entity_id/server/job 메타데이터만 갱신 (2026-07-08, update_nickname
        대체 - 이제 nickname이 키 자체이므로 "닉네임을 바꿔 쓰는" 개념이 없다)."""
        record = self._get_or_create(nickname)
        if entity_id is not None:
            record["entity_id"] = entity_id
        if server is not None:
            record["server"] = server
        if job is not None:
            record["job"] = job
        self._save()

    def update_oath_energy(self, nickname, new_total, delta, base=None, dynamic=None, entity_id=None):
        """new_total 은 항상 "진짜 총 소지량"(base+dynamic)이어야 한다 - 호출측
        (aion2_live_monitor.py)이 미리 합산해서 넘겨준다. base/dynamic 은 참고용으로 같이
        저장 - None 이면 그 구성요소는 이번에 갱신 안 된 것이므로 기존 저장값을 그대로 둔다.
        entity_id 는 참고용 메타데이터(2026-07-08 추가, 닉네임 키 전환에 맞춰 같이 기록).
        """
        record = self._get_or_create(nickname)
        if entity_id is not None:
            record["entity_id"] = entity_id
        if base is not None:
            record["oath_energy_base"] = base
        if dynamic is not None:
            record["oath_energy_dynamic"] = dynamic
        # 2026-07-08 수정(중요 버그): new_total 이 None 이어도 예전엔 무조건 record["oath_energy"]에
        # 덮어썼다 - 호출측(aion2_live_monitor.py)이 실수로 None을 넘기면 이미 저장돼 있던 정상적인
        # oath_energy 값이 None으로 지워지는 문제가 실측으로 확인됨(표에 "None" 표시). base/dynamic과
        # 똑같이 None이면 "이번엔 갱신 안 됨"으로 취급해 기존 값을 그대로 둔다.
        if new_total is not None:
            record["oath_energy"] = new_total
            record["last_delta"] = delta
            record["last_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        self._save()

    def update_combat_power(self, nickname, combat_power, entity_id=None):
        """전투력 갱신. 오드에너지처럼 history 를 남기진 않는다 - 필요해지면 그때 추가."""
        record = self._get_or_create(nickname)
        if entity_id is not None:
            record["entity_id"] = entity_id
        record["combat_power"] = combat_power
        record["combat_power_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        self._save()

    OATH_ENERGY_BASE_CAP = 840  # 2026-07-09 추가: 왼쪽 숫자(기본 오드)의 게임 내 한도 (사용자 확인)

    def apply_periodic_regen(self, amount):
        """2026-07-09 추가: 게임 서버의 정기 충전(02/05/08/11/14/17/20/23시, "왼쪽 숫자"에
        +10 또는 +15)을 실제 패킷 없이 우리 프로그램이 시간 기준으로 직접 흉내낸다
        (aion2_live_monitor.py의 스케줄러가 이 시각마다 호출). 사용자 요청 배경: "오랫동안
        안 들어간 캐릭터에 대해서 오드량을 예상하기 위한 것" - 실제 로그인/이벤트로 확인된 값이
        아니라 추정치이지만, 사용자가 명시적으로 "구분 없이 그냥 합산해서 json에 담아 넣어라"고
        확정했으므로 oath_energy_base/oath_energy 필드에 실측값과 구분 없이 바로 더한다.
        **주의: 이 증가분은 왼쪽 숫자(oath_energy_base)에 더해지는 것이지 오른쪽 숫자
        (oath_energy_dynamic, 추가오드/아이템 누적분)가 아니다** - 사용자가 명시적으로
        구분해달라고 확인함. last_updated는 건드리지 않는다 - most_recent_character()가
        이 값으로 "최근에 실제로 플레이한 캐릭터"를 판단하는데, 정기 충전은 전체 캐릭터에
        동시에 적용되는 이벤트라 실제 활동 시각과 혼동되면 안 된다.

        적용 대상: 저장된 모든 캐릭터(사용자 확인: "저장된 모든 캐릭터한테 적용"). 아직 한
        번도 오드에너지가 확인된 적 없는 캐릭터(oath_energy_base가 None)는 건너뛴다 - 실측값이
        전혀 없는 캐릭터에 추정치만으로 레코드를 만드는 건 오히려 혼란을 주므로.

        **2026-07-09 추가: 840 한도 적용.** 사용자 확인: "기본오드는 840이 한계". 오래 접속
        안 한 캐릭터는 이 시뮬레이션이 여러 번 누적되면서 실제 게임 서버가 절대 허용 안 하는
        840 초과 값을 만들어낼 수 있어서, oath_energy_base를 840에서 클램프한다. 이미 840에
        도달했으면 이번 틱은 실질적으로 증가분이 0(그대로 유지) - amount를 무조건 더해서
        넘치게 두지 않는다. oath_energy(총량)에는 "실제로 증가한 만큼"만 반영해서 base+dynamic
        합산 불변식이 깨지지 않게 한다(그냥 amount를 그대로 더하면 총량만 840 초과분까지 따라
        올라가서 base/총량이 서로 안 맞게 됨).
        """
        for record in self.data.values():
            base = record.get("oath_energy_base")
            if base is None:
                continue
            new_base = min(base + amount, self.OATH_ENERGY_BASE_CAP)
            actual_added = new_base - base
            record["oath_energy_base"] = new_base
            record["oath_energy"] = (record.get("oath_energy") or 0) + actual_added
        self._save()

    def most_recent_character(self):
        """oath_energy 가 채워진 레코드 중 last_updated 가 가장 최근인 닉네임을 반환.
        없으면 None. (2026-07-08: entity_id 대신 닉네임 반환하도록 이름/반환값 변경 -
        entity_id는 더 이상 저장소의 유일 키가 아니므로 "기준 캐릭터"를 가리키려면 닉네임이 필요함.)
        """
        best_nick, best_ts = None, None
        for nickname, record in self.data.items():
            if record.get("oath_energy") is None:
                continue
            ts = record.get("last_updated")
            if ts is None:
                continue
            if best_ts is None or ts > best_ts:
                best_ts = ts
                best_nick = nickname
        return best_nick

    def get_known_base(self, nickname):
        """이 닉네임으로 마지막으로 확인된 "왼쪽 숫자"(정기 충전분)를 반환. 모르면 0."""
        record = self.data.get(nickname)
        if record is None:
            return 0
        base = record.get("oath_energy_base")
        return base if base is not None else 0
