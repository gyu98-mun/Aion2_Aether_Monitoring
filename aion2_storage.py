"""
캐릭터별 오드에너지 데이터를 로컬 JSON 파일에 저장하는 간단한 저장소.

프로젝트 로드맵의 "1차 구조"(로컬 저장 + 로컬 웹 대시보드) 중 저장 부분 담당.
나중에 만들 대시보드 페이지가 이 JSON 파일을 그대로 읽어서 보여줄 예정이므로,
스키마를 함부로 바꾸지 말고 필드를 추가하는 방향으로만 확장할 것.

스키마 (oath_energy_data.json):
{
  "<entity_id>": {
    "entity_id": int,
    "nickname": str | null,
    "server": int | null,
    "job": int | null,
    "oath_energy": int | null,        # 총 소지량 = oath_energy_base + oath_energy_dynamic
    "oath_energy_base": int | null,   # "왼쪽 숫자" - 정기 충전분 (02시부터 3시간마다 +10/+15,
                                       # 로그인 스냅샷 opcode(0x0B,0x61)에서만 얻을 수 있음, 2026-07-07 추가)
    "oath_energy_dynamic": int | null,# "오른쪽 숫자" - 아이템/던전 등 누적분 (opcode(0x0C,0x61) 변경
                                       # 이벤트가 갱신하는 값, 2026-07-07 추가)
    "last_delta": int | null,
    "last_updated": "ISO8601 문자열" | null,
    "history": [                      # 최근 변경 이력 (2026-07-08 추가, 대시보드용).
                                       # 최신이 리스트 맨 뒤, 최대 HISTORY_LIMIT개까지만 보관.
      {"timestamp": "ISO8601", "oath_energy": int, "delta": int|null,
       "base": int|null, "dynamic": int|null},
      ...
    ]
  },
  ...
}
"""

import json
import os
import datetime

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oath_energy_data.json")
HISTORY_LIMIT = 50  # 캐릭터당 최근 변경 이력 보관 개수 (대시보드 "최근 변경 이력" 표시용)


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

    def _get_or_create(self, entity_id):
        key = str(entity_id)
        if key not in self.data:
            self.data[key] = {
                "entity_id": entity_id,
                "nickname": None,
                "server": None,
                "job": None,
                "oath_energy": None,
                "oath_energy_base": None,
                "oath_energy_dynamic": None,
                "last_delta": None,
                "last_updated": None,
                "history": [],
            }
        return self.data[key]

    def update_nickname(self, entity_id, nickname, server=None, job=None):
        record = self._get_or_create(entity_id)
        record["nickname"] = nickname
        if server is not None:
            record["server"] = server
        if job is not None:
            record["job"] = job
        self._save()

    def update_oath_energy(self, entity_id, new_total, delta, base=None, dynamic=None):
        """new_total 은 항상 "진짜 총 소지량"(base+dynamic)이어야 한다 - 호출측
        (aion2_live_monitor.py)이 미리 합산해서 넘겨준다. base/dynamic 은 참고용으로 같이
        저장(2026-07-07 추가, 왼쪽/오른쪽 숫자 버그 수정) - None 이면 그 구성요소는 이번에
        갱신 안 된 것이므로 기존 저장값을 그대로 둔다.
        """
        record = self._get_or_create(entity_id)
        record["oath_energy"] = new_total
        if base is not None:
            record["oath_energy_base"] = base
        if dynamic is not None:
            record["oath_energy_dynamic"] = dynamic
        record["last_delta"] = delta
        record["last_updated"] = datetime.datetime.now().isoformat(timespec="seconds")

        # 최근 변경 이력 기록 (2026-07-08 추가). 예전에 만들어진 레코드는 "history" 키가
        # 없을 수 있으므로 setdefault로 안전하게 처리.
        history = record.setdefault("history", [])
        history.append({
            "timestamp": record["last_updated"],
            "oath_energy": new_total,
            "delta": delta,
            "base": record.get("oath_energy_base"),
            "dynamic": record.get("oath_energy_dynamic"),
        })
        if len(history) > HISTORY_LIMIT:
            del history[: len(history) - HISTORY_LIMIT]

        self._save()

    def get_display_name(self, entity_id):
        record = self.data.get(str(entity_id))
        if record and record.get("nickname"):
            return record["nickname"]
        return f"캐릭터(id={entity_id})"

    def has_confirmed_oath_energy(self, entity_id):
        """이 entity_id 로 오드에너지 값을 확인해본 적이 있는지 (opcode 오탐 검증에 사용).

        2026-07-07 추가: opcode(0x0C,0x61)가 오드에너지가 아닌 다른 용도(맵 이벤트 카운터 등)로도
        재사용된다는 게 확인됨 - 구조적으로 그럴듯해 보여도 실제로는 다른 entity_id 를 가리키는
        패킷일 수 있다. "이전에 실제로 오드에너지로 확인된 적 있는 id인지"를 신뢰 판단 기준 중
        하나로 쓴다 (aion2_live_monitor.py 참고).
        """
        record = self.data.get(str(entity_id))
        return record is not None and record.get("oath_energy") is not None

    def most_recent_oath_entity_id(self):
        """oath_energy 가 채워진 레코드 중 last_updated 가 가장 최근인 entity_id 를 반환.
        없으면 None. (2026-07-07 추가, opcode 오탐 검증의 "이번 세션에서 추적 중인 캐릭터"
        초기값을 이전 실행 기록에서 이어받기 위한 용도.)
        """
        best_id, best_ts = None, None
        for key, record in self.data.items():
            if record.get("oath_energy") is None:
                continue
            ts = record.get("last_updated")
            if ts is None:
                continue
            if best_ts is None or ts > best_ts:
                best_ts = ts
                best_id = record.get("entity_id", int(key))
        return best_id

    def get_known_base(self, entity_id):
        """이 entity_id 로 마지막으로 확인된 "왼쪽 숫자"(정기 충전분)를 반환. 모르면 0.
        (2026-07-07 추가, 왼쪽/오른쪽 숫자 합산 버그 수정용 - 로그인 스냅샷을 놓친 세션에서도
        직전에 알던 base 값으로 총량을 근사할 수 있게 해준다.)
        """
        record = self.data.get(str(entity_id))
        if record is None:
            return 0
        base = record.get("oath_energy_base")
        return base if base is not None else 0
