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
    "combat_power_updated": "ISO8601 문자열" | null,
    "oath_energy_regen_checkpoint": "ISO8601 문자열" | null,  # 2026-07-18 추가, 아래 참고
    "item_level": int | null,         # 템레벨 (2026-07-19 추가, opcode(0x1D,0x56))
    "item_level_updated": "ISO8601 문자열" | null
  },
  ...
}

**2026-07-09 추가: oath_energy_base/oath_energy 에는 실측값 외에 "추정치"도 섞여 들어갈 수 있다.**
`apply_periodic_regen()`/`catch_up_periodic_regen()` (아래 참고)이 정기 충전(+15, 왼쪽 숫자)을
실제 패킷 없이 시간 기준으로 흉내내서 이 필드들에 직접 더한다 - 사용자 요청으로 실측값과 필드
상으로는 구분하지 않는다(다음 실제 로그인/이벤트가 오면 그 값으로 덮어써지면서 자연히 보정됨).

**2026-07-18 추가: `oath_energy_regen_checkpoint`.** 정기충전을 마지막으로 계산에 반영한
시각(ISO8601). `catch_up_periodic_regen()`이 이 시각과 지금 사이에 정기충전 정각이 몇 번
지났는지 세서 한 번에 몰아 적용하고, 적용 후 이 값을 지금 시각으로 갱신한다 - 프로그램이
꺼져있던 동안 놓친 정기충전을 다음 실행 때 소급으로 보상하기 위한 필드(사용자 제안).
`update_oath_energy()`가 실측 base를 받을 때도 이 값을 그 시각으로 맞춰서, 실측과 시뮬레이션이
같은 시간 구간을 중복 가산하지 않게 한다.
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


def _count_ticks_since(start, end, tick_hours):
    """2026-07-18 추가: start(제외) 부터 end(포함) 사이에 tick_hours(예: (2,5,8,11,14,17,20,23))
    정각이 몇 번 있었는지 센다. `CharacterStore.catch_up_periodic_regen`이 소급 계산에 사용."""
    if start >= end:
        return 0
    count = 0
    day = start.date()
    last_day = end.date()
    while day <= last_day:
        for hour in tick_hours:
            t = datetime.datetime.combine(day, datetime.time(hour=hour))
            if start < t <= end:
                count += 1
        day += datetime.timedelta(days=1)
    return count


class CharacterStore:
    def __init__(self, path=DEFAULT_PATH, on_change=None):
        """`on_change` (2026-08-13, 2단계 서버 업로드 대비 추가): 캐릭터 레코드가 실제로
        갱신될 때마다 그 레코드 dict 하나를 인자로 호출되는 콜백. 이 파일(storage.py)은
        순수 로컬 저장 책임만 지고 네트워크는 전혀 모른다는 원칙을 지키기 위해, 실제
        서버 업로드 로직(aion2_uploader.py)은 여기서 직접 import하지 않고 호출자
        (aion2_live_monitor.py의 LiveCapture)가 콜백으로 주입한다 - replay_pcap은 이
        콜백을 넘기지 않으므로 리플레이 모드는 지금처럼 부작용 없이 그대로 유지된다
        (정기충전을 replay에 연결하지 않은 것과 동일한 원칙). 콜백에서 예외가 나도
        저장 자체(로컬 파일 쓰기)는 절대 실패하면 안 되므로 `_notify`에서 항상 삼킨다."""
        self.path = path
        self.on_change = on_change
        self.save_revision = 0
        self.data = self._load()

    def _notify(self, nickname):
        if self.on_change is None:
            return
        try:
            self.on_change(self.data.get(nickname))
        except Exception:
            pass

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
        # 성공한 파일 교체만 GUI에 알린다. 업로드 콜백과 독립적으로 삭제도 포함한다.
        self.save_revision += 1

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
                "oath_energy_regen_checkpoint": None,  # 2026-07-18 추가, catch_up_periodic_regen 참고
                "item_level": None,  # 2026-07-19 추가, opcode(0x1D,0x56)
                "item_level_updated": None,
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
        self._notify(nickname)

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
            # 2026-07-18 추가: 실측(로그인 스냅샷/2값 증가 이벤트)으로 base가 갱신되는 순간은
            # "이 시각까지의 정기충전을 이미 포함한 진짜 값"이라는 뜻이다 - catch_up_periodic_regen
            # 이 다음번에 "체크포인트 이후 지난 정기충전 횟수"를 셀 때, 이 실측 시각 이전 구간을
            # 또 세서 중복 가산하지 않도록 체크포인트를 여기서 실측 시각으로 맞춰준다(사용자 확정:
            # "갱신 시간부터 소급하는 방향" - last_updated를 소급 기준점으로 삼되, 실측이 올 때마다
            # 그 기준점 자체를 최신으로 당겨놓는 방식).
            record["oath_energy_regen_checkpoint"] = datetime.datetime.now().isoformat(timespec="seconds")
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
        self._notify(nickname)

    def update_combat_power(self, nickname, combat_power, entity_id=None):
        """전투력 갱신. 오드에너지처럼 history 를 남기진 않는다 - 필요해지면 그때 추가."""
        record = self._get_or_create(nickname)
        if entity_id is not None:
            record["entity_id"] = entity_id
        record["combat_power"] = combat_power
        record["combat_power_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        self._save()
        self._notify(nickname)

    def update_item_level(self, nickname, item_level, entity_id=None):
        """템레벨 갱신 (2026-07-19 추가, opcode(0x1D,0x56)). update_combat_power와 완전히
        동일한 구조 - 마찬가지로 history는 안 남김."""
        record = self._get_or_create(nickname)
        if entity_id is not None:
            record["entity_id"] = entity_id
        record["item_level"] = item_level
        record["item_level_updated"] = datetime.datetime.now().isoformat(timespec="seconds")
        self._save()
        self._notify(nickname)

    def delete_character(self, nickname):
        """캐릭터 레코드를 완전히 삭제 (2026-07-19 추가, GUI의 "삭제" 버튼용). 되돌릴 방법이
        없는 파괴적 동작이라 호출측(GUI)에서 사용자 확인을 먼저 받아야 한다. 삭제해도 그
        캐릭터가 실제로 다시 접속해서 새 패킷이 오면(entity_id는 계정 공용이라 아직 추적
        중이면) 레코드가 다시 자연스럽게 생성될 수 있음 - "다시는 못 보게 영구 차단"이 아니라
        "지금 목록에서 안 보이게 지우기"에 가까운 동작. 존재하지 않는 닉네임이면 조용히
        아무 것도 안 함(no-op), 호출측에서 미리 존재 여부를 확인할 필요 없게 함."""
        if nickname in self.data:
            del self.data[nickname]
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
        changed_nicknames = []
        for nickname, record in self.data.items():
            base = record.get("oath_energy_base")
            if base is None:
                continue
            new_base = min(base + amount, self.OATH_ENERGY_BASE_CAP)
            actual_added = new_base - base
            record["oath_energy_base"] = new_base
            record["oath_energy"] = (record.get("oath_energy") or 0) + actual_added
            if actual_added > 0:
                changed_nicknames.append(nickname)
        self._save()
        # 2026-08-13 추가: 정기충전으로 바뀐 캐릭터도 서버 업로드 콜백 대상에 포함시킨다 -
        # 안 그러면 서버 DB는 그 캐릭터가 다음에 실제로 접속할 때까지 정기충전분을 영영 못 받음
        # (aion2_gui_qt.py의 "미접속캐릭 표시 안갱신" 버그와 같은 종류의 누락을 서버 쪽에서도
        # 반복하지 않기 위함).
        for nickname in changed_nicknames:
            self._notify(nickname)

    def catch_up_periodic_regen(self, amount, tick_hours):
        """2026-07-18 추가: 프로그램이 꺼져있던 동안 놓친 정기충전을 실제 경과 시간 기준으로
        한 번에 몰아서 계산해 적용한다 (사용자 제안: "15가 올라간 시간을 갱신날짜로 기록해놓고
        exe가 스타트될때 그 갱신날짜를 기반으로 시간 계산을 한 다음 갱신 시켜놓으면 되는거
        아닌가"). 기존 `apply_periodic_regen`은 "프로그램이 실제로 그 정각에 켜져 있어야만"
        적용됐는데, 이 메서드는 그 제약이 없다 - 캐릭터별로 `oath_energy_regen_checkpoint`
        (마지막으로 정기충전을 계산에 반영한 시각)를 기준으로 지금까지 `tick_hours` 정각이
        몇 번 지났는지 세서 `amount * 횟수`를 한 번에 더한다(OATH_ENERGY_BASE_CAP으로 클램프,
        apply_periodic_regen과 동일한 클램프 로직 - 총량엔 실제로 늘어난 만큼만 반영).

        체크포인트가 아직 없는 레코드(이 기능 도입 전부터 있던 캐릭터, 또는 실측이 있었지만
        아직 체크포인트가 안 찍힌 경우)는 `last_updated`(마지막 실측 시각)를 최초 기준점으로
        삼는다 - 사용자 확정: "갱신 시간부터 소급하는 방향"(과거 전체 공백에 대해 소급 적용,
        이번 기능 도입 시점부터만 카운트하는 보수적 방식은 채택 안 함). 실제 게임 서버는 우리
        프로그램이 켜져 있는지와 무관하게 계속 충전해왔을 것이므로, 오래 방치된 캐릭터가 이
        메서드 최초 실행 시 바로 상한(840) 근처로 점프하는 것은 버그가 아니라 의도된 동작이다.

        체크포인트도 last_updated도 둘 다 없으면(한 번도 실측된 적 없는 캐릭터) 건너뛴다 -
        base가 None인 레코드와 마찬가지로 기준으로 삼을 시각 자체가 없어서 계산이 불가능하다.

        매 호출마다(변화가 있든 없든) 체크포인트를 지금 시각으로 갱신한다 - 그래야 다음 호출이
        같은 구간을 또 세지 않는다. `update_oath_energy`가 실측 base를 받을 때도 체크포인트를
        그 시각으로 맞춰두므로(위 참고), 실측과 이 시뮬레이션이 서로 같은 구간을 중복 가산하는
        일은 없다.

        **2026-07-18 추가(사용자 확정, "2번으로 가야지" - 값이 바뀌면 갱신날짜도 갱신하는
        방향): 실제로 base가 증가했을 때(actual_added > 0)만 `last_updated`도 지금 시각으로
        같이 갱신한다.** 원래(Fourteenth addition, apply_periodic_regen)는 정기충전이 "모든
        캐릭터에 동시다발적으로 적용되는 이벤트라 실제 활동 시각과 혼동되면 안 된다"는 이유로
        last_updated를 일부러 안 건드렸는데, 소급 캐치업이 추가되면서 한 번에 840까지 확
        뛰는 큰 변화가 생길 수 있게 됐고, 그 옆에 GUI 갱신날짜가 여전히 옛날 그대로면 "값은
        바뀌었는데 날짜는 왜 그대로냐"는 혼란을 준다는 사용자 지적으로 정책이 바뀜.
        **"실제 플레이 시각" vs "정기충전 시각" 구분은 이 프로그램에서 애초에 의미가 없다고
        사용자가 명시적으로 확인함("최근 실제 플레이라는게 의미가없어 오드만감시하는
        프로그렘이니까")** - 이 프로그램은 플레이 세션을 추적하는 게 아니라 오드에너지 수치
        자체만 감시하는 도구이므로, `most_recent_character()`가 "정기충전만 받은 캐릭터"를
        골라도 문제로 취급하지 않는다. 즉 위에서 우려했던 트레이드오프는 실제로는 트레이드
        오프가 아니다 - 그냥 "이 캐릭터 레코드가 마지막으로 갱신된 시각"으로 단순하게
        취급하면 된다.

        호출 지점(aion2_live_monitor.py): (1) 프로그램 시작 직후 1회 - 꺼져있던 동안의 공백을
        메움, (2) 이후 매 정기충전 시각(2/5/8/11/14/17/20/23시)마다 - 기존 `_schedule_periodic_regen`
        타이머가 그대로 호출하되 이제 `apply_periodic_regen` 대신 이 메서드를 씀(타이머가 살짝
        늦게 발화하거나 절전모드 등으로 밀려도 실제 경과 틱 수를 정확히 세므로 더 견고함). 여전히
        리플레이 모드(replay_pcap)에는 연결하지 않는다 - 리플레이는 과거 캡처 검증용이라 현재
        벽시계 시각 기준 로직을 붙이면 검증 결과가 왜곡된다(위 apply_periodic_regen과 동일한 이유).
        """
        now = datetime.datetime.now()
        changed_nicknames = []
        for nickname, record in self.data.items():
            base = record.get("oath_energy_base")
            if base is None:
                continue
            checkpoint_str = record.get("oath_energy_regen_checkpoint") or record.get("last_updated")
            if not checkpoint_str:
                continue
            try:
                checkpoint = datetime.datetime.fromisoformat(checkpoint_str)
            except ValueError:
                continue
            ticks = _count_ticks_since(checkpoint, now, tick_hours)
            if ticks > 0:
                new_base = min(base + amount * ticks, self.OATH_ENERGY_BASE_CAP)
                actual_added = new_base - base
                record["oath_energy_base"] = new_base
                record["oath_energy"] = (record.get("oath_energy") or 0) + actual_added
                if actual_added > 0:
                    # 2026-07-18 추가(사용자 확정 "2번으로 가야지"): 실제로 값이 변했을 때만
                    # last_updated도 같이 갱신 - GUI 갱신날짜와 실제 표시값이 어긋나 보이지
                    # 않게 함. 위 docstring의 트레이드오프 설명 참고.
                    record["last_updated"] = now.isoformat(timespec="seconds")
                    changed_nicknames.append(nickname)
            record["oath_energy_regen_checkpoint"] = now.isoformat(timespec="seconds")
        self._save()
        # 2026-08-13 추가: apply_periodic_regen과 동일한 이유 - 소급분도 서버 업로드 콜백을 태워야
        # 서버 DB가 "오래 접속 안 한 캐릭터"를 다음 실접속까지 기다리지 않고 반영받는다.
        for nickname in changed_nicknames:
            self._notify(nickname)

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
