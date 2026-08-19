"""
2단계(서버 업로드) 클라이언트 측 헬퍼 (2026-08-13 신규).

**핵심 원칙: 서버 없이도 CS 앱은 지금까지처럼 완전히 정상 동작해야 한다.** 1단계(로컬
저장 + 로컬 오버레이/대시보드)는 서버 유무와 무관하게 동작해왔고 그 성질을 절대 깨면 안
된다는 게 [[aion2_project_roadmap]]의 기존 원칙 - 그래서 이 모듈은:
- 설정 파일(`server_config.json`)이 없거나 `server_url`이 비어있으면 완전히 조용히
  아무것도 안 한다(로그도 안 남김 - 서버 기능 자체를 안 쓰는 사용자에게는 소음).
- 업로드는 항상 별도 스레드에서 fire-and-forget으로 수행 - 절대 호출자(저장 경로)를
  블로킹하지 않는다. 실패해도 예외를 삼키고 상태 메시지만 (있으면) status_queue에 남긴다.
- `aion2_storage.py`는 이 모듈을 import하지 않는다 - `CharacterStore(on_change=...)`
  콜백으로 느슨하게 연결된다(저장소는 네트워크를 모른다는 계층 분리 원칙 유지).
- `replay_pcap`(리플레이 검증 모드)에는 연결하지 않는다 - `LiveCapture`에서 만드는
  `CharacterStore`에만 `on_change` 콜백을 넘긴다. 정기충전을 replay에 안 붙인 것과
  동일한 이유(과거 캡처 재생 결과가 실제 네트워크 부작용을 일으키면 안 됨).

설정 파일 위치는 `oath_energy_data.json`/`gui_settings.json`과 동일한 규칙(exe로
패키징됐으면 실행 파일 옆, 아니면 스크립트 옆)을 따른다:
{
  "server_url": "http://1.2.3.4:6000",   # 비어있거나 파일 자체가 없으면 업로드 기능 꺼짐
  "upload_key": "아무 문자열",             # 서버의 AION2_UPLOAD_KEY와 일치해야 함
  "owner": "신문규"                        # 서버 DB에서 이 설치본의 캐릭터들을 묶는 이름표.
                                            # 3단계에 실제 로그인이 생기기 전까지의 잠정 값 -
                                            # 나중에 로그인이 생기면 이 필드는 실제 계정 id로
                                            # 교체될 것(지금부터 owner 개념을 넣어두는 이유는
                                            # aion2_server.py의 DB 스키마 설명 참고).
}
"""

import json
import os
import sys
import threading

try:
    import requests
except ImportError:  # requirements.txt에 없던 예전 설치본에서도 앱 자체는 죽지 않게
    requests = None

if getattr(sys, "frozen", False):
    _BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(_BASE_DIR, "server_config.json")

# 업로드 레코드에 실어 보낼 필드 - aion2_storage.py의 스키마와 1:1 (nickname은 별도로 얹음)
_UPLOAD_FIELDS = [
    "entity_id", "server", "job", "oath_energy", "oath_energy_base",
    "oath_energy_dynamic", "last_delta", "last_updated", "combat_power",
    "combat_power_updated", "oath_energy_regen_checkpoint", "item_level",
    "item_level_updated",
]


def _load_config():
    """설정 파일이 없거나 server_url이 비어있으면 None을 반환 - 업로드 기능이 꺼져있다는 뜻."""
    if not os.path.exists(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return None
    url = (cfg.get("server_url") or "").strip().rstrip("/")
    if not url:
        return None
    return {
        "url": url,
        "key": cfg.get("upload_key") or "",
        "owner": cfg.get("owner") or "default",
    }


def enqueue_upload(record, status_queue=None):
    """CharacterStore의 on_change 콜백으로 그대로 넘길 수 있는 시그니처: record(dict) 하나만
    받는다. status_queue는 선택 - 있으면 성공/실패를 상태창에 짧게 남긴다(정기충전의
    [정기충전] 메시지와 같은 패턴, aion2_gui_qt.py의 _refresh_all_rows_from_store가
    이 메시지도 같이 반응하지 않도록 접두사를 다르게 둠: [서버업로드]).

    `record`가 None이거나(존재하지 않는 닉네임에 대한 알림 등 방어적 상황) `requests`가
    설치 안 돼 있으면(구버전 배포본) 조용히 아무것도 안 한다.
    """
    if not record or requests is None:
        return
    cfg = _load_config()
    if cfg is None:
        return

    nickname = record.get("nickname")
    if not nickname:
        return

    payload = {"nickname": nickname, "owner": cfg["owner"]}
    for f in _UPLOAD_FIELDS:
        payload[f] = record.get(f)

    def _worker():
        try:
            resp = requests.post(
                f"{cfg['url']}/api/upload",
                json=payload,
                headers={"X-Upload-Key": cfg["key"]},
                timeout=5,
            )
            if status_queue is not None:
                if resp.status_code == 200:
                    status_queue.put(f"[서버업로드] {nickname} 반영됨")
                else:
                    status_queue.put(
                        f"[서버업로드][실패] {nickname} status={resp.status_code} {resp.text[:100]}"
                    )
        except Exception as e:
            if status_queue is not None:
                status_queue.put(f"[서버업로드][에러] {nickname}: {e!r}")

    threading.Thread(target=_worker, daemon=True).start()
