"""
AION2 2단계 - 서버 (Flask + SQLite).

[[aion2_project_roadmap]]의 원칙: 1단계(CS 앱의 로컬 저장+로컬 오버레이/대시보드)는 이
서버가 있든 없든, 켜져있든 꺼져있든 완전히 정상 동작해야 한다. 그래서 이 서버는 순수하게
"CS 앱이 올려주는 캐릭터 데이터를 저장하고, 닉네임으로 조회해주는" 역할만 한다 - CS 앱
쪽 실시간 캡처/파싱 로직은 전혀 건드리지 않는다.

DB 스키마 설계: `characters` 테이블을 (owner, nickname) 복합 유니크로 잡았다. 지금은
로그인이 없어서 owner는 CS 앱 설정 파일(`server_config.json`)에 사용자가 직접 적어넣는
문자열일 뿐이지만("잠정 계정"), 나중에 3단계에서 진짜 로그인이 생겨도 이 컬럼 구조를 그대로
재사용할 수 있게 지금부터 owner 개념을 넣어둔다 - 사용자 확인(2026-08-13): "나중엔 다른
사람도 쓸 수 있게".

인증: 지금은 사용자별 로그인이 아니라 "설치본마다 공유되는 업로드 키" 하나만 검사한다
(`X-Upload-Key` 헤더 vs 환경변수 `AION2_UPLOAD_KEY`) - 진짜 사용자 인증이 아니라 아무나
스팸 업로드 못 하게 막는 최소 장치. `AION2_UPLOAD_KEY`를 설정 안 하면(로컬 테스트 편의)
인증 검사 자체를 건너뛴다 - 실제 배포(VPS) 시에는 반드시 설정할 것.

배포: 이 파일 하나 + `server_web/` 폴더만 있으면 됨. 로컬 테스트는
`python aion2_server.py` (기본 포트 6000). 실제 배포(예: Oracle Cloud 같은 VPS)는 지금은
개발용 werkzeug 서버 대신 `gunicorn`/`waitress` 같은 운영용 WSGI 서버로 앞단을 바꾸는 걸
권장하지만, 이건 실제 서버를 마련한 뒤에 다룰 배포 단계 - 지금은 로직/스키마가 맞는지
로컬에서 검증하는 게 목표.
"""

import os
import sqlite3
import datetime

from flask import Flask, request, jsonify, g, send_from_directory

DB_PATH = os.environ.get(
    "AION2_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "aion2_server.db"),
)
UPLOAD_KEY = os.environ.get("AION2_UPLOAD_KEY", "")

_HERE = os.path.dirname(os.path.abspath(__file__))
_WEB_DIR = os.path.join(_HERE, "server_web")

app = Flask(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS characters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL DEFAULT 'default',
    nickname TEXT NOT NULL,
    entity_id INTEGER,
    server INTEGER,
    job INTEGER,
    oath_energy INTEGER,
    oath_energy_base INTEGER,
    oath_energy_dynamic INTEGER,
    last_delta INTEGER,
    last_updated TEXT,
    combat_power INTEGER,
    combat_power_updated TEXT,
    oath_energy_regen_checkpoint TEXT,
    item_level INTEGER,
    item_level_updated TEXT,
    server_received_at TEXT,
    UNIQUE(owner, nickname)
);
"""

# aion2_storage.py의 스키마와 1:1 대응 (nickname/owner는 별도 처리)
FIELDS = [
    "entity_id", "server", "job", "oath_energy", "oath_energy_base",
    "oath_energy_dynamic", "last_delta", "last_updated", "combat_power",
    "combat_power_updated", "oath_energy_regen_checkpoint", "item_level",
    "item_level_updated",
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(SCHEMA)
    conn.commit()
    conn.close()


def _check_auth():
    if not UPLOAD_KEY:  # 로컬 테스트 편의 - 운영 배포시엔 반드시 AION2_UPLOAD_KEY를 설정할 것
        return True
    return request.headers.get("X-Upload-Key") == UPLOAD_KEY


@app.route("/api/upload", methods=["POST"])
def upload():
    if not _check_auth():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    nickname = data.get("nickname")
    if not nickname:
        return jsonify({"error": "nickname required"}), 400
    owner = data.get("owner") or "default"

    db = get_db()
    row = db.execute(
        "SELECT id FROM characters WHERE owner = ? AND nickname = ?", (owner, nickname)
    ).fetchone()

    values = {f: data.get(f) for f in FIELDS}
    now = datetime.datetime.now().isoformat(timespec="seconds")

    if row is None:
        cols = ["owner", "nickname"] + FIELDS + ["server_received_at"]
        placeholders = ", ".join("?" for _ in cols)
        db.execute(
            f"INSERT INTO characters ({', '.join(cols)}) VALUES ({placeholders})",
            [owner, nickname] + [values[f] for f in FIELDS] + [now],
        )
    else:
        # 2026-08-13: None으로 온 필드는 기존 값을 덮어쓰지 않는다 - aion2_storage.py의
        # update_oath_energy가 "None이면 이번엔 갱신 안 된 것"으로 취급하는 규칙(2026-07-08
        # 버그 수정 이력)을 서버 쪽에서도 그대로 지킨다. 안 그러면 combat_power만 갱신된
        # 업로드가 이미 저장돼있던 oath_energy를 NULL로 지워버리는, 이미 한 번 겪은 것과
        # 같은 종류의 버그가 서버에서 재발한다.
        set_clauses = []
        params = []
        for f in FIELDS:
            if values[f] is not None:
                set_clauses.append(f"{f} = ?")
                params.append(values[f])
        set_clauses.append("server_received_at = ?")
        params.append(now)
        params += [owner, nickname]
        db.execute(
            f"UPDATE characters SET {', '.join(set_clauses)} WHERE owner = ? AND nickname = ?",
            params,
        )
    db.commit()
    return jsonify({"status": "ok"})


@app.route("/api/characters", methods=["GET"])
def list_characters():
    owner = request.args.get("owner")
    db = get_db()
    if owner:
        rows = db.execute(
            "SELECT * FROM characters WHERE owner = ? ORDER BY last_updated DESC", (owner,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM characters ORDER BY last_updated DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/characters/<nickname>", methods=["GET"])
def get_character(nickname):
    owner = request.args.get("owner")
    db = get_db()
    if owner:
        rows = db.execute(
            "SELECT * FROM characters WHERE nickname = ? AND owner = ?", (nickname, owner)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM characters WHERE nickname = ?", (nickname,)).fetchall()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return jsonify([dict(r) for r in rows])


@app.route("/")
def index():
    return send_from_directory(_WEB_DIR, "index.html")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 6000)), debug=False)
