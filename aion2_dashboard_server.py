"""
로컬 오드에너지 대시보드 서버.

프로젝트 로드맵 1차 구조의 마지막 조각: aion2_live_monitor.py가 계속 갱신하는
oath_energy_data.json을 브라우저에서 볼 수 있게 아주 작은 로컬 HTTP 서버를 띄운다.
DB나 외부 서버가 아니라 "이 PC 안에서만" 도는 로컬 웹페이지 용도.

실행:
    pip install flask          # 최초 1회
    python aion2_dashboard_server.py
    -> 브라우저에서 http://127.0.0.1:5000 열기

aion2_live_monitor.py를 따로(같은 시간에) 켜놔야 데이터가 실시간으로 갱신된다.
이 서버는 oath_energy_data.json을 직접 읽기만 하고 쓰지 않으므로, 두 프로그램을
동시에 켜놔도 서로 충돌하지 않는다 (저장소 쪽에서 임시파일+rename으로 원자적 쓰기 처리).
"""

import json
import os

from flask import Flask, jsonify, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "oath_energy_data.json")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

app = Flask(__name__, static_folder=DASHBOARD_DIR, static_url_path="")


def read_data():
    """oath_energy_data.json을 매 요청마다 새로 읽는다 (캐싱 안 함).

    aion2_live_monitor.py가 별도 프로세스로 계속 이 파일을 갱신하므로, 대시보드
    서버가 시작 시점 데이터를 들고 있으면 안 됨 - 항상 디스크에서 최신 상태를 읽는다.
    """
    if not os.path.exists(DATA_PATH):
        return {}
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # aion2_live_monitor.py가 하필 쓰는 도중 읽으려는 극히 드문 순간을 대비한 방어적 처리.
        # (실제로는 storage.py가 tmp파일+rename으로 원자적 쓰기를 하므로 거의 발생 안 함)
        return {}


@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/characters")
def api_characters():
    return jsonify(read_data())


if __name__ == "__main__":
    print("오드에너지 대시보드: http://127.0.0.1:5000  (Ctrl+C로 종료)")
    print("aion2_live_monitor.py를 같이 켜놔야 값이 실시간으로 갱신됩니다.")
    app.run(host="127.0.0.1", port=5000, debug=False)
