"""
AION2 오드에너지 GUI - PySide6(Qt) 버전 (2026-07-18 추가).

기존 Tkinter GUI(aion2_live_monitor.py의 run_gui)를 대체하는 새 GUI. 사용자가 참고
이미지(다른 DPS미터류 오버레이 - 프레임리스+둥근모서리+반투명 패널+아이콘 툴바+색깔
배지가 있는 캐릭터 목록)를 보여주며 "전체 디자인까지 이 느낌으로 재단장"을 요청해서
Tkinter 대신 PySide6로 새로 작성함. Tkinter의 -alpha는 창 전체(배경+글자+표)를 균일하게
반투명 처리하는 방식이라 참고 이미지처럼 "배경만 비치고 글자는 또렷한" 진짜 오버레이
느낌을 못 낸다 - PySide6는 WA_TranslucentBackground(진짜 픽셀 단위 투명)와 QSS
border-radius(진짜 둥근 창 모양)를 표준 기능으로 지원해서 이걸로 새로 작성함.

**데이터 흐름은 기존 run_gui와 동일** - event_queue/status_queue를 그대로 재사용하고
(QTimer로 폴링, Tkinter의 root.after(150, poll_queue) 자리를 대신함), 저장소 포맷터
함수(_fmt_info_cell/_fmt_date_cell/_fmt_combat_power_cell)와 STATUS_ROW_CAP도
aion2_live_monitor.py에서 그대로 가져다 쓴다(로직 중복 방지). 순환 임포트를 피하려고
aion2_live_monitor.py의 main()에서 이 모듈을 지연 임포트(lazy import)하는 걸 전제로
설계됨 - 모듈 최상단에서 서로를 바로 import하면 순환 참조가 생기지만, main() 안에서
지연 임포트하면 그 시점엔 aion2_live_monitor 모듈이 이미 다 로드된 뒤라 문제없다.

**PySide6 미설치/임포트 실패 시:** aion2_live_monitor.py의 main()이 이 모듈 임포트를
try/except로 감싸고, 실패하면 기존 Tkinter run_gui로 자동 폴백한다(기존 "GUI 실행
실패시 콘솔 모드로 전환"과 같은 안전망 패턴을 한 단계 더 추가한 것).

**잠금(🔒) 버튼 - 진짜 클릭 통과 오버레이 (2026-07-18 수정).** 사용자 요청: "자물쇠
모양을 누르면 효과가 클릭이 막히고 배경이 완전 투명이 되는거야". 잠그면 (1)
`WA_TransparentForMouseEvents`를 창 전체에 걸어서 마우스 클릭/스크롤이 창을 그냥
통과해 뒤에 있는 게임 화면으로 그대로 전달되고, (2) card(패널)의 배경색을
`transparent`로 바꿔서 패널 자체가 안 보이고 글자/표만 게임 화면 위에 떠 보인다.

**"잠금 해제를 어떻게 다시 누르나" 문제 - 시스템 트레이 아이콘으로 해결.** 창 전체가
클릭 통과 상태가 되면 타이틀바의 잠금 버튼 자체도 눌러지지 않아 "풀 방법이 없어지는"
함정이 생긴다. 그래서 잠금 해제는 창이 아니라 **완전히 별도의 위젯인 시스템 트레이
아이콘**(`QSystemTrayIcon`, Windows 작업표시줄 우측 트레이)의 우클릭 메뉴에서 하도록
분리했다 - 트레이 아이콘은 메인 창의 WA_TransparentForMouseEvents 설정과 무관하게
항상 클릭 가능한 별개의 창이라 안전장치로 쓸 수 있다. 트레이 메뉴: 잠금/잠금 해제
토글, 창 보이기(맨 앞으로 가져오기), 종료. `QSystemTrayIcon.isSystemTrayAvailable()`이
False면(트레이가 없는 환경) 조용히 건너뛴다 - 그 경우 잠그면 정말로 못 풀게 되니
주의(일반적인 Windows 데스크톱에서는 트레이가 항상 있어서 실사용에선 문제 없음).

**글자 크기 설정 (2026-08-08 추가).** 사용자 요청: "글자크기를 늘리는 설정을 할수있는
옵션을 추가하고싶어". 연속적인 슬라이더 대신 5단계 이산값(FONT_SCALE_STEPS)으로
제공한다 - 오버레이 창 폭이 사실상 고정에 가까워서(참고 이미지 스타일 유지) 임의의
배율을 허용하면 글자가 잘리거나 창이 과도하게 커질 위험이 있어, 미리 검증된 범위
안에서만 움직이게 제한했다. 트레이 아이콘 메뉴(잠금 해제와 같은 이유로 - 창이
잠겨있어도 항상 접근 가능해야 함)에 "글자 크기 크게/작게" 액션으로 노출하고,
`gui_settings.json`(오드에너지 데이터 파일과 같은 폴더, exe로 패키징했을 때도
aion2_storage.py의 _BASE_DIR와 동일한 이유로 exe 폴더 기준)에 저장해서 다음 실행에도
유지된다. 이미 만들어진 캐릭터 행(CharacterRow)/타이틀바도 실행 중에 즉시 재적용되도록
각각 apply_scale() 메서드를 갖는다 - 재시작 없이 바로 반영됨.
"""

import sys
import os
import json
import queue

from PySide6.QtCore import Qt, QTimer, QEvent
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence, QPainter, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QProgressBar, QSystemTrayIcon, QMenu, QMessageBox, QScrollArea,
)

from aion2_storage import CharacterStore
from aion2_sanctuary import format_sanctuaries
from aion2_window_geometry import constrain_resize
from aion2_live_monitor import (
    _fmt_info_cell, _fmt_date_cell, _fmt_combat_power_cell, STATUS_ROW_CAP,
)

# 캐릭터별 아이콘 배지 색상 팔레트 (참고 이미지의 다채로운 역할 아이콘 색을 흉내) -
# 닉네임 기준 결정론적 해시로 골라서 같은 캐릭터는 재실행해도 항상 같은 색이 나온다
# (Python 내장 hash()는 프로세스마다 랜덤 시드가 달라 재실행 시 색이 바뀌므로 안 씀).
_ROW_COLORS = [
    "#4FC3F7", "#BA68C8", "#4DB6AC", "#FFD54F", "#F06292",
    "#81C784", "#7986CB", "#FF8A65", "#A1887F", "#90A4AE",
]


def _color_for_nickname(nickname):
    idx = sum(ord(c) for c in nickname) % len(_ROW_COLORS)
    return _ROW_COLORS[idx]


# ---------------------------------------------------------------------------
# 글자 크기 설정 (2026-08-08 추가)
# ---------------------------------------------------------------------------

# aion2_storage.py의 _BASE_DIR 계산과 동일한 이유(PyInstaller로 패키징하면 __file__이
# 매 실행마다 새로 풀리는 임시 폴더를 가리켜서, exe 자체가 있는 폴더를 기준으로 삼아야
# 데이터가 실행할 때마다 사라지지 않음) - 이 모듈 안에서 독립적으로 계산해서
# aion2_storage의 내부(밑줄 접두) 이름에 기대지 않는다.
if getattr(sys, "frozen", False):
    _GUI_BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    _GUI_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

GUI_SETTINGS_PATH = os.path.join(_GUI_BASE_DIR, "gui_settings.json")

# 슬라이더가 아닌 이산 단계 - 레이아웃이 안 깨지는 범위로 미리 제한.
FONT_SCALE_STEPS = [0.85, 1.0, 1.15, 1.3, 1.5]
FONT_SCALE_LABELS = ["작게", "보통", "크게", "더 크게", "아주 크게"]
DEFAULT_FONT_SCALE_INDEX = 1  # "보통" = 기존 크기 그대로


def _load_font_scale_index():
    try:
        with open(GUI_SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        idx = int(data.get("font_scale_index", DEFAULT_FONT_SCALE_INDEX))
        if 0 <= idx < len(FONT_SCALE_STEPS):
            return idx
    except Exception:
        pass  # 파일이 없거나(첫 실행) 손상된 경우 - 조용히 기본값으로 시작
    return DEFAULT_FONT_SCALE_INDEX


def _save_gui_settings(**changes):
    try:
        try:
            with open(GUI_SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data.update(changes)
        with open(GUI_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass  # 저장 실패(권한 등)해도 기능 자체는 계속 동작 - 다음 실행 때 기본값으로 시작할 뿐


def _save_font_scale_index(idx):
    _save_gui_settings(font_scale_index=idx)


class RowScrollArea(QScrollArea):
    """휠 한 칸을 정확히 캐릭터 한 행으로 변환한다."""
    def __init__(self):
        super().__init__()
        self.row_step = 71
        self._wheel_remainder = 0
        self.verticalScrollBar().installEventFilter(self)
        self.verticalScrollBar().sliderReleased.connect(self.snap_position)

    def snap_position(self):
        bar = self.verticalScrollBar()
        bar.setValue(round(bar.value() / self.row_step) * self.row_step)

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        if not delta and event.pixelDelta().y():
            delta = event.pixelDelta().y() * 120 / self.row_step
        self._wheel_remainder += delta
        steps = int(self._wheel_remainder / 120)
        self._wheel_remainder -= steps * 120
        if steps:
            bar = self.verticalScrollBar()
            bar.setValue(round(bar.value() / self.row_step) * self.row_step - steps * self.row_step)
        event.accept()

    def eventFilter(self, watched, event):
        if watched is self.verticalScrollBar() and event.type() == QEvent.Wheel:
            self.wheelEvent(event)
            return True
        return super().eventFilter(watched, event)


class ResizeHandle(QWidget):
    """OS 프레임에 의존하지 않는 8방향 드래그 영역."""
    def __init__(self, window, edge):
        super().__init__(window)
        self.edge = edge
        self.drag_origin = None
        self.setStyleSheet("background-color: rgba(90, 100, 120, 18);")
        self.setCursor({1: Qt.SizeHorCursor, 2: Qt.SizeHorCursor,
                        3: Qt.SizeVerCursor, 6: Qt.SizeVerCursor,
                        4: Qt.SizeFDiagCursor, 8: Qt.SizeFDiagCursor,
                        5: Qt.SizeBDiagCursor, 7: Qt.SizeBDiagCursor}[edge])
        self.setMouseTracking(True)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.edge != 8:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#C2D4E5" if self.underMouse() else "#91A5BA"))
        # 오른쪽 아래 삼각형 점 무늬. 별도의 QSizeGrip은 만들지 않는다.
        for column, row in ((0, 2), (1, 1), (1, 2), (2, 0), (2, 1), (2, 2)):
            painter.drawEllipse(self.width() - 10 + column * 3,
                                self.height() - 10 + row * 3, 2, 2)

    def enterEvent(self, event):
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() != Qt.LeftButton or self.window().locked:
            return
        window = self.window()
        window._snap_height_to_rows()
        window._native_resizing = True
        window._row_snap_timer.stop()
        self.drag_origin = event.globalPosition().toPoint()
        self.original_geometry = window.geometry()
        self.grabMouse()
        event.accept()

    def mouseMoveEvent(self, event):
        if self.drag_origin is None:
            return
        window = self.window()
        delta = event.globalPosition().toPoint() - self.drag_origin
        original = self.original_geometry
        left, top = original.x(), original.y()
        right, bottom = left + original.width(), top + original.height()
        if self.edge in (1, 4, 7): left += delta.x()
        if self.edge in (2, 5, 8): right += delta.x()
        if self.edge in (3, 4, 5): top += delta.y()
        if self.edge in (6, 7, 8): bottom += delta.y()
        overhead, row_height, spacing, count = window._row_resize_metrics
        left, top, right, bottom = constrain_resize(
            (left, top, right, bottom), self.edge, ratio=1,
            minimum_width=window.minimumWidth(), minimum_height=window.minimumHeight(),
            maximum_height=window.maximumHeight(), overhead=overhead,
            row_height=row_height, spacing=spacing, count=count)
        window.setGeometry(left, top, right-left, bottom-top)
        event.accept()

    def mouseReleaseEvent(self, event):
        if self.drag_origin is not None and event.button() == Qt.LeftButton:
            self.releaseMouse()
            self.drag_origin = None
            window = self.window()
            window._native_resizing = False
            window._snap_height_to_rows()
            event.accept()


class CharacterRow(QFrame):
    """캐릭터 현황 한 줄. update_record(record)로 내용만 갱신한다 (위젯을 새로 만들지
    않음 - 기존 Tkinter Treeview의 item(iid, values=...) 갱신과 같은 목적)."""

    # 2026-07-18 재수정: 사용자가 다른 DPS미터류 오버레이(왼쪽, 훨씬 작고 촘촘함)를
    # 다시 보여주며 "이정도 수준으로 크기를 줄이고싶어" - 행 높이/뱃지/폰트를 전체적으로
    # 축소함 (기존 54px -> 36px). 이후 "오드랑 전투력 숫자들 크기를 좀 키워도될듯" 요청으로
    # 숫자 폰트를 다시 13px로 키우면서 행 높이도 40px로 살짝 늘림(잘림 방지).
    # 2026-08-08: 아래 값은 글자 크기 배율 1.0(보통) 기준 기본값으로 의미가 바뀌었다 -
    # 실제 적용 크기는 _px()를 거쳐 self.scale이 곱해진다.
    ROW_HEIGHT_BASE = 68

    def __init__(self, nickname, on_delete=None, scale=1.0):
        super().__init__()
        self.nickname = nickname
        self._on_delete = on_delete
        self._on_select = None
        self._selected = None
        self.setCursor(Qt.PointingHandCursor)
        self.scale = scale
        self.setObjectName("row")
        color = _color_for_nickname(nickname)
        # 카드 배경은 진하게 유지(2026-07-18 앞선 수정 - "캐릭터 카드는 너무 투명이
        # 되면안되" 참고) + 왼쪽 캐릭터 색상 강조선.
        self.setStyleSheet(
            "#row { background-color: rgba(26,26,34,210); border-radius: 6px; "
            f"border-left: 3px solid {color}; }}"
        )

        container = QVBoxLayout(self)
        container.setContentsMargins(0, 0, 0, 0)
        container.setSpacing(0)
        outer = QHBoxLayout()
        container.addLayout(outer)
        outer.setContentsMargins(8, 3, 6, 3)
        outer.setSpacing(6)

        # 2026-07-18 수정: 사용자가 뱃지(닉네임 첫 글자 원형 아이콘) 열만 잘라서 보여주며
        # "이게 필요가없어서... 걍 없에줘" - 왼쪽 색상 강조선(border-left)만으로도 캐릭터
        # 구분이 되니 뱃지 자체는 제거. 나머지 칸은 그대로 왼쪽으로 당겨진다.

        name_col = QVBoxLayout()
        name_col.setSpacing(1)
        self.name_label = QLabel(nickname)
        name_col.addWidget(self.name_label)

        # 기본오드/840(OATH_ENERGY_BASE_CAP) 비율을 보여주는 채움 막대 - 참고 이미지의
        # 캐릭터별 진행바 느낌을 흉내냄.
        self.fill_bar = QProgressBar()
        self.fill_bar.setFixedHeight(3)
        self.fill_bar.setTextVisible(False)
        self.fill_bar.setRange(0, 840)
        self.fill_bar.setStyleSheet(
            "QProgressBar { background-color: rgba(255,255,255,20); border-radius: 1px; }"
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 1px; }}"
        )
        name_col.addWidget(self.fill_bar)
        outer.addLayout(name_col, 2)

        # 2026-07-18 수정: 사용자 요청 - "기본은 흰색 추가는 파랑색으로". 기본/추가를
        # 색으로 구분해서 한눈에 왼쪽/오른쪽 숫자를 구별할 수 있게 함. 전투력은 중립색 유지.
        # 2026-08-08: 폰트 크기를 여기서 바로 안 정하고 _apply_scale_styles()가 한 번에
        # 적용하도록 미룸(생성 시점/설정 변경 시점 양쪽에서 재사용하기 위해).
        self.base_label = QLabel("-")
        self.extra_label = QLabel("-")
        self.cp_label = QLabel("-")
        self.item_level_label = QLabel("-")  # 2026-07-19 추가: 템레벨(opcode 0x1D,0x56)
        for lbl in (self.base_label, self.extra_label, self.cp_label, self.item_level_label):
            lbl.setAlignment(Qt.AlignCenter)
        outer.addWidget(self.base_label, 1)
        outer.addWidget(self.extra_label, 1)
        outer.addWidget(self.cp_label, 1)
        outer.addWidget(self.item_level_label, 1)

        self.date_label = QLabel("")
        self.date_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        outer.addWidget(self.date_label, 1)

        # 2026-07-19 추가: 사용자 요청 - "이거 안보고싶은캐릭터 삭제 버튼 기능도 만들어
        # 줘야겠다". stretch를 안 주고(고정 폭) 맨 끝에 붙여서 다른 칸 배치는 그대로 둠.
        self.delete_btn = QPushButton("✕")
        self.delete_btn.setCursor(Qt.PointingHandCursor)
        self.delete_btn.setToolTip("이 캐릭터 목록에서 삭제")
        self.delete_btn.clicked.connect(self._handle_delete_clicked)
        outer.addWidget(self.delete_btn)
        self.sanctuary_label = QLabel(format_sanctuaries(None))
        self.sanctuary_label.setContentsMargins(8, 0, 6, 3)
        container.addWidget(self.sanctuary_label)

        self._apply_scale_styles()

    def set_selected(self, selected):
        if self._selected == selected:
            return
        self._selected = selected
        color = _color_for_nickname(self.nickname)
        background = "rgba(45,75,100,235)" if selected else "rgba(26,26,34,210)"
        border = "#8ACFFF" if selected else "transparent"
        self.setStyleSheet(
            f"#row {{ background-color: {background}; border-radius: 6px; "
            f"border: 1px solid {border}; border-left: 3px solid {color}; }}"
        )

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self._on_select is not None:
            self._on_select(self.nickname)
            event.accept()
            return
        super().mousePressEvent(event)

    def _px(self, base_px):
        return max(1, round(base_px * self.scale))

    def _apply_scale_styles(self):
        """생성 시점과 apply_scale()(글자 크기 설정 변경 시) 양쪽에서 공유하는 크기/폰트
        적용 로직 (2026-08-08 추가) - 위젯을 새로 만들지 않고 이미 있는 위젯의 스타일만
        다시 계산해서 입힌다."""
        self.setFixedHeight(self._px(self.ROW_HEIGHT_BASE))
        self.sanctuary_label.setStyleSheet(f"color: #B8D8EA; font-size: {self._px(12)}px;")
        self.name_label.setStyleSheet(
            f"color: #EEEEEE; font-weight: bold; font-size: {self._px(13)}px;"
        )
        # 2026-07-18 수정: 사용자 요청 - "오드랑 전투력 숫자들 크기를 좀 키워도될듯한데".
        # 10px -> 13px(기준값) + 굵게. 기본/추가 색상은 각각 개별 지정.
        self.base_label.setStyleSheet(f"color: #FFFFFF; font-weight: bold; font-size: {self._px(13)}px;")
        self.extra_label.setStyleSheet(f"color: #4FC3F7; font-weight: bold; font-size: {self._px(13)}px;")
        self.cp_label.setStyleSheet(f"color: #F0F0F0; font-weight: bold; font-size: {self._px(13)}px;")
        self.item_level_label.setStyleSheet(f"color: #FFD54F; font-weight: bold; font-size: {self._px(13)}px;")
        self.date_label.setStyleSheet(f"color: #888888; font-size: {self._px(8)}px;")
        btn_size = self._px(14)
        self.delete_btn.setFixedSize(btn_size, btn_size)
        self.delete_btn.setStyleSheet(
            "QPushButton { background-color: rgba(255,255,255,15); color: #999999; "
            f"border: none; border-radius: {max(1, btn_size // 2)}px; font-size: {self._px(8)}px; }}"
            "QPushButton:hover { background-color: rgba(240,80,80,140); color: #FFFFFF; }"
        )

    def apply_scale(self, scale):
        """MainWindow가 글자 크기 설정을 바꿀 때, 이미 화면에 떠 있는 행에도 재시작 없이
        즉시 반영하기 위해 호출한다 (2026-08-08 추가)."""
        self.scale = scale
        self._apply_scale_styles()

    def _handle_delete_clicked(self):
        if self._on_delete is not None:
            self._on_delete(self.nickname)

    def update_record(self, record):
        self.sanctuary_label.setText(format_sanctuaries(record.get("sanctuary_counts")))
        updated = record.get("sanctuary_updated") or "미수신"
        self.sanctuary_label.setToolTip(f"성역 스냅샷 갱신: {updated}\n루드라 ID는 잠정 매핑. 입장 후에는 다음 스냅샷 수신 시 갱신됩니다.")
        base = record.get("oath_energy_base")
        self.base_label.setText(_fmt_info_cell(base))
        self.extra_label.setText(_fmt_info_cell(record.get("oath_energy_dynamic")))
        self.cp_label.setText(_fmt_combat_power_cell(record.get("combat_power")))
        self.item_level_label.setText(_fmt_info_cell(record.get("item_level")))
        full_date = _fmt_date_cell(record.get("last_updated"))
        # 컴팩트 모드라 폭이 좁음 - 연도(YYYY-)는 생략하고 월/일/시각만 표시, 전체
        # 날짜는 툴팁으로 확인 가능하게 유지 (공유 포맷터 _fmt_date_cell 자체는 안 건드림 -
        # Tkinter 쪽 run_gui도 같은 함수를 쓰므로).
        short_date = full_date
        if len(full_date) > 5 and full_date[4] == "-" and full_date[:4].isdigit():
            short_date = full_date[5:]
        self.date_label.setText(short_date)
        self.date_label.setToolTip(full_date)
        self.fill_bar.setValue(max(0, min(840, base or 0)))


class _TitleBar(QWidget):
    """프레임리스 창이라 OS 타이틀바가 없다 - 드래그 이동은 여기서 직접 구현한다."""

    HEIGHT_BASE = 28
    BTN_SIZE_BASE = 18

    def __init__(self, main_window, scale=1.0):
        super().__init__()
        self._main_window = main_window
        self._drag_pos = None
        self.scale = scale

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 6, 0)
        layout.setSpacing(4)

        # 2026-07-19 수정: 사용자 요청 - "템렙이 로고에도 찍히게 해줘". 타이틀바 텍스트 라벨을
        # self에 저장해서 set_item_level()로 나중에 갱신할 수 있게 함(원래는 지역변수라 한 번
        # 찍고 끝이었음).
        self._title_base = "⚡ AION2 오드에너지"
        self.title_label = QLabel(self._title_base)
        layout.addWidget(self.title_label)
        layout.addStretch(1)

        self.refresh_btn = self._make_icon_button("⟳", "새로고침 (저장된 값 다시 불러오기)")
        self.lock_btn = self._make_icon_button(
            "🔓", "잠금 (클릭 통과 + 배경 완전 투명 오버레이 모드, 해제는 트레이 아이콘에서)"
        )
        self.close_btn = self._make_icon_button("✕", "닫기")
        layout.addWidget(self.refresh_btn)
        layout.addWidget(self.lock_btn)
        layout.addWidget(self.close_btn)
        self._icon_buttons = (self.refresh_btn, self.lock_btn, self.close_btn)

        self._apply_scale_styles()

    def set_item_level(self, item_level):
        if item_level is None:
            self.title_label.setText(self._title_base)
        else:
            self.title_label.setText(f"{self._title_base} · 템렙 {item_level}")

    def _px(self, base_px):
        return max(1, round(base_px * self.scale))

    def _make_icon_button(self, text, tooltip):
        """버튼 생성만 담당(폰트/크기는 _apply_scale_styles가 따로 적용) - 2026-08-08에
        기존 _icon_button에서 스타일 적용 부분을 분리."""
        btn = QPushButton(text)
        btn.setToolTip(tooltip)
        btn.setCursor(Qt.PointingHandCursor)
        return btn

    def _apply_scale_styles(self):
        self.setFixedHeight(self._px(self.HEIGHT_BASE))
        self.title_label.setStyleSheet(
            f"color: #EEEEEE; font-weight: bold; font-size: {self._px(10)}px;"
        )
        btn_size = self._px(self.BTN_SIZE_BASE)
        for btn in self._icon_buttons:
            btn.setFixedSize(btn_size, btn_size)
            btn.setStyleSheet(
                "QPushButton { background-color: rgba(255,255,255,18); color: #DDDDDD; "
                f"border: none; border-radius: {max(1, btn_size // 2)}px; font-size: {self._px(9)}px; }}"
                "QPushButton:hover { background-color: rgba(255,255,255,40); }"
            )

    def apply_scale(self, scale):
        """MainWindow.set_font_scale_index()가 호출 (2026-08-08 추가)."""
        self.scale = scale
        self._apply_scale_styles()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and not self._main_window.locked:
            self._drag_pos = event.globalPosition().toPoint() - self._main_window.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and not self._main_window.locked:
            self._main_window.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None


class MainWindow(QWidget):
    # 2026-08-08 추가: 글자 크기 배율에 맞춰 창 너비도 같이 조절하기 위한 기준값(배율 1.0=보통
    # 기준). 높이는 _resize_to_fit()이 매번 내용물 sizeHint로 다시 계산하므로 여기 넣지 않는다.
    BASE_WIDTH = 388
    BASE_MIN_WIDTH = 348

    def __init__(self, event_queue, status_queue, opacity=0.90, store=None):
        super().__init__()
        self.event_queue = event_queue
        self.status_queue = status_queue
        # 2026-07-19 추가: 삭제 버튼 기능을 위해 CharacterStore 인스턴스를 밖에서 주입받을
        # 수 있게 함. 실시간 캡처 모드(main())에서는 LiveCapture가 이미 갖고 있는
        # capture.store를 그대로 넘겨받아 공유한다 - GUI가 자기 것만 따로 새로 만들면(예전
        # 방식) 삭제 시 GUI 쪽 인스턴스에서만 지워지고, LiveCapture 쪽 인스턴스는 메모리에
        # 옛 상태를 그대로 들고 있다가 다음 저장 때 삭제된 캐릭터를 되살려버리는(clobber)
        # 문제가 생김 - 이미 주기적 오드 재생 스케줄러에서 같은 이유로 capture.store를
        # 재사용하고 있던 것과 동일한 패턴. store가 안 주어지면(리플레이/단독 실행 모드)
        # 기존처럼 새로 하나 만든다.
        self.store = store if store is not None else CharacterStore()
        self._display_save_revision = -1
        self.locked = False
        self._unlocked_opacity = opacity  # 잠금 해제 시 복원할 패널 투명도

        # 2026-08-08 추가: 글자 크기 설정 - 마지막으로 저장된 값을 불러와서 시작한다.
        self.font_scale_index = _load_font_scale_index()
        self.font_scale = FONT_SCALE_STEPS[self.font_scale_index]

        self.setWindowTitle("AION2 오드에너지")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        # 진짜 픽셀 단위 배경 투명 - card(QFrame)의 border-radius 바깥 영역이 완전히
        # 안 보이게 된다 (Tkinter -alpha처럼 글자까지 같이 비치는 게 아님).
        self.setAttribute(Qt.WA_TranslucentBackground)
        # 2026-07-18 재수정: 참고 이미지(다른 DPS미터류 오버레이, 훨씬 작고 촘촘함)를
        # 보여주며 "이정도 수준으로 크기를 줄이고싶어" - 전체적으로 훨씬 컴팩트하게.
        # 2026-07-19 수정: 템레벨 칸이 추가되면서 320px는 너무 좁아짐(날짜 칸과 겹침) - 370으로 확장.
        # 2026-07-19 재수정: 삭제(✕) 버튼 칸이 추가되면서 다시 좁아짐 - 388로 확장.
        # 2026-08-08 수정: 저장된 글자 크기 배율에 맞춰 시작 너비도 같이 스케일.
        self.resize(self._px(self.BASE_WIDTH), 540)
        self.setMinimumHeight(240)
        self.setMinimumWidth(self._px(self.BASE_MIN_WIDTH))

        outer = QVBoxLayout(self)
        outer.setContentsMargins(5, 5, 5, 5)

        self.card = QFrame()
        self.card.setObjectName("card")
        self._apply_opacity(opacity)
        outer.addWidget(self.card)

        self.card_layout = card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(0, 0, 0, 6)
        card_layout.setSpacing(0)

        self.title_bar = _TitleBar(self, scale=self.font_scale)
        card_layout.addWidget(self.title_bar)

        summary = QVBoxLayout()
        summary.setContentsMargins(10, 4, 10, 4)
        summary.setSpacing(1)
        self.value_label = QLabel("대기 중...")
        summary_top = QHBoxLayout()
        summary_top.addWidget(self.value_label, 1)
        self.selected_nickname = None
        self.selected_label = QLabel("행을 클릭해 선택")
        self.selected_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.selected_label.setWordWrap(True)
        self.selected_label.setTextFormat(Qt.PlainText)
        summary_top.addWidget(self.selected_label, 1)
        summary.addLayout(summary_top)

        self.delta_label = QLabel("아이템을 사용하거나 캐릭터로 접속하면 표시됩니다")
        self.delta_label.setWordWrap(True)
        # 2026-07-18 수정: 사용자 요청 - 변화량 줄("+15"/"-1780" 등)을 화면에서 안 보이게
        # 해달라 함. breakdown_label이 이미 "기본 X + 추가 Y = Z"로 같은 정보를 다 보여주고
        # 있어서 중복 정보였음. render_summary는 그대로 delta_label.setText(...)를 계속
        # 호출하지만(로직 안 건드림) 위젯 자체를 숨겨서 레이아웃에서 자리도 차지 안 하게 함 -
        # 나중에 다시 보이게 하고 싶으면 이 setVisible(False) 한 줄만 지우면 됨.
        self.delta_label.setVisible(False)
        summary.addWidget(self.delta_label)

        self.updated_label = QLabel("")
        summary.addWidget(self.updated_label)
        card_layout.addLayout(summary)

        self.section_label = QLabel("캐릭터 현황")
        self.section_label.setContentsMargins(10, 2, 10, 2)
        card_layout.addWidget(self.section_label)

        # 현황 목록만 스크롤하고 상단/하단은 고정한다.
        self.rows_container = QWidget()
        self.rows_container.setStyleSheet("background: transparent;")
        self.rows_layout = QVBoxLayout(self.rows_container)
        self.rows_layout.setContentsMargins(10, 0, 10, 4)
        self.rows_layout.setSpacing(3)
        self.rows_layout.setAlignment(Qt.AlignTop)
        self.scroll_area = RowScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setWidget(self.rows_container)
        self.scroll_area.setStyleSheet("""
            QScrollArea { background: transparent; }
            QScrollBar:vertical {
                background: #222630;
                width: 10px;
                margin: 5px 1px 5px 1px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #91A5BA;
                min-height: 32px;
                border: 1px solid #A5B8CA;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #BCD4E8;
                border-color: #D2E5F4;
            }
            QScrollBar::handle:vertical:pressed {
                background: #70C9F3;
                border-color: #A0DEFA;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
                border: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: transparent;
            }
        """)
        card_layout.addWidget(self.scroll_area, 1)

        # 2026-07-18 수정: 사용자 요청 - "기본 700 + 추가 45 = 745" 줄(예전 breakdown_label)이
        # 상단에 항상 떠 있는 게 "사실 이부분도 필요없긴한데", 대신 "기본 + 추가는 밑에
        # 토스트식으로 잠깐 보여줄만해" - 캐릭터 목록 밑쪽에, 값이 바뀔 때만 잠깐 떴다가
        # 자동으로 사라지는 토스트 라벨로 옮김(_show_toast/_toast_timer 참고).
        self.toast_label = QLabel("")
        self.toast_label.setAlignment(Qt.AlignCenter)
        self.toast_label.setContentsMargins(10, 0, 10, 0)
        self.toast_label.setVisible(False)
        card_layout.addWidget(self.toast_label)

        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(self._hide_toast)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setContentsMargins(10, 2, 10, 0)
        card_layout.addWidget(self.status_label)

        self.title_bar.refresh_btn.clicked.connect(self._on_refresh)
        self.title_bar.lock_btn.clicked.connect(self._on_toggle_lock)
        self.title_bar.close_btn.clicked.connect(self.close)

        # ---- 기존 run_gui(Tkinter)와 동일한 데이터 흐름 상태 (그대로 이식) ----
        self.row_by_nickname = {}
        self._displayed_records = {}
        self._summary_record = {}
        self.entity_nickname = {}
        self.pending_records = {}

        self._apply_own_font_styles()

        self._load_initial()

        self.tray_icon = None
        self.tray_lock_action = None
        self.tray_font_level_action = None
        self.tray_font_bigger_action = None
        self.tray_font_smaller_action = None
        self._create_tray_icon()

        # 2026-08-08 추가: 트레이 없이도(또는 트레이를 찾기 전에) 키보드로 바로 조절할 수
        # 있도록 창 단위 단축키도 같이 둔다 - 창이 포커스를 갖고 있을 때만 동작하므로
        # 트레이 메뉴가 항상 되는 주 경로이고 이건 편의 기능.
        QShortcut(QKeySequence("Ctrl+="), self, activated=lambda: self._step_font_scale(+1))
        QShortcut(QKeySequence("Ctrl+-"), self, activated=lambda: self._step_font_scale(-1))

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_queue)
        self.timer.start(150)
        self._size_save_timer = QTimer(self)
        self._size_save_timer.setSingleShot(True)
        self._size_save_timer.timeout.connect(lambda: _save_gui_settings(window_width=self.width(), window_height=self.height()))
        try:
            with open(GUI_SETTINGS_PATH, "r", encoding="utf-8") as stream:
                settings = json.load(stream)
            screen = self.screen().availableGeometry()
            self.resize(min(screen.width(), max(self.minimumWidth(), int(settings.get("window_width", self.width())))),
                        min(screen.height(), max(self.minimumHeight(), int(settings.get("window_height", self.height())))))
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        self._row_snap_timer = QTimer(self)
        self._row_snap_timer.setSingleShot(True)
        self._row_snap_timer.timeout.connect(self._snap_height_to_rows)
        self._row_snap_timer.start(0)
        self._resize_handles = [ResizeHandle(self, edge) for edge in range(1, 9)]
        self._position_resize_handles()

    def _px(self, base_px):
        return max(1, round(base_px * self.font_scale))

    def _apply_opacity(self, opacity):
        opacity = max(0.3, min(1.0, opacity))
        alpha = int(opacity * 255)
        self.card.setStyleSheet(
            f"#card {{ background-color: rgba(16,16,16,{alpha}); border-radius: 10px; }}"
        )

    def _apply_own_font_styles(self):
        """MainWindow 자체 라벨들(캐릭터 행/타이틀바가 아닌 상단 요약 영역)의 폰트 크기를
        현재 self.font_scale 기준으로 다시 계산해 입힌다 (2026-08-08 추가) - __init__과
        set_font_scale_index() 양쪽에서 공유."""
        self.value_label.setStyleSheet(
            f"color: #7CFC00; font-size: {self._px(18)}px; font-weight: bold;"
        )
        self.delta_label.setStyleSheet(f"color: #999999; font-size: {self._px(9)}px;")
        self.updated_label.setStyleSheet(f"color: #777777; font-size: {self._px(8)}px;")
        self.section_label.setStyleSheet(
            f"color: #CCCCCC; font-size: {self._px(9)}px; font-weight: bold;"
        )
        self.toast_label.setStyleSheet(
            f"background-color: rgba(124,252,0,30); color: #CFFFB0; font-size: {self._px(10)}px; "
            f"font-weight: bold; border-radius: {self._px(8)}px; padding: {self._px(3)}px {self._px(8)}px;"
        )
        self.status_label.setStyleSheet(f"color: #666666; font-size: {self._px(8)}px;")

    # ---- 글자 크기 설정 (2026-08-08 추가) ----

    def _step_font_scale(self, direction):
        """트레이 메뉴/단축키 공용 - direction=+1이면 한 단계 크게, -1이면 한 단계 작게."""
        new_index = self.font_scale_index + direction
        new_index = max(0, min(len(FONT_SCALE_STEPS) - 1, new_index))
        if new_index != self.font_scale_index:
            self.set_font_scale_index(new_index)

    def set_font_scale_index(self, index):
        """글자 크기 설정을 바꾸고, 이미 떠 있는 모든 위젯(자기 자신/타이틀바/캐릭터 행
        전부)에 재시작 없이 즉시 반영한 뒤 설정 파일에 저장한다."""
        index = max(0, min(len(FONT_SCALE_STEPS) - 1, index))
        self.font_scale_index = index
        self.font_scale = FONT_SCALE_STEPS[index]

        self._apply_own_font_styles()
        self.title_bar.apply_scale(self.font_scale)
        for row in self.row_by_nickname.values():
            row.apply_scale(self.font_scale)

        # 창 너비도 배율에 맞춰 다시 잡는다 - 높이는 _resize_to_fit()이 이어서 계산.
        self.setMinimumWidth(self._px(self.BASE_MIN_WIDTH))
        self.resize(self._px(self.BASE_WIDTH), self.height())
        self._resize_to_fit()

        self._update_font_tray_labels()
        _save_font_scale_index(index)
        self.status_label.setText(f"[알림] 글자 크기: {FONT_SCALE_LABELS[index]}")

    def _update_font_tray_labels(self):
        if self.tray_font_level_action is not None:
            self.tray_font_level_action.setText(f"글자 크기: {FONT_SCALE_LABELS[self.font_scale_index]}")
        if self.tray_font_bigger_action is not None:
            self.tray_font_bigger_action.setEnabled(self.font_scale_index < len(FONT_SCALE_STEPS) - 1)
        if self.tray_font_smaller_action is not None:
            self.tray_font_smaller_action.setEnabled(self.font_scale_index > 0)

    # ---- 버튼 동작 ----

    def _on_refresh(self):
        self._sync_display_from_json(manual=True)

    def _sync_after_save(self):
        # 기존 GUI 이벤트 처리 주기를 사용하되 저장이 없으면 파일을 읽지 않는다.
        # 여러 저장이 쌓이면 최신 JSON을 한 번 읽어 반영한다.
        revision = self.store.save_revision
        if revision != self._display_save_revision:
            self._display_save_revision = revision
            self._sync_display_from_json()

    def _sync_display_from_json(self, manual=False):
        """JSON을 화면의 기준으로 사용한다. 캡처가 쓰는 공유 메모리는 덮어쓰지 않는다."""
        try:
            with open(self.store.path, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            if not isinstance(data, dict):
                raise ValueError("캐릭터 목록 형식이 아닙니다")
            for nickname, record in data.items():
                if not isinstance(record, dict) or record.get("nickname") != nickname:
                    raise ValueError("캐릭터 정보 형식이 올바르지 않습니다")
                if not isinstance(record.get("last_updated") or "", str):
                    raise ValueError("갱신 시각 형식이 올바르지 않습니다")
                for field in ("oath_energy", "oath_energy_base", "oath_energy_dynamic",
                              "combat_power", "item_level", "last_delta"):
                    value = record.get(field)
                    if value is not None and type(value) is not int:
                        raise ValueError("캐릭터 수치 형식이 올바르지 않습니다")
        except (OSError, ValueError) as exc:
            self.status_label.setText(f"[JSON 동기화 실패] 기존 화면 유지: {exc}")
            return False

        records = sorted(data.values(), key=lambda r: r.get("last_updated") or "")
        records = records[-STATUS_ROW_CAP:]
        wanted = {record["nickname"] for record in records}
        changed = False
        for nickname in list(self.row_by_nickname):
            if nickname not in wanted:
                row = self.row_by_nickname.pop(nickname)
                self.rows_layout.removeWidget(row)
                row.deleteLater()
                self._displayed_records.pop(nickname, None)
                changed = True
        for record in records:
            nickname = record["nickname"]
            if nickname not in self.row_by_nickname or self._displayed_records.get(nickname) != record:
                # 닉네임이 확정된 JSON이므로 entity_id 기반 캐시를 변경하지 않는다.
                self._place_row(nickname, record)
                changed = True

        summary = data.get(self._summary_record.get("nickname"))
        if summary is None:
            summary = records[-1] if records else {}
        if self._summary_record != summary:
            self._render_summary(summary)
            if not summary:
                self._hide_toast()
            changed = True
        if changed:
            self._resize_to_fit()
        if manual or changed or self.status_label.text().startswith("[JSON 동기화 실패]"):
            self.status_label.setText("[알림] JSON 기준으로 화면 동기화 완료")
        return True

    def _on_toggle_lock(self):
        self._set_locked(not self.locked)

    def _set_locked(self, locked):
        """잠금 상태 전환. 잠그면: (1) 창 전체를 클릭 통과시켜 마우스 입력이 뒤에 있는
        게임 화면으로 그대로 전달되고, (2) 패널 배경을 완전히 투명하게 만들어 글자/표만
        게임 화면 위에 떠 보이게 한다. 사용자 요청 그대로: "자물쇠 모양을 누르면 효과가
        클릭이 막히고 배경이 완전 투명이 되는거야". 해제는 창 자체가 클릭을 안 받으므로
        타이틀바 버튼이 아니라 트레이 아이콘 메뉴(_create_tray_icon)에서만 가능하다."""
        self.locked = locked
        for handle in getattr(self, "_resize_handles", []):
            handle.setVisible(not locked)
        self.title_bar.lock_btn.setText("🔒" if locked else "🔓")
        self.setAttribute(Qt.WA_TransparentForMouseEvents, locked)
        if locked:
            self.card.setStyleSheet("#card { background-color: transparent; border-radius: 10px; }")
        else:
            self._apply_opacity(self._unlocked_opacity)
        if self.tray_lock_action is not None:
            self.tray_lock_action.setText("잠금 해제" if locked else "잠금")

    def _create_tray_icon(self):
        """잠금(클릭 통과) 상태에서도 항상 접근 가능한 안전장치 - 메인 창과 별개의
        위젯이라 창이 클릭 통과 상태여도 트레이 아이콘은 정상적으로 클릭된다. 글자 크기
        설정도 같은 이유로 여기(트레이 메뉴)에 둔다(2026-08-08) - 창이 잠겨 있어도
        조절할 수 있어야 하므로."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return  # 트레이가 없는 환경(일부 리눅스 등) - 조용히 건너뜀

        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor("#7CFC00"))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(4, 4, 24, 24)
        painter.end()

        self.tray_icon = QSystemTrayIcon(QIcon(pixmap), self)
        self.tray_icon.setToolTip("AION2 오드에너지")

        menu = QMenu()
        self.tray_lock_action = QAction("잠금", self)
        self.tray_lock_action.triggered.connect(lambda: self._set_locked(not self.locked))
        menu.addAction(self.tray_lock_action)

        show_action = QAction("창 보이기", self)
        show_action.triggered.connect(self._bring_to_front)
        menu.addAction(show_action)

        menu.addSeparator()

        # 2026-08-08 추가: 글자 크기 설정. 현재 단계를 보여주는 비활성 라벨 액션 + 크게/작게
        # 두 액션. 슬라이더/서브메뉴 대신 이 세 줄로 충분히 직관적이라 판단.
        self.tray_font_level_action = QAction("", self)
        self.tray_font_level_action.setEnabled(False)
        menu.addAction(self.tray_font_level_action)

        self.tray_font_bigger_action = QAction("글자 크기 크게 (Ctrl+=)", self)
        self.tray_font_bigger_action.triggered.connect(lambda: self._step_font_scale(+1))
        menu.addAction(self.tray_font_bigger_action)

        self.tray_font_smaller_action = QAction("글자 크기 작게 (Ctrl+-)", self)
        self.tray_font_smaller_action.triggered.connect(lambda: self._step_font_scale(-1))
        menu.addAction(self.tray_font_smaller_action)

        self._update_font_tray_labels()

        menu.addSeparator()
        quit_action = QAction("종료", self)
        quit_action.triggered.connect(self._quit)
        menu.addAction(quit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.show()

    def _bring_to_front(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _quit(self):
        self.close()

    def closeEvent(self, event):
        self.timer.stop()
        self._size_save_timer.stop()
        self._row_snap_timer.stop()
        self._toast_timer.stop()
        if self.tray_icon is not None:
            self.tray_icon.hide()
        event.accept()
        QApplication.instance().quit()

    # ---- 데이터 반영 (기존 run_gui의 render_summary/upsert_status_row/poll_queue 이식) ----

    def _load_initial(self):
        try:
            # 2026-07-19 수정: 읽기 전용 새로고침이었을 땐 매번 새 CharacterStore()를 만들어도
            # 상관없었지만(생성자가 매번 파일을 새로 읽으니까), 삭제 기능이 생기면서 반드시
            # self.store(생성자에서 주입받은, 실시간 캡처와 공유하는 그 인스턴스)를 써야 한다
            # - 새로 만들면 그 인스턴스로 delete_character를 호출해도 self.store/LiveCapture가
            # 들고 있는 다른 인스턴스엔 반영이 안 됨.
            store = self.store
            initial_nickname = store.most_recent_character()
            if initial_nickname is not None:
                self._render_summary(store.data.get(initial_nickname, {}))
            records = list(store.data.values())
            records.sort(key=lambda r: r.get("last_updated") or "")
            for rec in records:
                self._upsert_row(rec, nickname_confirmed=True)
        except Exception:
            pass

    def _render_summary(self, record):
        self._summary_record = dict(record)
        total = record.get("oath_energy")
        nickname = record.get("nickname") or "캐릭터 확인 중"
        self.value_label.setText(f"{nickname} / {total}" if total is not None else "대기 중...")

        # 2026-07-19 추가: 사용자 요청 - "템렙이 로고에도 찍히게 해줘". _poll_queue가 오드에너지/
        # 전투력/템레벨 이벤트 전부에 대해 _render_summary를 부르므로(레코드가 있는 모든 이벤트),
        # 여기 한 곳만 고치면 템레벨이 갱신되는 모든 경로에서 타이틀바도 같이 갱신된다.
        self.title_bar.set_item_level(record.get("item_level"))

        base = record.get("oath_energy_base")
        dynamic = record.get("oath_energy_dynamic")
        if base is not None and dynamic is not None:
            self._show_toast(f"기본 {base} + 추가 {dynamic} = {base + dynamic}")

        last_updated = record.get("last_updated")
        self.updated_label.setText(f"마지막 갱신: {last_updated}" if last_updated else "")

        last_delta = record.get("last_delta")
        if last_delta is None:
            self.delta_label.setText("(변화량 알 수 없음, 최초 값)")
        else:
            sign = "+" if last_delta >= 0 else ""
            self.delta_label.setText(f"{sign}{last_delta}")

    def _show_toast(self, text, duration_ms=2500):
        """"기본 700 + 추가 45 = 745" 같은 값을 상단에 항상 띄워두지 않고, 값이 갱신될
        때만 캐릭터 목록 밑에 잠깐 떴다가 자동으로 사라지는 토스트로 보여준다 (사용자 요청,
        2026-07-18: "기본 + 추가는 밑에 토스트식으로 잠깐 보여줄만해"). 창이 내용에 맞춰
        자동으로 커지는 구조라(_resize_to_fit) 토스트가 뜨고 사라질 때도 창 높이가 같이
        맞춰지도록 매번 호출한다."""
        self.toast_label.setText(text)
        self.toast_label.setVisible(True)
        self._resize_to_fit()
        self._toast_timer.start(duration_ms)  # 이미 타이머가 돌고 있었으면 자동으로 재시작됨

    def _hide_toast(self):
        if getattr(self, "_native_resizing", False):
            self._toast_timer.start(150)
            return
        self.toast_label.setVisible(False)
        self._resize_to_fit()

    def _upsert_row(self, record, nickname_confirmed=False):
        # 공통 항목 ID는 캐릭터 식별자가 아니다. 이름 확인/보류 병합은
        # monitor가 담당하며, 화면은 레코드에 명시된 닉네임만 사용한다.
        nickname = record.get("nickname")
        if not nickname:
            return
        entity_id = record.get("entity_id")
        if entity_id is not None:
            self.entity_nickname[entity_id] = nickname
            self.pending_records.pop(entity_id, None)
        self._place_row(nickname, record)

    def _place_row(self, nickname, record):
        row = self.row_by_nickname.get(nickname)
        if row is None:
            # 2026-08-08 수정: 새로 만드는 행도 지금 설정된 글자 크기를 바로 받도록 scale 전달.
            row = CharacterRow(nickname, on_delete=self._on_delete_row, scale=self.font_scale)
            row._on_select = self._select_character
            self.row_by_nickname[nickname] = row
            self.rows_layout.insertWidget(0, row)
            # STATUS_ROW_CAP 초과분은 가장 오래된(맨 아래) 것부터 제거한다. 스크롤
            # 영역을 없앤 뒤로(2026-07-18) rows_layout엔 더 이상 트레일링 stretch
            # 아이템이 없으므로 count()가 곧 실제 행 개수다.
            row_count = self.rows_layout.count()
            if row_count > STATUS_ROW_CAP:
                for i in range(row_count - 1, STATUS_ROW_CAP - 1, -1):
                    old_item = self.rows_layout.itemAt(i)
                    if old_item and old_item.widget():
                        old_nick = old_item.widget().nickname
                        self.row_by_nickname.pop(old_nick, None)
                        old_item.widget().deleteLater()
                        self.rows_layout.removeItem(old_item)
        else:
            self.rows_layout.removeWidget(row)
            self.rows_layout.insertWidget(0, row)  # 방금 갱신된 캐릭터를 맨 위로
        row.update_record(record)
        self._displayed_records[nickname] = dict(record)
        self._resize_to_fit()

    def _resize_to_fit(self):
        self._refresh_selection()
        self.rows_layout.invalidate()
        self.rows_container.updateGeometry()
        if hasattr(self, "_row_snap_timer"):
            self._row_snap_timer.start(0)

    def _select_character(self, nickname):
        self.selected_nickname = None if self.selected_nickname == nickname else nickname
        self._refresh_selection()

    def _refresh_selection(self):
        if self.selected_nickname not in self.row_by_nickname:
            self.selected_nickname = None
        for nickname, row in self.row_by_nickname.items():
            row.set_selected(nickname == self.selected_nickname)
        record = self._displayed_records.get(self.selected_nickname, {})
        base, extra = record.get("oath_energy_base"), record.get("oath_energy_dynamic")
        total = base + extra if base is not None and extra is not None else record.get("oath_energy")
        self.selected_label.setStyleSheet(
            f"color: #9ED8FF; font-size: {self._px(12)}px; font-weight: bold;"
        )
        self.selected_label.setText(
            f"선택: {self.selected_nickname}\n총 오드 {_fmt_info_cell(total)}"
            if self.selected_nickname else "행을 클릭해 선택"
        )

    def _snap_height_to_rows(self):
        if getattr(self, "_snapping_rows", False) or getattr(self, "_native_resizing", False):
            return
        self._snapping_rows = True
        try:
            self.layout().activate()
            self.card_layout.activate()
            # 카드의 실제 최소 폭에 목록 여백과 스크롤바 폭을 별도로 확보한다.
            # 스크롤바가 생기고 사라질 때 최소 폭이 흔들리지 않도록 항상 예약한다.
            row_width = max((row.minimumSizeHint().width()
                             for row in self.row_by_nickname.values()), default=0)
            margins = self.rows_layout.contentsMargins()
            scrollbar_width = self.scroll_area.verticalScrollBar().sizeHint().width()
            outer_width = max(0, self.width() - self.scroll_area.width())
            minimum_width = max(self._px(self.BASE_MIN_WIDTH),
                                row_width + margins.left() + margins.right()
                                + scrollbar_width + outer_width + 4)
            self.setMinimumWidth(minimum_width)
            count = len(self.row_by_nickname)
            row_height = self._px(CharacterRow.ROW_HEIGHT_BASE)
            spacing = self.rows_layout.spacing()
            step = row_height + spacing
            margins = self.rows_layout.contentsMargins()
            overhead = self.height() - self.scroll_area.viewport().height() + margins.top() + margins.bottom()
            self._row_resize_metrics = (overhead, row_height, spacing, count)
            if count:
                screen_height = self.screen().availableGeometry().height()
                capacity = max(1, (screen_height - overhead + spacing) // step)
                maximum_rows = min(count, capacity)
                visible = max(1, min(maximum_rows, int((self.height() - overhead + spacing) / step + 0.5)))
                minimum = overhead + row_height
                maximum = overhead + maximum_rows * step - spacing
                target = overhead + visible * step - spacing
            else:
                minimum = maximum = target = overhead + 40
            self.setMinimumHeight(minimum)
            self.setMaximumHeight(maximum)
            self.resize(self.width(), target)
            bar = self.scroll_area.verticalScrollBar()
            self.scroll_area.row_step = step
            bar.setSingleStep(step)
            bar.setPageStep(max(1, self.scroll_area.viewport().height() // step) * step)
            bar.setValue(round(bar.value() / step) * step)
        finally:
            self._snapping_rows = False

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_resize_handles"):
            self._position_resize_handles()
        if hasattr(self, "_size_save_timer"):
            self._size_save_timer.start(400)
        if (hasattr(self, "_row_snap_timer") and not getattr(self, "_snapping_rows", False)
                and not getattr(self, "_native_resizing", False)):
            self._row_snap_timer.start(80)

    def _position_resize_handles(self):
        width, height = self.width(), self.height()
        border, corner = 5, 10
        boxes = {1: (0, corner, border, height-2*corner),
                 2: (width-border, corner, border, height-2*corner),
                 3: (corner, 0, width-2*corner, border),
                 6: (corner, height-border, width-2*corner, border),
                 4: (0, 0, corner, corner),
                 5: (width-corner, 0, corner, corner),
                 7: (0, height-corner, corner, corner),
                 # 표식과 실제 클릭 영역을 어두운 카드 안쪽으로 이동한다.
                 8: (width-22, height-22, 16, 16)}
        for handle in self._resize_handles:
            handle.setGeometry(*boxes[handle.edge])
            handle.raise_()

    def _on_delete_row(self, nickname):
        """캐릭터 행의 ✕ 버튼 클릭 처리 (2026-07-19 추가, 사용자 요청: "안보고싶은캐릭터
        삭제 버튼"). 되돌릴 수 없는 동작이라 먼저 확인 대화상자를 띄운다. 확인되면
        (1) self.store(공유 인스턴스)에서 영구 삭제, (2) 화면에서 행 제거, (3) 그 닉네임을
        가리키던 entity_id -> 닉네임 캐시(entity_nickname)도 같이 정리해서, 삭제 직후 같은
        entity_id로 오는 이후 패킷이 죽은 닉네임에 잘못 매핑되는 걸 방지한다."""
        box = QMessageBox(self)
        box.setWindowTitle("캐릭터 삭제")
        box.setText(f"'{nickname}' 캐릭터를 목록에서 삭제할까요?\n(저장된 기록도 함께 지워집니다)")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return

        self.store.delete_character(nickname)

        row = self.row_by_nickname.pop(nickname, None)
        if row is not None:
            self.rows_layout.removeWidget(row)
            row.deleteLater()

        stale_ids = [eid for eid, n in self.entity_nickname.items() if n == nickname]
        for eid in stale_ids:
            self.entity_nickname.pop(eid, None)

        self._resize_to_fit()
        self.status_label.setText(f"[알림] '{nickname}' 삭제됨")

    def _refresh_all_rows_from_store(self):
        """정기충전(2/5/8/11/14/17/20/23시 +15 시뮬레이션, aion2_storage.py의
        catch_up_periodic_regen)처럼 개별 패킷 이벤트 없이 저장소 전체가 한 번에
        갱신되는 경우를 위한 화면 새로고침 (2026-08-13 추가).

        정기충전은 event_queue가 아니라 status_queue에 안내 메시지 하나만 올린다
        (_schedule_periodic_regen/_start_periodic_regen 참고) - 그런데 이 표의 행은
        지금까지 오직 event_queue로 들어온, 실제 패킷을 동반한 이벤트에서만 갱신됐다
        (_upsert_row는 event_queue 이벤트에서만 호출됨). 그 결과 JSON 파일(self.store.data)
        자체는 catch_up_periodic_regen이 정상적으로 갱신하지만, 지금 게임에 접속 중이 아닌
        (당장 실제 패킷이 안 오는) 캐릭터의 화면 카드는 다음 실제 패킷이 올 때까지 옛날
        숫자 그대로 남아있었다 - 사용자 보고("5시가 지났는데 미접속캐릭들의 오드가
        갱신이안된데")의 원인. 저장 자체는 문제 없었고 화면 반영 누락이었다.

        `_load_initial()`과 동일한 방식(store.data를 통째로 다시 그림)으로, 이미 화면에
        떠 있는 캐릭터든 아직 한 번도 안 뜬 캐릭터든 상관없이 저장된 전체 캐릭터를
        nickname_confirmed=True로 다시 그린다 - 초기 로딩과 마찬가지로 디스크에서 직접
        읽은 확정된 데이터이므로 안전하다."""
        for record in self.store.data.values():
            self._upsert_row(record, nickname_confirmed=True)

    def _poll_queue(self):
        # 드래그 중에는 카드/상태 라벨 갱신으로 크기 계산 기준이 변하지 않게 한다.
        # 큐는 보존되며 드래그가 끝나면 기존 주기로 처리된다.
        if getattr(self, "_native_resizing", False):
            return
        try:
            while True:
                ev = self.event_queue.get_nowait()

                forget_id = getattr(ev, "forget_entity_id", None)
                if forget_id is not None:
                    self.entity_nickname.pop(forget_id, None)
                    print(f"[알림] entity_id={forget_id} 닉네임 캐시 초기화 (캐릭터 전환 감지)")
                    continue

                record = getattr(ev, "record", None)
                if record:
                    self._render_summary(record)
                    nickname_confirmed = getattr(ev, "nickname_confirmed", False)
                    self._upsert_row(record, nickname_confirmed)
                    nick = record.get("nickname") or f"캐릭터(id={record.get('entity_id')})"
                    print(
                        f"[갱신] {nick}  오드={record.get('oath_energy')}  "
                        f"전투력={record.get('combat_power')}  "
                        f"닉네임확인={'예' if nickname_confirmed else '아니오'}"
                    )
                else:
                    self.value_label.setText(f"캐릭터 확인 중 / {ev.new_total}")
                    print(f"[오드에너지] 총량={ev.new_total} (레코드 스냅샷 없음)")
        except queue.Empty:
            pass
        try:
            while True:
                msg = self.status_queue.get_nowait()
                self.status_label.setText(msg)
                print(f"[상태] {msg}")
                # 2026-08-13 추가: 정기충전 성공 메시지("[정기충전][에러]"는 제외)가 오면
                # 저장소 전체를 화면에 다시 그려서 미접속 캐릭터도 즉시 반영되게 한다 -
                # _refresh_all_rows_from_store 참고.
                if msg.startswith("[정기충전]") and "[에러]" not in msg:
                    self._refresh_all_rows_from_store()
        except queue.Empty:
            pass


        self._sync_after_save()


def run_gui_qt(event_queue, status_queue, opacity=0.90, store=None):
    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow(event_queue, status_queue, opacity=opacity, store=store)
    window.show()
    app.exec()
