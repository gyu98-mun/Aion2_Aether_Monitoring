"""콘솔 없는 EXE의 print/오류 출력을 UTF-8 텍스트 로그로 보존한다."""
import datetime
import os
from pathlib import Path
import sys
import threading
import traceback

_log_stream = None


def setup_file_logging(directory=None):
    global _log_stream
    if _log_stream is not None:
        return Path(_log_stream.name)
    folder = Path(directory) if directory is not None else Path(sys.executable).resolve().parent / 'logs'
    filename = f'AION2_{datetime.date.today().isoformat()}.txt'
    try:
        folder.mkdir(parents=True, exist_ok=True)
        stream = (folder / filename).open('a', encoding='utf-8', buffering=1)
    except OSError:
        if directory is not None:
            raise
        # Program Files 등 실행 경로가 쓰기 금지일 때 사용자 폴더 사용.
        folder = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'AION2_OathEnergy' / 'logs'
        folder.mkdir(parents=True, exist_ok=True)
        stream = (folder / filename).open('a', encoding='utf-8', buffering=1)
    _log_stream = stream
    sys.stdout = stream
    sys.stderr = stream

    def exception_hook(exc_type, exc_value, exc_tb):
        print(f'[{datetime.datetime.now().isoformat(timespec="seconds")}] 처리되지 않은 오류', file=stream)
        traceback.print_exception(exc_type, exc_value, exc_tb, file=stream)
        stream.flush()

    sys.excepthook = exception_hook
    threading.excepthook = lambda args: exception_hook(args.exc_type, args.exc_value, args.exc_traceback)
    print(f'\n=== 실행 시작 {datetime.datetime.now().isoformat(timespec="seconds")} / PID {os.getpid()} ===')
    print(f'로그 파일: {folder / filename}')
    return folder / filename
