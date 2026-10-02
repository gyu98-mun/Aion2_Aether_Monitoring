import ast
import datetime
from pathlib import Path
import queue
import subprocess
import sys
import threading
import types
import unittest


def method(path, name, cls=None):
    tree = ast.parse(Path(__file__).with_name(path).read_text(encoding='utf-8'))
    nodes = tree.body
    if cls:
        nodes = next(n for n in nodes if isinstance(n, ast.ClassDef) and n.name == cls).body
    node = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.Module(body=[node], type_ignores=[])


class ShutdownTest(unittest.TestCase):
    def test_pending_regen_does_not_keep_process_alive(self):
        script = '''
import datetime, queue, threading, types
from test_shutdown import method
ns = dict(threading=threading, datetime=datetime,
          _next_periodic_regen_time=lambda: datetime.datetime.now()+datetime.timedelta(hours=3))
exec(compile(method('aion2_live_monitor.py', '_schedule_periodic_regen'), 'regen', 'exec'), ns)
capture = types.SimpleNamespace(_stop=threading.Event())
ns['_schedule_periodic_regen'](None, queue.Queue(), capture)
assert capture._regen_timer.daemon
'''
        result = subprocess.run([sys.executable, '-B', '-c', script], cwd=Path(__file__).parent, timeout=5, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stop_cancels_reservation_and_joins_capture(self):
        ns = dict(threading=threading)
        exec(compile(method('aion2_live_monitor.py', 'stop', 'LiveCapture'), 'stop', 'exec'), ns)
        calls = []
        capture = types.SimpleNamespace(_stop=threading.Event(),
            _regen_timer=types.SimpleNamespace(cancel=lambda: calls.append('cancel')),
            _thread=types.SimpleNamespace(join=lambda timeout: calls.append(('join', timeout))))
        ns['stop'](capture)
        self.assertTrue(capture._stop.is_set())
        self.assertEqual(calls, ['cancel', ('join', 2)])

    def test_close_stops_ui_and_quits_application(self):
        calls = []
        ns = dict(QApplication=types.SimpleNamespace(instance=lambda: types.SimpleNamespace(quit=lambda: calls.append('quit'))))
        exec(compile(method('aion2_gui_qt.py', 'closeEvent', 'MainWindow'), 'close', 'exec'), ns)
        timer = types.SimpleNamespace(stop=lambda: calls.append('stop'))
        window = types.SimpleNamespace(timer=timer, _size_save_timer=timer, _row_snap_timer=timer, _toast_timer=timer,
            tray_icon=types.SimpleNamespace(hide=lambda: calls.append('hide')))
        ns['closeEvent'](window, types.SimpleNamespace(accept=lambda: calls.append('accept')))
        self.assertEqual(calls, ['stop']*4 + ['hide', 'accept', 'quit'])

if __name__ == '__main__':
    unittest.main()
