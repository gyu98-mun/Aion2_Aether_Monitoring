import datetime
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class FileLoggingTest(unittest.TestCase):
    def test_append_stdout_stderr_and_thread_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = '''
import sys, threading
from aion2_logging import setup_file_logging
sys.stdout = sys.stderr = None
setup_file_logging(sys.argv[1])
print('한글 로그')
print('stderr marker', file=sys.stderr)
def fail():
    raise RuntimeError('thread failure')
t = threading.Thread(target=fail)
t.start()
t.join()
'''
            for _ in range(2):
                subprocess.run([sys.executable, '-B', '-c', code, tmp], check=True,
                               cwd=Path(__file__).parent, capture_output=True)
            text = next(Path(tmp).glob('*.txt')).read_text(encoding='utf-8')
            self.assertEqual(text.count('한글 로그'), 2)
            self.assertEqual(text.count('stderr marker'), 2)
            self.assertIn('RuntimeError: thread failure', text)
            self.assertEqual(text.count('=== 실행 시작'), 2)

    def test_main_error_is_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = 'import sys; from aion2_logging import setup_file_logging; setup_file_logging(sys.argv[1]); raise ValueError("main failure")'
            result = subprocess.run([sys.executable, '-B', '-c', code, tmp],
                                    cwd=Path(__file__).parent, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ValueError: main failure', next(Path(tmp).glob('*.txt')).read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
