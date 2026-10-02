import json
import queue
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from aion2_sanctuary import parse_sanctuary_snapshot, format_sanctuaries
from aion2_storage import CharacterStore
from aion2_core import StreamProcessor, _encode_varint
from aion2_live_monitor import LiveCapture


class SanctuaryTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = json.loads(Path(__file__).with_name('sanctuary_test_fixtures.json').read_text(encoding='utf-8'))

    def test_real_snapshots(self):
        expected = {'활성성': [[0, 0], [0, 0], [0, 0], [1, 2]],
                    '조준성': [[0, 0], [1, 0], [1, 0], [1, 0]],
                    '엘프성': [[0, 0], [0, 0], [1, 0], [1, 0]]}
        for name, values in expected.items():
            with self.subTest(name=name):
                result = parse_sanctuary_snapshot(bytes.fromhex(self.fixtures[name]))
                self.assertEqual(list(result.values()), values)

    def test_missing_truncated_and_invalid_snapshot(self):
        raw = bytes.fromhex(self.fixtures['활성성'])
        self.assertIsNone(parse_sanctuary_snapshot(b''))
        self.assertIsNone(parse_sanctuary_snapshot(raw[:-1]))
        self.assertIsNone(parse_sanctuary_snapshot(raw.replace(bytes.fromhex('88 4a 5d 05'), b'xxxx')))

    def test_format(self):
        self.assertEqual(format_sanctuaries(None), '루드라 -   침식 -   무스펠 -   비탄 -')
        self.assertIn('비탄 1+2', format_sanctuaries(parse_sanctuary_snapshot(bytes.fromhex(self.fixtures['활성성']))))

    def test_capture_to_correct_character_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = LiveCapture.__new__(LiveCapture)
            capture.event_queue = queue.Queue()
            capture.status_queue = queue.Queue()
            capture.known_oath_id = 51591
            capture.known_base = 0
            capture.last_dynamic = None
            capture.current_nickname = '이전캐릭터'
            capture.current_server = 1001
            capture.current_job = 14
            capture.pending_oath = {}
            capture._switch_epoch = 0
            capture.store = CharacterStore(str(Path(tmp) / 'test.json'))
            processor = StreamProcessor(on_oath_energy=capture._on_oath_energy)
            for name in ('활성성', '조준성', '엘프성'):
                raw = bytes.fromhex(self.fixtures[name])
                body = b'\x0b\x61' + raw
                processor.on_packet_received(_encode_varint(len(body) + 4) + body)
                self.assertNotIn(name, capture.store.data)
                capture._on_nickname(SimpleNamespace(nickname=name, server=1001, job=14))
                self.assertEqual(capture.store.data[name]['sanctuary_counts'], parse_sanctuary_snapshot(raw))
            self.assertNotIn('이전캐릭터', capture.store.data)
            loaded = CharacterStore(capture.store.path)
            self.assertEqual(loaded.data['활성성']['sanctuary_counts']['90000008'], [1, 2])
            before = dict(loaded.data['활성성'])
            loaded.update_sanctuaries('활성성', None)
            self.assertEqual(loaded.data['활성성'], before)


if __name__ == '__main__':
    unittest.main()
