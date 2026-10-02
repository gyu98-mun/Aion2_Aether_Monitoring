"""실제 GUI 행 라우팅 메서드를 Qt 없이 검사한다."""
import ast
from pathlib import Path
import types
import unittest


class CharacterRoutingTest(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(Path(__file__).with_name('aion2_gui_qt.py').read_text(encoding='utf-8'))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'MainWindow')
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_upsert_row')
        ns = {}
        exec(compile(ast.Module(body=[method], type_ignores=[]), 'routing', 'exec'), ns)
        self.rows = {}
        self.gui = types.SimpleNamespace(
            entity_nickname={}, pending_records={}, row_by_nickname=self.rows,
            _place_row=lambda name, record: self.rows.update({name: dict(record)}),
        )
        self.update = types.MethodType(ns['_upsert_row'], self.gui)
        self.update(dict(entity_id=51591, nickname='첫째', oath_energy=100), True)
        self.update(dict(entity_id=51591, nickname='둘째', oath_energy=200), True)

    def test_unidentified_energy_preserves_all_rows(self):
        before = {name: dict(record) for name, record in self.rows.items()}
        for confirmed in (False, True):
            self.update(dict(entity_id=51591, nickname=None, oath_energy=999), confirmed)
        self.assertEqual(self.rows, before)
        self.assertEqual(self.gui.pending_records, {})

    def test_named_update_uses_name_despite_shared_id(self):
        self.update(dict(entity_id=51591, nickname='첫째', oath_energy=300), False)
        self.assertEqual(self.rows['첫째']['oath_energy'], 300)
        self.assertEqual(self.rows['둘째']['oath_energy'], 200)

    def test_confirmation_does_not_merge_stale_gui_pending(self):
        self.gui.pending_records[51591] = dict(oath_energy=999, sanctuary_counts={'rudra': 9})
        record = dict(entity_id=51591, nickname='셋째', oath_energy=400)
        self.update(record, True)
        self.assertEqual(self.rows['셋째'], record)


if __name__ == '__main__':
    unittest.main()
