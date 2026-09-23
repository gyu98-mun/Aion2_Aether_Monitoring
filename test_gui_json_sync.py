"""GUI JSON 동기화 회귀 검사. Qt/캡처 없이 실제 메서드를 임시 파일로 실행한다."""
import ast
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from aion2_storage import CharacterStore


class Label:
    def __init__(self):
        self.value = ""

    def setText(self, value):
        self.value = value

    def text(self):
        return self.value


class JsonSyncTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "data.json"
        source = Path(__file__).with_name("aion2_gui_qt.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "MainWindow")
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_sync_display_from_json")
        namespace = {"json": json, "STATUS_ROW_CAP": 2}
        exec(compile(ast.Module(body=[method], type_ignores=[]), "gui_sync", "exec"), namespace)
        self.updates = []
        self.gui = types.SimpleNamespace(
            store=types.SimpleNamespace(path=str(self.path), data={"capture": "untouched"}),
            row_by_nickname={}, _displayed_records={}, _summary_record={},
            status_label=Label(), rows_layout=types.SimpleNamespace(removeWidget=lambda row: None),
            _resize_to_fit=lambda: None, _hide_toast=lambda: None,
        )
        def place(nickname, record):
            self.updates.append(nickname)
            self.gui.row_by_nickname[nickname] = types.SimpleNamespace(deleteLater=lambda: None)
            self.gui._displayed_records[nickname] = dict(record)
        self.gui._place_row = place
        self.gui._render_summary = lambda record: setattr(self.gui, "_summary_record", dict(record))
        self.sync = types.MethodType(namespace["_sync_display_from_json"], self.gui)

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def record(self, name, value=10):
        return {"nickname": name, "oath_energy": value, "last_updated": "2026-09-24T10:00:00"}

    def test_add_change_delete_and_empty(self):
        self.write({"a": self.record("a"), "b": self.record("b")})
        self.assertTrue(self.sync())
        self.assertEqual(set(self.gui.row_by_nickname), {"a", "b"})
        self.updates.clear()
        self.sync()
        self.assertEqual(self.updates, [])
        self.write({"b": self.record("b", 30)})
        self.sync()
        self.assertEqual(set(self.gui.row_by_nickname), {"b"})
        self.assertEqual(self.gui._displayed_records["b"]["oath_energy"], 30)
        self.assertEqual(self.gui._summary_record["oath_energy"], 30)
        self.write({})
        self.sync()
        self.assertEqual(self.gui.row_by_nickname, {})
        self.assertEqual(self.gui._summary_record, {})
        self.assertEqual(self.gui.store.data, {"capture": "untouched"})

    def test_failure_preserves_display_and_recovers(self):
        self.write({"a": self.record("a")})
        self.sync()
        for invalid in ('{broken', '[]', '{"a": null}', '{"a": {"nickname": "a", "oath_energy": "bad"}}'):
            self.path.write_text(invalid, encoding="utf-8")
            self.assertFalse(self.sync())
            self.assertEqual(self.gui._displayed_records["a"], self.record("a"))
        self.path.unlink()
        self.assertFalse(self.sync())
        self.write({"a": self.record("a")})
        self.assertTrue(self.sync())
        self.assertNotIn("실패", self.gui.status_label.text())

    def test_repairs_display_even_if_json_unchanged(self):
        self.write({"a": self.record("a")})
        self.sync()
        self.gui._displayed_records["a"]["oath_energy"] = 999
        self.sync()
        self.assertEqual(self.gui._displayed_records["a"]["oath_energy"], 10)

    def test_row_limit(self):
        self.write({name: self.record(name) for name in ("a", "b", "c")})
        self.sync()
        self.assertEqual(set(self.gui.row_by_nickname), {"b", "c"})

    def test_only_successful_save_triggers_sync(self):
        source = Path(__file__).with_name("aion2_gui_qt.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "MainWindow")
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_sync_after_save")
        namespace = {}
        exec(compile(ast.Module(body=[method], type_ignores=[]), "gui_save_sync", "exec"), namespace)
        store = CharacterStore(path=str(self.path))
        calls = []
        gui = types.SimpleNamespace(store=store, _display_save_revision=-1,
                                    _sync_display_from_json=lambda: calls.append(store.save_revision))
        check = types.MethodType(namespace["_sync_after_save"], gui)
        check()  # 初回 표시
        check()
        self.assertEqual(calls, [0])
        store.update_character_info("a", entity_id=1)
        check()
        check()
        self.assertEqual(calls, [0, 1])
        with patch("aion2_storage.os.replace", side_effect=OSError("write failed")):
            with self.assertRaises(OSError):
                store.update_character_info("a", entity_id=2)
        check()
        self.assertEqual(calls, [0, 1])
        store.delete_character("a")
        check()
        self.assertEqual(calls, [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
