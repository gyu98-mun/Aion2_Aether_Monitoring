import unittest
from aion2_window_geometry import constrain_resize


class ResizeRulesTest(unittest.TestCase):
    def resize(self, rect, edge, ratio=1, count=9):
        return constrain_resize(rect, edge, ratio=ratio, minimum_width=400,
                                minimum_height=168, maximum_height=168 + (max(1, count)-1)*71,
                                overhead=100, row_height=68, spacing=3, count=count)

    def test_all_edges_and_dpi(self):
        for ratio in (1, 1.25, 1.5, 2):
            for edge in range(1, 9):
                with self.subTest(ratio=ratio, edge=edge):
                    original = (100, 100, 350, 100+round(427*ratio))
                    left, top, right, bottom = self.resize(original, edge, ratio)
                    if edge in (1, 2):
                        self.assertEqual((top, bottom), (original[1], original[3]))
                    else:
                        self.assertEqual(bottom-top, round(452*ratio))  # 다섯 행
                    if edge in (3, 6):
                        self.assertEqual((left, right), (original[0], original[2]))
                    else:
                        self.assertEqual(right-left, round(400*ratio))
                    if edge in (1, 4, 7): self.assertEqual(right, original[2])
                    if edge in (2, 5, 8): self.assertEqual(left, original[0])
                    if edge in (3, 4, 5): self.assertEqual(bottom, original[3])
                    if edge in (6, 7, 8): self.assertEqual(top, original[1])

    def test_limits_and_no_drift(self):
        for count in (1, 3, 9):
            for requested in (30, 350, 8000):
                rect = self.resize((0, 0, 500, requested), 8, count=count)
                height = rect[3]-rect[1]
                self.assertGreaterEqual(height, 168)
                self.assertLessEqual(height, 168+(count-1)*71)
                self.assertEqual((height-168)%71, 0)
                self.assertEqual(self.resize(rect, 8, count=count), rect)


if __name__ == '__main__':
    unittest.main()
