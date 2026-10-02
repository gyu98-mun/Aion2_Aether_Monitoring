"""Windows WMSZ 방향에 따른 단일 크기 조절 규칙 (좌표는 물리 픽셀)."""


def constrain_resize(rect, edge, *, ratio, minimum_width, minimum_height,
                     maximum_height, overhead, row_height, spacing, count):
    left, top, right, bottom = rect
    if edge not in range(1, 9):
        return rect
    # 1/2=좌/우, 3=위, 4/5=위 모서리, 6=아래, 7/8=아래 모서리.
    if edge in (1, 2, 4, 5, 7, 8):
        width = max(right - left, round(minimum_width * ratio))
        if edge in (1, 4, 7):
            left = right - width
        else:
            right = left + width
    if edge not in (1, 2):
        step = row_height + spacing
        rows = max(1, min(max(1, count), int(((bottom - top) / ratio - overhead + spacing) / step + 0.5)))
        height = overhead + rows * step - spacing
        height = round(max(minimum_height, min(maximum_height, height)) * ratio)
        if edge in (3, 4, 5):
            top = bottom - height
        else:
            bottom = top + height
    return left, top, right, bottom
