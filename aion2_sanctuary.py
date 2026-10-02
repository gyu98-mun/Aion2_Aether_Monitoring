"""성역 스냅샷 파서. 90000002=루드라는 사용자 승인 잠정 매핑."""
import struct

SANCTUARIES = ((90000002, '루드라'), (90000004, '침식'),
               (90000006, '무스펠'), (90000008, '비탄'))


def parse_sanctuary_snapshot(payload):
    """연속된 90000001~08 레코드가 모두 맞을 때만 반환. 미수신은 None."""
    def varint(pos):
        value = 0
        for shift in range(0, 35, 7):
            byte = payload[pos]
            pos += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, pos
        raise ValueError('invalid varint')

    anchor = struct.pack('<I', 90000001)
    search = 0
    while True:
        index = payload.find(anchor, search)
        if index < 0:
            return None
        search = index + 1
        if index == 0:
            continue
        pos = index - 1
        result = {}
        try:
            for expected in range(90000001, 90000009):
                tag = payload[pos]
                identifier = struct.unpack_from('<I', payload, pos + 1)[0]
                if tag not in (0, 4, 8, 12) or identifier != expected:
                    raise ValueError('unexpected record')
                pos += 5
                values = []
                for flag in (4, 8):
                    value = 0
                    if tag & flag:
                        value, pos = varint(pos)
                    values.append(value)
                if expected % 2 == 0:
                    result[str(expected)] = values
            return result
        except (IndexError, ValueError, struct.error):
            continue


def format_sanctuaries(data):
    parts = []
    for identifier, name in SANCTUARIES:
        values = data.get(str(identifier)) if isinstance(data, dict) else None
        valid = (isinstance(values, (list, tuple)) and len(values) == 2
                 and all(type(v) is int and v >= 0 for v in values))
        count = (f'{values[0]}+{values[1]}' if values[1] else str(values[0])) if valid else '-'
        parts.append(f'{name} {count}')
    return '   '.join(parts)
