"""
Aion2-Dps-Meter (TK-open-public, MIT) 의 StreamAssembler + StreamProcessor 로직을
그대로 파이썬으로 포팅한 것.

사용법:
    1) 서버->클라이언트 TCP 스트림을 시퀀스 번호 순서대로 이어붙인 bytes 를 만든다
       (반드시 seq 순서, 재전송 중복 제거된 상태여야 함 - 실제 pcap 파일에서 tshark/scapy로 재조립)
    2) StreamAssembler(on_packet).process_chunk(그 bytes, arrived_at) 호출

핵심 발견 (build.gradle.kts 의 lz4-java 의존성에서 유추 후 소스 확인으로 확정):
  - 거의 모든 "랜덤처럼 보이는" 페이로드는 사실 LZ4 블록(raw block, frame 아님) 압축.
  - 압축 마커: 헤더 varint 길이(+ extraFlag 바이트) 뒤에 0xFF 0xFF 가 오면 압축 패킷.
    그 다음 4바이트 LE = 압축 해제 후 원본 길이, 그 다음부터 LZ4 raw block 데이터.
  - 압축 해제된 내부 버퍼는 다시 [varint 길이][opcode 2바이트][payload...] 프레임들의 연속.
  - 이전에 Wireshark 에서 손으로 복사-붙여넣기한 dump_raw.txt/dump_ext.txt 는
    "패킷마다 0번지부터 다시 시작하는" 상대 오프셋을 절대 오프셋인 것처럼 배열에 덮어써서
    reconstruct 했기 때문에(search.py 참고) 실제로는 여러 패킷이 서로를 덮어쓴 쓰레기 배열이었음.
    => 그 실험에서 335/345/365/375 를 못 찾은 건 "그 값이 없다"는 증거가 아니라
       애초에 파싱 자체가 깨져 있었다는 뜻. 무효 실험으로 간주해야 함.
"""

import lz4.block
import struct


class VarInt:
    __slots__ = ("value", "length")
    def __init__(self, value, length):
        self.value = value
        self.length = length


def read_varint(b: bytes, offset: int = 0) -> VarInt:
    value = 0
    shift = 0
    count = 0
    while True:
        if offset + count >= len(b):
            return VarInt(-1, -1)
        byte_val = b[offset + count]
        count += 1
        value |= (byte_val & 0x7F) << shift
        if (byte_val & 0x80) == 0:
            return VarInt(value, count)
        shift += 7
        if shift >= 32:
            return VarInt(-1, -1)


def to_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


OPCODES = {
    (0x33, 0x36): "OwnNickname",
    (0x44, 0x36): "OtherNickname",
    (0x45, 0x36): "OtherNickname2",
    (0x41, 0x36): "Summon",
    (0x04, 0x38): "Damage",
    (0x05, 0x38): "DoT",
    (0x2A, 0x38): "BuffApply",
    (0x2B, 0x38): "BuffApply2",
    (0x21, 0x8D): "BattleToggle",
    (0x00, 0x8D): "RemainHp",
    (0x07, 0x97): "JoinRequest",
    (0x25, 0x97): "CancelJoin",
    (0x0B, 0x97): "AdmitJoin",
    (0x09, 0x97): "RefuseJoin",
    (0x18, 0x97): "InstanceStart",
    (0x1D, 0x97): "ExitParty",
}


class StreamProcessor:
    def __init__(self, on_packet=None, verbose=False):
        self.on_packet = on_packet  # callback(opcode_tuple_or_None, packet_bytes, offset_after_opcode)
        self.verbose = verbose
        self.unknown_opcode_counts = {}

    def on_packet_received(self, packet: bytes, arrived_at=0):
        if len(packet) == 3:
            return

        length_info = read_varint(packet)
        if length_info.length <= 0:
            return
        if length_info.length >= len(packet):
            return

        extra_flag = 0xF0 <= packet[length_info.length] < 0xFF

        if extra_flag:
            if (length_info.length + 2 < len(packet)
                    and packet[length_info.length + 1] == 0xFF
                    and packet[length_info.length + 2] == 0xFF):
                self.decompress_packet(packet, length_info.length, True, arrived_at)
                return
        else:
            if (length_info.length + 1 < len(packet)
                    and packet[length_info.length] == 0xFF
                    and packet[length_info.length + 1] == 0xFF):
                self.decompress_packet(packet, length_info.length, False, arrived_at)
                return

        opcode_offset = length_info.length + (1 if extra_flag else 0)
        if opcode_offset + 1 >= len(packet):
            return

        b1 = packet[opcode_offset]
        b2 = packet[opcode_offset + 1]
        name = OPCODES.get((b1, b2))
        if name is None:
            key = (b1, b2)
            self.unknown_opcode_counts[key] = self.unknown_opcode_counts.get(key, 0) + 1

        if self.on_packet:
            self.on_packet(name, (b1, b2), packet, opcode_offset + 2, arrived_at)

    def decompress_packet(self, packet: bytes, header_length: int, extra_flag: bool, arrived_at=0):
        try:
            offset = header_length + 2
            if extra_flag:
                offset += 1
            if offset + 4 > len(packet):
                return
            origin_length = struct.unpack_from("<I", packet, offset)[0]
            offset += 4

            compressed = packet[offset:]
            restored = lz4.block.decompress(compressed, uncompressed_size=origin_length)

            if self.verbose:
                print(f"[decompress] compressed={len(compressed)}B -> restored={len(restored)}B")

            inner_offset = 0
            while inner_offset < len(restored):
                past_inner_offset = inner_offset
                length_info = read_varint(restored, inner_offset)
                if length_info.value == 0:
                    inner_offset += 1
                    continue
                if length_info.length <= 0:
                    break

                real_length = length_info.value + length_info.length - 4
                if real_length <= 0:
                    if self.verbose:
                        print("패킷 길이 체크 오류", to_hex(restored), inner_offset)
                    break
                if past_inner_offset + real_length > len(restored):
                    if self.verbose:
                        print("길이 초과, 잘린 패킷일 가능성", real_length, len(restored) - past_inner_offset)
                    break

                self.on_packet_received(restored[past_inner_offset:past_inner_offset + real_length], arrived_at)
                inner_offset += real_length
        except Exception as e:
            if self.verbose:
                print("압축 해제 에러:", e, "packet len", len(packet))


class PacketAccumulator:
    def __init__(self):
        self.buf = bytearray()

    def append(self, data: bytes):
        self.buf += data

    def peek(self, length: int) -> bytes:
        return bytes(self.buf[:length])

    def slice(self, start: int, length: int) -> bytes:
        return bytes(self.buf[start:start + length])

    def discard_bytes(self, length: int):
        del self.buf[:length]

    @property
    def size(self):
        return len(self.buf)


class StreamAssembler:
    def __init__(self, processor: StreamProcessor):
        self.processor = processor
        self.buffer = PacketAccumulator()

    def process_chunk(self, chunk: bytes, arrived_at=0):
        self.buffer.append(chunk)

        while self.buffer.size > 0:
            header = self.buffer.peek(8)
            if len(header) == 0:
                return

            length_info = read_varint(header)
            if length_info.value == 0:
                self.buffer.discard_bytes(1)
                continue
            if length_info.value == -1:
                # varint 파싱 실패 (헤더가 8바이트보다 모자랄 수도 있음)
                if self.buffer.size < 8:
                    return  # 더 기다리기
                self.buffer = PacketAccumulator()
                break

            real_length = length_info.value + length_info.length - 4
            if real_length <= 0:
                self.buffer = PacketAccumulator()
                break

            if self.buffer.size < real_length:
                return  # 아직 다 안옴

            packet = self.buffer.slice(0, real_length)
            self.processor.on_packet_received(packet, arrived_at)
            self.buffer.discard_bytes(real_length)


if __name__ == "__main__":
    # 간단 자가 테스트: varint 인코딩/디코딩 왕복 확인
    def encode_varint(v):
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
        return bytes(out)

    for v in [335, 345, 315, 325, 365, 375]:
        enc = encode_varint(v)
        dec = read_varint(enc)
        print(v, "->", enc.hex(), "decoded:", dec.value, dec.length)
