import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / '.analysis_deps'))
import json
import struct
import lz4.block
from collections import defaultdict
from scapy.utils import PcapNgReader
from scapy.layers.inet import IP, TCP
from aion2_decoder import StreamProcessor
from aion2_core import StreamAssembler, read_varint

terms = ['성역', '루드라', '침식', '무스펠', '비탄']
terms += ['rudra', 'muspel', 'sanctuary', 'sanctum', 'erosion', 'corrosion',
          'encroachment', 'invasion', 'sorrow', 'grief', 'lament', 'anguish',
          'sanct', 'erod', 'corrupt', 'mourn', 'bitter', 'invad']
patterns = [(term, enc, term.encode(enc)) for term in terms for enc in ('utf-8', 'utf-16-le', 'utf-16-be', 'cp949')]
results = []
for filename in sys.argv[1:]:
    path = Path(filename)
    result = {'file': path.name, 'raw_matches': [], 'decoded_matches': [], 'streams': []}
    raw = path.read_bytes()
    for term, enc, pattern in patterns:
        count = raw.lower().count(pattern)
        if count: result['raw_matches'].append({'term': term, 'encoding': enc, 'count': count})
    streams = defaultdict(list)
    with PcapNgReader(str(path)) as packets:
        for number, packet in enumerate(packets, 1):
            if IP in packet and TCP in packet and bytes(packet[TCP].payload):
                ip, tcp = packet[IP], packet[TCP]
                streams[(ip.src, tcp.sport, ip.dst, tcp.dport)].append((int(tcp.seq), bytes(tcp.payload), number))
    for key, chunks in streams.items():
        if 13328 not in (key[1], key[3]): continue
        stats = {'direction': 'server_to_client' if key[1] == 13328 else 'client_to_server', 'decoded_frames': 0, 'gaps': 0, 'missing_bytes': 0}
        def on_packet(name, opcode, packet, offset, arrived):
            stats['decoded_frames'] += 1
            for term, enc, pattern in patterns:
                start = 0
                while True:
                    pos = packet.lower().find(pattern, start)
                    if pos < 0: break
                    result['decoded_matches'].append({'term': term, 'encoding': enc, 'opcode': '%02X %02X' % opcode, 'capture_packet': arrived, 'offset': pos, 'direction': stats['direction'], 'context': packet[max(0,pos-24):pos+len(pattern)+60].decode(enc, errors='replace'), 'hex': packet[max(0,pos-16):pos+len(pattern)+24].hex(' ')})
                    start = pos + len(pattern)
        processor = StreamProcessor(on_packet=on_packet, verbose=True)
        assembler = StreamAssembler(processor)
        end = None
        joined = bytearray()
        for seq, payload, number in sorted(chunks):
            segment_end = seq + len(payload)
            if end is not None and seq > end:
                stats['gaps'] += 1
                stats['missing_bytes'] += seq - end
                assembler = StreamAssembler(processor)
            if end is not None and seq < end:
                payload = payload[max(0, end-seq):]
            if payload:
                joined.extend(payload)
                assembler.process_chunk(payload, number)
            end = max(end or 0, segment_end)
        stats['unparsed_tail'] = assembler.buffer.size
        # 프레임 파서가 중간에 멈춘 구간도 독립적으로 LZ4 마커/길이를 검증한다.
        stats['validated_lz4_blocks'] = 0
        stats['restored_bytes'] = 0
        marker = 0
        while True:
            marker = joined.find(b'\xff\xff', marker)
            if marker < 0: break
            for start in range(max(0, marker-6), marker):
                length = read_varint(joined, start)
                header_end = start + length.length
                if header_end != marker and not (header_end + 1 == marker and 0xf0 <= joined[header_end] < 0xff):
                    continue
                stop = start + length.value + length.length - 4
                if not marker+6 < stop <= len(joined): continue
                size = struct.unpack_from('<I', joined, marker+2)[0]
                if not 0 < size < 16000000: continue
                try:
                    restored = lz4.block.decompress(bytes(joined[marker+6:stop]), uncompressed_size=size)
                except Exception: continue
                if len(restored) != size: continue
                stats['validated_lz4_blocks'] += 1
                stats['restored_bytes'] += size
                for term, enc, pattern in patterns:
                    pos = restored.lower().find(pattern)
                    if pos >= 0:
                        result['decoded_matches'].append({'term': term, 'encoding': enc, 'stream_offset': start, 'restored_offset': pos, 'context': restored[max(0,pos-24):pos+len(pattern)+60].decode(enc, errors='replace')})
                break
            marker += 2
        result['streams'].append(stats)
    results.append(result)
out = Path(__file__).with_name('capture_name_findings.json')
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
for result in results:
    print(json.dumps(result, ensure_ascii=True))
