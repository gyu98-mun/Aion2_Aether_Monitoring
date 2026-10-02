import sys, json, struct, ast, re, bisect
from pathlib import Path
from collections import defaultdict, Counter
sys.path.insert(0,str(Path(__file__).parent/'.analysis_deps'))
import lz4.block
from scapy.utils import PcapNgReader
from scapy.layers.inet import IP,TCP
import aion2_core as core
from aion2_decoder import StreamProcessor
read_varint=core.read_varint
tree=ast.parse(Path('inventory_aion_strings.py').read_text(encoding='utf-8'))
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='blocks'],type_ignores=[]),'blocks','exec'))
out=Path('packet_inventory/character_packets');out.mkdir(exist_ok=True)
all_records=[]
known={'33 36':'자기 캐릭터 이름','0B 61':'로그인 스탯 묶음','0C 61':'오드 변경','56 36':'전투력','1D 56':'아이템 레벨'}
for filename in sys.argv[1:]:
    path=Path(filename);streams=defaultdict(list)
    with PcapNgReader(str(path)) as reader:
        for number,p in enumerate(reader,1):
            if IP not in p or TCP not in p:continue
            ip,tcp=p[IP],p[TCP]
            if tcp.sport!=13328 or not ip.src.startswith('206.127.156.'):continue
            payload=bytes(tcp.payload)[:max(0,int(ip.len)-int(ip.ihl)*4-int(tcp.dataofs)*4)]
            if payload:streams[(ip.src,tcp.sport,ip.dst,tcp.dport)].append((int(tcp.seq),payload,number))
    records=[]
    for key,chunks in streams.items():
        buf=bytearray();marks=[];end=None
        for seq,data,num in sorted(chunks,key=lambda x:(x[0],-len(x[1]))):
            if end is not None and seq>end:raise ValueError('TCP gap')
            piece=data[max(0,(end or seq)-seq):]
            if piece:marks.append((len(buf),num));buf.extend(piece)
            end=max(end or 0,seq+len(data))
        def callback(name,opcode,packet,offset,arrival):
            op='%02X %02X'%opcode;payload=packet[offset:]
            item=dict(file=path.name,opcode=op,capture_packet=arrival,payload_hex=payload.hex(' '),payload_length=len(payload))
            event=None
            if op=='0B 61':event=core.parse_own_stats_snapshot_payload(payload)
            elif op=='0C 61':event=core.parse_oath_energy_payload(payload)
            elif op=='33 36':event=core.parse_own_nickname_packet(packet,read_varint(packet).length)
            elif op=='56 36':event=core.parse_combat_power_payload(payload)
            elif op=='1D 56':event=core.parse_item_level_payload(payload)
            if event:
                item['decoded']={k:getattr(event,k) for k in ('nickname','entity_id','server','job','base','dynamic','new_total','combat_power','item_level') if hasattr(event,k)}
            records.append(item)
        processor=StreamProcessor(on_packet=callback)
        offsets=[x[0] for x in marks]
        # Decode validated compressed blocks independently of outer frame alignment.
        for start,stop,restored in blocks(bytes(buf)):
            num=marks[max(0,bisect.bisect_right(offsets,start)-1)][1]
            pos=0
            while pos<len(restored):
                v=read_varint(restored,pos);size=v.value+v.length-4
                if v.value==0:pos+=1;continue
                if v.length<=0 or size<=0 or pos+size>len(restored):break
                processor.on_packet_received(restored[pos:pos+size],num)
                pos+=size
    all_records.extend(records)
    (out/(path.stem.strip()+'.json')).write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')

ids=Counter(r['decoded']['entity_id'] for r in all_records if r.get('decoded',{}).get('entity_id') is not None)
shared_id=ids.most_common(1)[0][0] if ids else None
needle=core._encode_varint(shared_id) if shared_id is not None else b''
lines=['# 캐릭터 정보 패킷 비교','',f'현재 파서에서 확인된 주요 공통 entity_id: **{shared_id}** (varint `{needle.hex(" ")}`). 캐릭터 고유 ID로 간주하면 안 됩니다.','',
'범위: 아이온2 서버 TCP 13328의 검증된 LZ4 블록 내부 프레임. 미해석/비압축 프레임은 이 표에서 빠질 수 있습니다. 패킷 번호는 이를 포함한 압축 블록의 시작 패킷입니다.','',
'## 현재 프로그램이 읽는 항목','', '| 캡처 | opcode | 의미 | 해석 결과 | 캡처 패킷 |','|---|---|---|---|---:|']
for r in all_records:
    if r['opcode'] in known:
        lines.append(f"| {r['file']} | {r['opcode']} | {known[r['opcode']]} | {json.dumps(r.get('decoded',{}),ensure_ascii=False)} | {r['capture_packet']} |")
files=sorted({r['file'] for r in all_records})
common=set.intersection(*[{r['opcode'] for r in all_records if r['file']==f} for f in files])
lines+=['','## 세 캡처 공통 opcode','', '| opcode | '+ ' | '.join(files)+' |','|---|'+'---|'*len(files)]
for op in sorted(common):
    cols=[]
    for f in files:
        rs=[r for r in all_records if r['file']==f and r['opcode']==op]
        cols.append(', '.join(str(r['payload_length']) for r in rs)+' B')
    lines.append('| '+op+' | '+' | '.join(cols)+' |')
lines+=['','## 공통 ID 바이트열이 포함된 패킷','', '바이트 일치만으로 모든 위치를 entity_id 필드라고 확정할 수 없습니다. 아래 값 나열은 경계 미확정 탐색용 varint 해석입니다.','']
matches=[]
for r in all_records:
    payload=bytes.fromhex(r['payload_hex'])
    positions=[m.start() for m in re.finditer(re.escape(needle),payload)] if needle else []
    if not positions:continue
    matches.append((r,positions))
    lines += [f"### {r['file']} · {r['opcode']} · 패킷 #{r['capture_packet']} · payload {len(payload)} B",'']
    for pos in positions:
        after=pos+len(needle);values=[]
        for _ in range(10):
            v=read_varint(payload,after)
            if v.length<=0:break
            values.append(v.value);after+=v.length
        lines += [f'- ID 시작 offset `{pos}` / 직전 2바이트 `{payload[max(0,pos-2):pos].hex(" ")}` / 뒤쪽 varint 후보 `{values}`']
    lines += ['', '```text', '\n'.join(f'{i:04X}: '+payload[i:i+16].hex(' ') for i in range(0,len(payload),16)), '```','']
(out/'comparison.md').write_text('\n'.join(lines),encoding='utf-8')
print(json.dumps({'common_id':shared_id,'common_opcodes':len(common),'id_matches':[(r['file'],r['opcode'],r['payload_length'],p) for r,p in matches],'decoded':[r for r in all_records if r.get('decoded')]},ensure_ascii=True))
