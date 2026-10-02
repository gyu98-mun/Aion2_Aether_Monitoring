"""Read-only AION TCP string inventory; never opens CharacterStore."""
import sys, json, re, struct, bisect, ipaddress, html
from pathlib import Path
from collections import defaultdict, Counter
sys.path.insert(0, str(Path(__file__).parent / '.analysis_deps'))
import lz4.block
from scapy.utils import PcapNgReader
from scapy.layers.inet import IP, TCP
from aion2_core import read_varint

OUT = Path(__file__).parent / 'packet_inventory'
OUT.mkdir(exist_ok=True)
entries = defaultdict(list)
stats = []
opcodes = Counter()
network = ipaddress.ip_network('206.127.156.0/24')

def strings(buf, file, flow, layer, locator, opcode=''):
    found = set()
    patterns = [('ASCII', rb'[\x20-\x7e]{4,}'),
                ('UTF-16LE', rb'(?:[\x20-\x7e]\x00){4,}'),
                ('UTF-16BE', rb'(?:\x00[\x20-\x7e]){4,}')]
    for encoding, pattern in patterns:
        for match in re.finditer(pattern, buf):
            text = match.group().decode({'ASCII':'ascii','UTF-16LE':'utf-16-le','UTF-16BE':'utf-16-be'}[encoding]).strip()
            if len(text) < 4: continue
            key = (text, match.start(), encoding)
            if key in found: continue
            found.add(key)
            entries[text].append(dict(file=file, flow=flow, layer=layer, encoding=encoding,
                                      location=locator, offset=match.start(), opcode=opcode))

def blocks(buf):
    pos = 0
    while True:
        pos = buf.find(b'\xff\xff', pos)
        if pos < 0: return
        for start in range(max(0,pos-6),pos):
            v = read_varint(buf,start)
            if v.length <= 0: continue
            h = start+v.length
            if h != pos and not (h+1 == pos and 0xf0 <= buf[h] < 0xff): continue
            end = start+v.value+v.length-4
            if not pos+6 < end <= len(buf): continue
            n = struct.unpack_from('<I',buf,pos+2)[0]
            if not 0 < n < 16000000: continue
            try: data = lz4.block.decompress(buf[pos+6:end],uncompressed_size=n)
            except Exception: continue
            if len(data) == n:
                yield start,end,data
                break
        pos += 2

for filename in sys.argv[1:]:
    path = Path(filename)
    flows = defaultdict(list)
    total = selected = truncated = 0
    with PcapNgReader(str(path)) as reader:
        for number,p in enumerate(reader,1):
            total += 1
            if IP not in p or TCP not in p: continue
            ip,tcp = p[IP],p[TCP]
            server = ((tcp.sport == 13328 and ipaddress.ip_address(ip.src) in network) or
                      (tcp.dport == 13328 and ipaddress.ip_address(ip.dst) in network))
            if not server: continue
            selected += 1
            # Ethernet padding is not TCP data.
            expected = max(0, int(ip.len)-int(ip.ihl)*4-int(tcp.dataofs)*4)
            payload = bytes(tcp.payload)[:expected]
            if len(payload) < expected: truncated += 1
            if payload: flows[(ip.src,tcp.sport,ip.dst,tcp.dport)].append((int(tcp.seq),payload,number))
    info = dict(file=path.name,total_packets=total,aion_packets=selected,truncated=truncated,flows=[])
    for key,chunks in flows.items():
        direction = '서버→클라이언트' if key[1] == 13328 else '클라이언트→서버'
        segments=[]; data=bytearray(); marks=[]; end=None; gaps=0
        for seq,payload,number in sorted(chunks,key=lambda x:(x[0],-len(x[1]))):
            last=seq+len(payload)
            if end is not None and seq>end:
                segments.append((bytes(data),marks)); data=bytearray();marks=[];gaps+=1
            overlap=max(0,(end or seq)-seq)
            piece=payload[overlap:]
            if piece: marks.append((len(data),number));data.extend(piece)
            end=max(end or 0,last)
        if data: segments.append((bytes(data),marks))
        flow_info=dict(direction=direction,connection='%s:%s → %s:%s'%key,gaps=gaps,bytes=sum(len(s[0]) for s in segments),lz4_blocks=0,decoded_bytes=0,inner_frames=0)
        for segnum,(buf,marks) in enumerate(segments):
            strings(buf,path.name,direction,'TCP 원본',f'연속 구간 {segnum}')
            for start,stop,restored in blocks(buf):
                flow_info['lz4_blocks']+=1;flow_info['decoded_bytes']+=len(restored)
                offsets=[m[0] for m in marks]
                number=marks[max(0,bisect.bisect_right(offsets,start)-1)][1]
                locator=f'패킷 #{number} / TCP구간 {segnum} +{start}'
                # All decompressed bytes are searched even if inner framing fails.
                strings(restored,path.name,direction,'LZ4 해제',locator)
                offset=0
                while offset<len(restored):
                    v=read_varint(restored,offset)
                    if v.value==0: offset+=1;continue
                    size=v.value+v.length-4
                    if v.length<=0 or size<=0 or offset+size>len(restored):break
                    h=offset+v.length
                    if h<len(restored) and 0xf0<=restored[h]<0xff:h+=1
                    if h+2<=offset+size:
                        op=restored[h:h+2].hex(' ').upper()
                        opcodes[(path.name,op)]+=1;flow_info['inner_frames']+=1
                    offset+=size
        info['flows'].append(flow_info)
    stats.append(info)

rows=[]
for text,occ in entries.items():
    # Heuristic only: binary bytes can accidentally resemble identifiers.
    candidate=bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_./:\- ]{3,}',text) and re.search(r'[A-Za-z]{4}',text))
    files=sorted({o['file'] for o in occ})
    rows.append(dict(text=text,category='태그 후보' if candidate else '기타 문자열',files=files,
                     common=len(files)==3,count=len(occ),decoded=any(o['layer']=='LZ4 해제' for o in occ),occurrences=occ))
rows.sort(key=lambda r:(not r['common'],r['category']!='태그 후보',not r['decoded'],r['text'].lower()))
result=dict(filter='TCP 13328 + 206.127.156.0/24',stats=stats,strings=rows,
            opcodes=[dict(file=f,opcode=o,count=c) for (f,o),c in sorted(opcodes.items())])
(OUT/'inventory.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'all_strings.txt').write_text('\n'.join(f"[{r['category']}] [{','.join(r['files'])}] {r['text']}" for r in rows),encoding='utf-8')
payload=json.dumps(result,ensure_ascii=False).replace('<','\\u003c')
page='''<!doctype html><meta charset="utf-8"><title>아이온2 패킷 문자열 목록</title>
<style>body{font:15px system-ui;margin:32px;background:#111827;color:#e5e7eb}input,select{padding:10px;margin:6px;background:#253047;color:white;border:1px solid #64748b}table{border-collapse:collapse;width:100%}td,th{padding:10px;text-align:left;border-bottom:1px solid #374151;vertical-align:top}code{white-space:pre-wrap;word-break:break-all;color:#93c5fd}summary{cursor:pointer}small{color:#9ca3af}.bar{position:sticky;top:0;background:#111827;padding:8px}h1{font-size:25px}</style>
<h1>아이온2 패킷 문자열 목록</h1><p>성령성 · 마술성 · 궁예성 캡처 / TCP 13328, 서버 206.127.156.0/24만 포함</p>
<p>문자열은 프로토콜 필드명이 확정된 태그가 아닙니다. ‘태그 후보’는 영문 식별자 모양을 기준으로 분류했으며, 바이너리 우연 일치도 포함될 수 있습니다.<br>ASCII 및 영문 UTF-16 4글자 이상을 추출했습니다. 원본의 압축 바이트에서 나온 문자열은 잡음일 수 있습니다. LZ4 해제 여부를 함께 확인하세요.<br>출현 횟수는 추출 횟수이며 원본/압축 해제 중복을 포함합니다. 패킷 번호는 압축 블록 시작 위치입니다. 일부 내부 프레임은 미해석 상태입니다.</p>
<details><summary>캡처별 분석 범위</summary><pre id="stats"></pre></details>
<div class="bar"><input id="q" placeholder="이름 / dungeon / raid / boss 등 검색" size="40"><select id="kind"><option value="">전체 문자열</option>태그 후보</option>기타 문자열</option></select><label><input type="checkbox" id="common">세 파일 공통만</label><label><input type="checkbox" id="decoded">압축 해제에서 발견된 것만</label><span id="count"></span></div>
<table><thead><tr><th>문자열</th><th>분류 / 출처</th><th>발견 파일</th><th>위치</th></tr></thead><tbody id="body"></tbody></table>
<script>const data=PAYLOAD;const $=id=>document.getElementById(id);$('stats').textContent=JSON.stringify(data.stats,null,2);
function render(){const q=$('q').value.toLowerCase();const rows=data.strings.filter(r=>r.text.toLowerCase().includes(q)&&(!$('kind').value||r.category===$('kind').value)&&(!$('common').checked||r.common)&&(!$('decoded').checked||r.decoded));$('count').textContent=rows.length+'개 / 전체 '+data.strings.length+'개';$('body').replaceChildren();for(const r of rows){let tr=document.createElement('tr');const td=()=>{let x=document.createElement('td');tr.append(x);return x};let code=document.createElement('code');code.textContent=r.text;td().append(code);td().textContent=r.category+' / '+(r.decoded?'LZ4 해제 포함':'TCP 원본')+(r.common?' / 3개 공통':'');td().textContent=r.files.join(', ');let details=document.createElement('details'),s=document.createElement('summary');s.textContent=r.count+'회 — 위치 보기';details.append(s);let pre=document.createElement('pre');pre.textContent=r.occurrences.map(o=>o.file+' | '+o.flow+' | '+o.layer+' | '+o.encoding+' | '+o.location+' | 문자열 +'+o.offset).join('\\n');details.append(pre);td().append(details);$('body').append(tr)}}for(const id of ['q','kind','common','decoded'])$(id).addEventListener('input',render);render();</script>'''.replace('PAYLOAD',payload)
(OUT/'index.html').write_text(page,encoding='utf-8')
print(json.dumps({'unique_strings':len(rows),'candidates':sum(r['category']=='태그 후보' for r in rows),'common_candidates':[r['text'] for r in rows if r['common'] and r['category']=='태그 후보'],'decoded_candidates':[r['text'] for r in rows if r['decoded'] and r['category']=='태그 후보'],'stats':stats},ensure_ascii=True))
