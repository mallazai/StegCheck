import argparse, os, math, mimetypes, json
from collections import Counter

B='='*68
SIGS={b'PK\x03\x04':'ZIP archive',b'Rar!\x1a\x07\x00':'RAR archive',b'7z\xbc\xaf\x27\x1c':'7Z archive',b'%PDF-':'PDF document',b'MZ':'Windows executable'}
MAGIC=[(b'\xff\xd8\xff','JPEG image'),(b'\x89PNG\r\n\x1a\n','PNG image'),(b'ID3','MP3 audio'),(b'RIFF','RIFF/WAV/AVI'),(b'ftyp','MP4/MOV container'),(b'GIF89a','GIF image'),(b'GIF87a','GIF image')]

def entropy(data):
    if not data:return 0.0
    c=Counter(data);n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def detect(data):
    h=data[:64]
    for s,n in MAGIC:
        if s in h:return n
    return 'Unknown'

def embedded(data):
    out=[]
    for s,n in SIGS.items():
        p=data.find(s,1)
        if p>0: out.append((n,p))
    return out

def jpeg_trail(data):
    i=data.rfind(b'\xff\xd9')
    return len(data)-(i+2) if i!=-1 and i+2<len(data) else 0

def score_file(path):
    with open(path,'rb') as f:data=f.read()
    size=len(data)
    et=entropy(data[:min(size,1024*1024)])
    dtype=detect(data)
    emb=embedded(data)
    trail=jpeg_trail(data) if 'JPEG' in dtype else 0
    score=0; reasons=[]
    if emb: score+=60; reasons.append('Embedded signatures found')
    if trail: score+=35; reasons.append(f'Trailing JPEG payload: {trail} bytes')
    if et>7.7: score+=20; reasons.append('High entropy content')
    if dtype=='Unknown': score+=10; reasons.append('Unknown header')
    verdict='LOW' if score<25 else 'MEDIUM' if score<60 else 'HIGH'
    return {'file':path,'size':size,'type':dtype,'entropy':round(et,2),'embedded':emb,'trail':trail,'score':score,'verdict':verdict,'reasons':reasons,'mime':mimetypes.guess_type(path)[0] or 'unknown'}

def show(r):
    icon={'LOW':'🟢','MEDIUM':'🟡','HIGH':'🔴'}[r['verdict']]
    bar='#'*min(20,max(1,r['score']//5)) if r['score'] else ''
    print(B) ; print(' STEGCHECK v2 - Advanced Steganalysis Scanner') ; print(B)
    print('File        :',r['file'])
    print('Size        :',r['size'],'bytes')
    print('MIME        :',r['mime'])
    print('Detected    :',r['type'])
    print('Entropy     :',r['entropy'],'/ 8.00')
    print('Risk Score  :',r['score'],bar)
    print('Verdict     :',icon,r['verdict'])
    if r['trail']: print('Trailing    :',r['trail'],'bytes after JPEG EOF')
    if r['embedded']:
        print('Embedded    :')
        for n,p in r['embedded']: print('  -',n,'@ offset',p)
    if r['reasons']:
        print('Reasons     :')
        for x in r['reasons']: print('  -',x)
    print(B)

def scan_folder(folder):
    for root,_,files in os.walk(folder):
        for f in files:
            p=os.path.join(root,f)
            try: show(score_file(p))
            except: pass

if __name__=='__main__':
    ap=argparse.ArgumentParser(description='StegCheck v2')
    ap.add_argument('target', nargs='?', help='file target')
    ap.add_argument('--folder', help='scan folder')
    ap.add_argument('--json', help='save json report')
    a=ap.parse_args()
    if a.folder:
        scan_folder(a.folder)
    elif a.target:
        r=score_file(a.target); show(r)
        if a.json:
            open(a.json,'w').write(json.dumps(r,indent=2))
            print('Saved report:',a.json)
    else:
        ap.print_help()
