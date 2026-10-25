import os, json, hashlib, uuid, base64, re
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

PROFILE = 'ga5-mailroom-action-gate/v2'
ACTIONS = {'create_draft','update_internal_record','send_approved_notice','request_confirmation','quarantine_item','no_action'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def db():
    url = os.environ.get('DATABASE_URL')
    if not url:
        raise RuntimeError('DATABASE_URL is required')
    return psycopg.connect(url)

def setup():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS evaluations (
          evaluation_id TEXT PRIMARY KEY,
          request_digest TEXT NOT NULL,
          input_digest TEXT NOT NULL,
          verifier JSONB NOT NULL,
          proposals JSONB NOT NULL,
          propose_response JSONB NOT NULL,
          commit_digest TEXT,
          commit_response JSONB
        )''')

@asynccontextmanager
async def lifespan(app):
    setup()
    yield

app = FastAPI(lifespan=lifespan)

@app.exception_handler(HTTPException)
async def errors(request, exc):
    return JSONResponse(status_code=exc.status_code, content={'error':str(exc.detail)})

def fail(msg, code=422):
    raise HTTPException(code, msg)

def require(cond, msg):
    if not cond: fail(msg)

def verify_propose(body):
    require(body.get('profile') == PROFILE and body.get('operation') == 'propose', 'Invalid profile/operation')
    eid=body.get('evaluationId')
    require(isinstance(eid,str) and eid, 'Missing evaluationId')
    dossiers=body.get('dossiers')
    require(isinstance(dossiers,list) and len(dossiers)>0 and len(dossiers)<=100, 'Invalid dossiers')
    ids=[]
    for d in dossiers:
        require(isinstance(d,dict), 'Invalid dossier')
        did=d.get('dossierId')
        require(isinstance(did,str) and did, 'Missing dossierId')
        ids.append(did)
        sources=d.get('sources')
        require(isinstance(sources,list), 'Invalid sources')
        lineids=[]
        for s in sources:
            require(isinstance(s,dict) and isinstance(s.get('lines'),list), 'Invalid source')
            for line in s['lines']:
                require(isinstance(line,dict) and isinstance(line.get('lineId'),str) and isinstance(line.get('text'),str), 'Invalid line')
                lineids.append(line['lineId'])
        require(len(lineids)==len(set(lineids)), 'Duplicate lineId in dossier')
        require(bool(lineids), 'Dossier has no lines')
    require(len(ids)==len(set(ids)), 'Duplicate dossierId')
    verifier=body.get('receiptVerifier')
    require(isinstance(verifier,dict) and verifier.get('algorithm')=='Ed25519', 'Invalid receipt verifier')
    jwk=verifier.get('publicKeyJwk')
    require(isinstance(jwk,dict) and jwk.get('kty')=='OKP' and jwk.get('crv')=='Ed25519' and isinstance(jwk.get('x'),str), 'Invalid public key')
    try: public_key(jwk)
    except Exception: fail('Invalid Ed25519 key')
    allowed=body.get('allowedActions')
    require(isinstance(allowed,list) and set(allowed)==ACTIONS and len(allowed)==len(ACTIONS), 'Invalid allowedActions')
    corpus=body.get('corpus')
    require(isinstance(corpus,dict) and corpus.get('stableCount')==58 and corpus.get('freshCount')==6, 'Invalid corpus')
    return eid,dossiers,verifier

def public_key(jwk):
    s=jwk['x']; raw=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    if len(raw)!=32: raise ValueError('Invalid key length')
    return Ed25519PublicKey.from_public_bytes(raw)

def dummy_proposals(dossiers):
    # PROTOCOL TEST ONLY: replace with validated AI decisions before any official Check.
    proposals=[]
    for d in dossiers:
        first=d['sources'][0]['lines'][0]['lineId'] if d['sources'][0]['lines'] else next(line['lineId'] for s in d['sources'] for line in s['lines'])
        proposals.append({'dossierId':d['dossierId'], 'callId':'call_'+uuid.uuid4().hex,
            'action':'no_action','target':None,
            'payload':{'reasonCode':'INFORMATIONAL','referenceId':d['dossierId']},
            'evidence':[first]})
    return proposals

def proposal_digest(p):
    normalized={k:p[k] for k in ('dossierId','callId','action','target','payload','evidence')}
    normalized['evidence']=sorted(normalized['evidence'])
    return digest(normalized)

def verify_commit(body, saved):
    require(body.get('profile')==PROFILE and body.get('operation')=='commit','Invalid profile/operation')
    require(body.get('inputDigest')==saved['input_digest'],'inputDigest mismatch')
    receipts=body.get('receipts')
    proposals=saved['proposals']
    require(isinstance(receipts,list) and len(receipts)==len(proposals),'Receipt count mismatch')
    pmap={p['dossierId']:p for p in proposals}
    require(len(pmap)==len(proposals),'Duplicate stored proposals')
    key=public_key(saved['verifier']['publicKeyJwk'])
    seen_dossiers=set(); seen_receipts=set(); outcomes=[]
    for r in receipts:
        require(isinstance(r,dict),'Invalid receipt')
        required={'dossierId','callId','action','accepted','proposalDigest','receiptId','receiptSignature'}
        require(set(r)==required,'Invalid receipt fields')
        did=r['dossierId']
        require(isinstance(did,str) and did in pmap and did not in seen_dossiers,'Unknown or duplicate dossier')
        seen_dossiers.add(did)
        require(isinstance(r['receiptId'],str) and r['receiptId'] and r['receiptId'] not in seen_receipts,'Duplicate/invalid receiptId')
        seen_receipts.add(r['receiptId'])
        require(type(r['accepted']) is bool,'Invalid accepted flag')
        p=pmap[did]
        require(r['callId']==p['callId'] and r['action']==p['action'] and r['proposalDigest']==proposal_digest(p),'Receipt/proposal mismatch')
        require(isinstance(r['receiptSignature'],str),'Missing signature')
        signed={'profile':PROFILE,'evaluationId':body['evaluationId'],'inputDigest':body['inputDigest'],
                'receipt':{k:v for k,v in r.items() if k!='receiptSignature'}}
        try:
            sig=base64.b64decode(r['receiptSignature'],validate=True)
            key.verify(sig,canonical(signed))
        except (ValueError,InvalidSignature,TypeError):
            fail('Invalid receipt signature')
        outcomes.append({'dossierId':did,'callId':p['callId'],'action':p['action'],
                         'proposalDigest':r['proposalDigest'],'receiptId':r['receiptId'],
                         'status':'executed' if r['accepted'] else 'rejected'})
    return {'profile':PROFILE,'evaluationId':body['evaluationId'],'status':'completed',
            'inputDigest':body['inputDigest'],'outcomes':outcomes}

@app.get('/health')
def health():
    return {'status':'ok','mode':'protocol-test-only'}

@app.post('/')
async def handle(request:Request):
    raw=await request.body()
    if len(raw)>2_000_000: fail('Request too large',413)
    try: body=json.loads(raw)
    except (ValueError,UnicodeDecodeError): fail('Invalid JSON',400)
    require(isinstance(body,dict),'Expected JSON object')
    op=body.get('operation')
    if op=='propose':
        eid,dossiers,verifier=verify_propose(body)
        request_digest=digest(body)
        with db() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(eid,))
            row=conn.execute('SELECT request_digest,propose_response FROM evaluations WHERE evaluation_id=%s',(eid,)).fetchone()
            if row:
                if row[0]!=request_digest: fail('evaluationId reused with changed content',409)
                return JSONResponse(row[1])
            proposals=dummy_proposals(dossiers)
            response={'profile':PROFILE,'evaluationId':eid,'status':'awaiting_receipts',
                      'inputDigest':digest(dossiers),'proposals':proposals}
            conn.execute('INSERT INTO evaluations(evaluation_id,request_digest,input_digest,verifier,proposals,propose_response) VALUES (%s,%s,%s,%s,%s,%s)',
                (eid,request_digest,response['inputDigest'],json.dumps(verifier),json.dumps(proposals),json.dumps(response)))
        return JSONResponse(response)
    if op=='commit':
        require(body.get('profile')==PROFILE,'Invalid profile')
        eid=body.get('evaluationId')
        require(isinstance(eid,str) and eid,'Missing evaluationId')
        with db() as conn:
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(eid,))
            row=conn.execute('SELECT input_digest,verifier,proposals,commit_digest,commit_response FROM evaluations WHERE evaluation_id=%s',(eid,)).fetchone()
            if not row: fail('Unknown evaluation',400)
            saved={'input_digest':row[0],'verifier':row[1],'proposals':row[2]}
            cd=digest(body)
            if row[3] is not None:
                if row[3]!=cd: fail('Commit conflicts with completed evaluation',409)
                return JSONResponse(row[4])
            response=verify_commit(body,saved)
            conn.execute('UPDATE evaluations SET commit_digest=%s,commit_response=%s WHERE evaluation_id=%s',(cd,json.dumps(response),eid))
        return JSONResponse(response)
    fail('Unsupported operation',400)
