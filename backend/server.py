from fastapi import FastAPI, APIRouter, Cookie, Header, HTTPException, Response, Query
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import time
import json
import asyncio
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
import httpx
from datetime import datetime, timezone, timedelta

from security import (
    detect_and_mask, risk_score, risk_level, evaluate_policies,
    DEFAULT_POLICIES, TYPE_LABELS,
)

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY')
LOCAL_AI_BASE_URL = os.environ.get('LOCAL_AI_BASE_URL', '')

PROVIDER_MODELS = {
    'Gemini': {'provider': 'gemini', 'default': 'gemini-3-flash-preview',
               'models': ['gemini-3-flash-preview', 'gemini-3.1-pro-preview', 'gemini-2.5-pro', 'gemini-2.5-flash']},
    'OpenAI': {'provider': 'openai', 'default': 'gpt-5.4',
               'models': ['gpt-5.4', 'gpt-5.4-mini', 'gpt-5.2', 'gpt-4.1', 'gpt-4o', 'gpt-4o-mini']},
    'Claude': {'provider': 'anthropic', 'default': 'claude-sonnet-4-6',
               'models': ['claude-sonnet-4-6', 'claude-opus-4-6', 'claude-haiku-4-5-20251001']},
}
PROVIDER_KEY_ENVS = {'Gemini': 'GEMINI_API_KEY', 'OpenAI': 'OPENAI_API_KEY', 'Claude': 'ANTHROPIC_API_KEY'}

MODEL_PRICES = {  # rough blended USD per 1M tokens, for estimated cost only
    'gpt-5.4': 3.0, 'gpt-5.4-mini': 0.6, 'gpt-5.2': 2.5, 'gpt-4.1': 4.0, 'gpt-4o': 5.0, 'gpt-4o-mini': 0.3,
    'claude-sonnet-4-6': 6.0, 'claude-opus-4-6': 30.0, 'claude-haiku-4-5-20251001': 2.0,
    'gemini-3-flash-preview': 0.5, 'gemini-3.1-pro-preview': 4.0, 'gemini-2.5-pro': 2.5, 'gemini-2.5-flash': 0.2,
    'local': 0.0,
}

event_subscribers: set = set()

def publish_event(event: dict):
    for q in list(event_subscribers):
        try:
            q.put_nowait(event)
        except Exception:
            event_subscribers.discard(q)

def resolve_model(provider: str, model: Optional[str]) -> str:
    cfg = PROVIDER_MODELS.get(provider)
    if not cfg:
        return model or 'local'
    if not model:
        return cfg['default']
    if model not in cfg['models']:
        raise HTTPException(status_code=400, detail=f'Model "{model}" is not available for {provider}')
    return model

DEFAULT_SETTINGS = {
    'block_critical': True, 'scan_output': True, 'strict_policy': False,
    'theme': 'Light', 'notify_blocked': True, 'daily_digest': False,
}


# ---------- Models ----------
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

class AuthUser(BaseModel):
    user_id: str
    email: str
    name: str
    picture: str = ''

class SecureChatRequest(BaseModel):
    message: str
    provider: str = 'Gemini'
    model: Optional[str] = None
    session_id: str

class PolicyCreate(BaseModel):
    name: str
    when: List[str] = ['any']
    risk: str = 'Low'
    then: str = 'MASK'
    enabled: bool = True

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    when: Optional[List[str]] = None
    risk: Optional[str] = None
    then: Optional[str] = None
    enabled: Optional[bool] = None

class SettingsUpdate(BaseModel):
    block_critical: Optional[bool] = None
    scan_output: Optional[bool] = None
    strict_policy: Optional[bool] = None
    theme: Optional[str] = None
    notify_blocked: Optional[bool] = None
    daily_digest: Optional[bool] = None


# ---------- Auth (Emergent managed Google) ----------
@api_router.get("/")
async def root():
    return {"message": "SentinelGuard gateway online"}

async def get_session_user(session_token: str | None, authorization: str | None = None) -> AuthUser:
    token = session_token
    if not token and authorization and authorization.lower().startswith('bearer '):
        token = authorization[7:]
    if not token:
        raise HTTPException(status_code=401, detail='Authentication required')
    session = await db.user_sessions.find_one({'session_token': token}, {'_id': 0})
    if not session:
        raise HTTPException(status_code=401, detail='Invalid session')
    expires_at = session.get('expires_at')
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.user_sessions.delete_one({'session_token': token})
        raise HTTPException(status_code=401, detail='Session expired')
    user = await db.users.find_one({'user_id': session['user_id']}, {'_id': 0})
    if not user:
        raise HTTPException(status_code=401, detail='User not found')
    return AuthUser(**user)

async def get_optional_user(session_token: str | None, authorization: str | None = None) -> Optional[AuthUser]:
    try:
        return await get_session_user(session_token, authorization)
    except HTTPException:
        return None

@api_router.post('/auth/session', response_model=AuthUser)
async def exchange_auth_session(payload: dict, response: Response):
    session_id = payload.get('session_id')
    if not session_id:
        raise HTTPException(status_code=400, detail='Missing session_id')
    try:
        async with httpx.AsyncClient(timeout=15) as hc:
            auth_response = await hc.get(
                'https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data',
                headers={'X-Session-ID': session_id},
            )
            auth_response.raise_for_status()
            identity = auth_response.json()
    except httpx.HTTPError as exc:
        logger.warning('Emergent auth exchange failed: %s', exc)
        raise HTTPException(status_code=401, detail='Unable to complete Google sign-in')
    user = await db.users.find_one({'email': identity['email']}, {'_id': 0})
    if user:
        user = {**user, 'name': identity.get('name', user.get('name', '')), 'picture': identity.get('picture', user.get('picture', ''))}
        await db.users.update_one({'user_id': user['user_id']}, {'$set': {'name': user['name'], 'picture': user['picture']}})
    else:
        user = {'user_id': f"user_{uuid.uuid4().hex[:12]}", 'email': identity['email'], 'name': identity.get('name', ''), 'picture': identity.get('picture', '')}
        await db.users.insert_one({**user, 'created_at': datetime.now(timezone.utc)})
    expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=7)
    await db.user_sessions.insert_one({'user_id': user['user_id'], 'session_token': identity['session_token'], 'expires_at': expires_at, 'created_at': datetime.now(timezone.utc)})
    response.set_cookie('session_token', identity['session_token'], max_age=7 * 24 * 60 * 60, httponly=True, secure=True, samesite='none', path='/')
    return AuthUser(**user)

@api_router.get('/auth/me', response_model=AuthUser)
async def auth_me(session_token: str | None = Cookie(default=None), authorization: str | None = Header(default=None)):
    return await get_session_user(session_token, authorization)

@api_router.post('/auth/logout')
async def auth_logout(response: Response, session_token: str | None = Cookie(default=None), authorization: str | None = Header(default=None)):
    token = session_token or (authorization[7:] if authorization and authorization.lower().startswith('bearer ') else None)
    if token:
        await db.user_sessions.delete_one({'session_token': token})
    response.delete_cookie('session_token', path='/')
    return {'ok': True}


# ---------- Helpers ----------
async def get_settings_doc():
    doc = await db.gateway_settings.find_one({'key': 'global'}, {'_id': 0, 'key': 0})
    return {**DEFAULT_SETTINGS, **(doc or {})}

def serialize_policy(p):
    return {
        'id': p['id'], 'name': p['name'], 'when': p.get('when', ['any']),
        'when_label': ', '.join(TYPE_LABELS.get(t, 'Any sensitive data') for t in p.get('when', ['any'])) or 'Any sensitive data',
        'risk': p.get('risk', 'Low'), 'then': p.get('then', 'MASK'), 'enabled': p.get('enabled', True),
        'created_at': p.get('created_at'),
    }

async def call_llm(provider: str, model: str, masked_message: str, session_id: str) -> str:
    if provider == 'Local AI':
        if not LOCAL_AI_BASE_URL:
            raise RuntimeError('Local AI endpoint is not configured. Set LOCAL_AI_BASE_URL in the backend environment.')
        async with httpx.AsyncClient(timeout=60) as hc:
            r = await hc.post(f"{LOCAL_AI_BASE_URL.rstrip('/')}/v1/chat/completions",
                              json={'model': model, 'messages': [{'role': 'user', 'content': masked_message}]})
            r.raise_for_status()
            return r.json()['choices'][0]['message']['content']
    if provider not in PROVIDER_MODELS:
        raise RuntimeError(f'Unknown provider: {provider}')
    api_key = os.environ.get(PROVIDER_KEY_ENVS[provider], '') or EMERGENT_LLM_KEY
    if not api_key:
        raise RuntimeError(f'{provider} is not configured. Add an API key in the backend environment.')
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    model_provider, model_name = PROVIDER_MODELS[provider]['provider'], model
    history = await db.chat_messages.find({'session_id': session_id}, {'_id': 0}).sort('created_at', -1).to_list(8)
    context = ''
    if history:
        lines = [f"{m['role']}: {m['content']}" for m in reversed(history)]
        context = "\n\nRecent conversation context:\n" + "\n".join(lines)
    chat = LlmChat(
        api_key=api_key,
        session_id=session_id,
        system_message='You are a helpful enterprise AI assistant behind the SentinelGuard security gateway. Sensitive data in prompts has been masked with placeholders like [EMAIL_MASKED]; treat them as redacted values and answer helpfully. Keep answers concise.' + context,
    ).with_model(model_provider, model_name)
    response = await chat.send_message(UserMessage(text=masked_message))
    return response


# ---------- Secure chat pipeline ----------
@api_router.post('/v1/secure/chat')
async def secure_chat(payload: SecureChatRequest,
                      session_token: str | None = Cookie(default=None),
                      authorization: str | None = Header(default=None)):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail='Message is required')
    model = resolve_model(payload.provider, payload.model)
    start = time.monotonic()
    user = await get_optional_user(session_token, authorization)
    user_name = (user.name or user.email) if user else 'console.user'
    settings = await get_settings_doc()

    masked, detections = detect_and_mask(payload.message)
    score = risk_score(detections)
    level = risk_level(score)
    detected_types = [d['type'] for d in detections]
    policies = await db.policies.find({}, {'_id': 0}).to_list(200)
    action, policy_name = evaluate_policies(detected_types, level, policies, settings['block_critical'])
    if settings.get('strict_policy') and detections and policy_name in ('Default sensitive data masking',):
        action, policy_name = 'BLOCK', 'Strict policy enforcement'

    ai_response = None
    error = None
    output_masked = False
    tokens_est = 0
    if action != 'BLOCK':
        outbound = masked if action == 'MASK' else payload.message
        try:
            ai_response = await call_llm(payload.provider, model, outbound, payload.session_id)
            if settings.get('scan_output') and ai_response:
                scanned, out_detections = detect_and_mask(ai_response)
                if out_detections:
                    ai_response = scanned
                    output_masked = True
            tokens_est = (len(outbound) + len(ai_response or '')) // 4
        except Exception as exc:
            logger.warning('Provider call failed: %s', exc)
            error = str(exc)
        now = datetime.now(timezone.utc).isoformat()
        await db.chat_messages.insert_many([
            {'session_id': payload.session_id, 'role': 'user', 'content': masked, 'created_at': now},
            {'session_id': payload.session_id, 'role': 'assistant', 'content': (ai_response or '')[:2000], 'created_at': now},
        ])

    latency_ms = int((time.monotonic() - start) * 1000)
    data_summary = ', '.join(d['label'] for d in detections) if detections else 'None detected'
    event = {
        'id': f"req_{uuid.uuid4().hex[:6].upper()}",
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'user': user_name,
        'data': data_summary,
        'detected_types': detected_types,
        'score': score,
        'risk_level': level,
        'action': 'ALLOWED' if action == 'ALLOW' else 'MASKED' if action == 'MASK' else 'BLOCKED',
        'provider': payload.provider,
        'model': model,
        'policy': policy_name,
        'latency_ms': latency_ms,
        'session_id': payload.session_id,
        'output_masked': output_masked,
        'tokens_est': tokens_est,
    }
    await db.security_events.insert_one({**event})
    publish_event(event)

    return {
        'event_id': event['id'],
        'decision': {
            'action': event['action'],
            'score': score,
            'risk_level': level,
            'policy': policy_name,
            'detected': [{'type': d['type'], 'label': d['label'], 'count': d['count'],
                          'original': d['original'], 'masked': d['masked']} for d in detections],
        },
        'masked_message': masked if detections else None,
        'response': ai_response,
        'error': error,
        'output_masked': output_masked,
        'latency_ms': latency_ms,
        'provider': payload.provider,
        'model': model,
    }


# ---------- Models catalog ----------
@api_router.get('/v1/models')
async def list_models():
    providers = []
    for name, cfg in PROVIDER_MODELS.items():
        own = bool(os.environ.get(PROVIDER_KEY_ENVS[name], ''))
        providers.append({'name': name, 'default': cfg['default'], 'models': cfg['models'],
                          'key_source': 'own' if own else 'universal'})
    providers.append({'name': 'Local AI', 'default': 'local', 'models': ['local'],
                      'key_source': 'endpoint' if LOCAL_AI_BASE_URL else 'not-configured'})
    return {'providers': providers}


# ---------- Events ----------
@api_router.get('/v1/events/stream')
async def events_stream():
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    event_subscribers.add(q)

    async def gen():
        try:
            yield ': connected\n\n'
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=20)
                    yield f'data: {json.dumps(ev)}\n\n'
                except asyncio.TimeoutError:
                    yield ': keepalive\n\n'
        finally:
            event_subscribers.discard(q)

    return StreamingResponse(gen(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@api_router.get('/v1/events')
async def get_events(search: str = '', limit: int = Query(default=100, le=500)):
    query = {}
    if search:
        rx = {'$regex': search, '$options': 'i'}
        query = {'$or': [{'id': rx}, {'user': rx}, {'data': rx}, {'policy': rx}, {'provider': rx}, {'action': rx}]}
    items = await db.security_events.find(query, {'_id': 0}).sort('timestamp', -1).to_list(limit)
    return {'items': items, 'total': len(items)}


# ---------- Model analytics ----------
@api_router.get('/v1/analytics/models')
async def model_analytics():
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    events = await db.security_events.find(
        {'timestamp': {'$gte': since}, 'model': {'$exists': True}}, {'_id': 0}).to_list(10000)
    groups: dict = {}
    for e in events:
        g = groups.setdefault(e['model'], {'model': e['model'], 'provider': e.get('provider', ''),
                                           'requests': 0, 'blocked': 0, 'score_sum': 0, 'latency_sum': 0, 'tokens': 0})
        g['requests'] += 1
        g['blocked'] += 1 if e['action'] == 'BLOCKED' else 0
        g['score_sum'] += e.get('score', 0)
        g['latency_sum'] += e.get('latency_ms', 0)
        g['tokens'] += e.get('tokens_est', 0)
    items = [{
        'model': g['model'], 'provider': g['provider'], 'requests': g['requests'], 'blocked': g['blocked'],
        'avg_score': round(g['score_sum'] / g['requests']),
        'avg_latency_ms': round(g['latency_sum'] / g['requests']),
        'tokens_est': g['tokens'],
        'est_cost': round(g['tokens'] / 1_000_000 * MODEL_PRICES.get(g['model'], 2.0), 4),
    } for g in groups.values()]
    items.sort(key=lambda x: -x['requests'])
    mx = max([i['requests'] for i in items], default=1)
    for i in items:
        i['share'] = round(i['requests'] / mx * 100)
    return {'items': items, 'window_days': 7}


# ---------- Dashboard ----------
def pct_change(curr: int, prev: int) -> str:
    if prev == 0:
        return '+100%' if curr > 0 else '+0%'
    delta = (curr - prev) / prev * 100
    return f"{'+' if delta >= 0 else ''}{delta:.1f}%"

@api_router.get('/v1/dashboard/stats')
async def dashboard_stats():
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=24)).isoformat()
    prev_since = (now - timedelta(hours=48)).isoformat()
    events = await db.security_events.find({'timestamp': {'$gte': since}}, {'_id': 0}).sort('timestamp', -1).to_list(5000)
    prev_events = await db.security_events.find({'timestamp': {'$gte': prev_since, '$lt': since}}, {'_id': 0}).to_list(5000)

    def summarize(evts):
        return {
            'requests': len(evts),
            'threats': sum(1 for e in evts if e['score'] >= 25),
            'blocked': sum(1 for e in evts if e['action'] == 'BLOCKED'),
            'sensitive': sum(1 for e in evts if e.get('detected_types')),
        }
    curr, prev = summarize(events), summarize(prev_events)

    trend = []
    for i in range(8):
        b_start = now - timedelta(hours=24 - i * 3)
        b_end = b_start + timedelta(hours=3)
        bucket = [e for e in events if b_start.isoformat() <= e['timestamp'] < b_end.isoformat()]
        trend.append({'name': b_end.strftime('%H:00'),
                      'requests': len(bucket),
                      'threats': sum(1 for e in bucket if e['score'] >= 25)})

    colors = {'Low': '#31c48d', 'Medium': '#f6b73c', 'High': '#f07167', 'Critical': '#c94b63'}
    total = max(1, len(events))
    risk_distribution = [
        {'name': lvl, 'value': round(sum(1 for e in events if e['risk_level'] == lvl) / total * 100), 'color': colors[lvl]}
        for lvl in ['Low', 'Medium', 'High', 'Critical']
    ]

    providers = [
        {'name': 'Gemini', 'status': 'connected' if EMERGENT_LLM_KEY else 'not-configured', 'uptime': '99.99%', 'kind': 'External provider'},
        {'name': 'OpenAI', 'status': 'connected' if EMERGENT_LLM_KEY else 'not-configured', 'uptime': '99.99%', 'kind': 'External provider'},
        {'name': 'Claude', 'status': 'connected' if EMERGENT_LLM_KEY else 'not-configured', 'uptime': '99.98%', 'kind': 'External provider'},
        {'name': 'Local AI', 'status': 'connected' if LOCAL_AI_BASE_URL else 'not-configured', 'uptime': '—', 'kind': 'On-premise endpoint'},
    ]

    return {
        'totals': {
            'requests': curr['requests'], 'requests_change': pct_change(curr['requests'], prev['requests']),
            'threats': curr['threats'], 'threats_change': pct_change(curr['threats'], prev['threats']),
            'blocked': curr['blocked'], 'blocked_change': pct_change(curr['blocked'], prev['blocked']),
            'sensitive': curr['sensitive'], 'sensitive_change': pct_change(curr['sensitive'], prev['sensitive']),
        },
        'trend': trend,
        'risk_distribution': risk_distribution,
        'recent_events': events[:6],
        'providers': providers,
        'total_analyzed': len(events),
    }


# ---------- Policies ----------
@api_router.get('/v1/policies')
async def list_policies():
    policies = await db.policies.find({}, {'_id': 0}).sort('created_at', 1).to_list(200)
    return {'items': [serialize_policy(p) for p in policies]}

@api_router.post('/v1/policies')
async def create_policy(payload: PolicyCreate):
    if payload.risk not in ('Low', 'Medium', 'High', 'Critical'):
        raise HTTPException(status_code=400, detail='Invalid risk level')
    if payload.then not in ('ALLOW', 'MASK', 'BLOCK'):
        raise HTTPException(status_code=400, detail='Invalid action')
    doc = {
        'id': f"pol_{uuid.uuid4().hex[:8]}", 'name': payload.name.strip() or 'New protection policy',
        'when': payload.when or ['any'], 'risk': payload.risk, 'then': payload.then,
        'enabled': payload.enabled, 'created_at': datetime.now(timezone.utc).isoformat(),
    }
    await db.policies.insert_one({**doc})
    return serialize_policy(doc)

@api_router.put('/v1/policies/{policy_id}')
async def update_policy(policy_id: str, payload: PolicyUpdate):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail='No changes provided')
    result = await db.policies.update_one({'id': policy_id}, {'$set': updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail='Policy not found')
    doc = await db.policies.find_one({'id': policy_id}, {'_id': 0})
    return serialize_policy(doc)

@api_router.delete('/v1/policies/{policy_id}')
async def delete_policy(policy_id: str):
    result = await db.policies.delete_one({'id': policy_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail='Policy not found')
    return {'ok': True}


# ---------- Audit logs ----------
@api_router.get('/v1/audit-logs')
async def audit_logs(search: str = '', action: str = '', page: int = Query(default=1, ge=1),
                     page_size: int = Query(default=10, le=100)):
    query = {}
    clauses = []
    if search:
        rx = {'$regex': search, '$options': 'i'}
        clauses.append({'$or': [{'id': rx}, {'user': rx}, {'data': rx}, {'policy': rx}, {'provider': rx}]})
    if action and action.upper() != 'ALL':
        clauses.append({'action': action.upper()})
    if clauses:
        query = {'$and': clauses} if len(clauses) > 1 else clauses[0]
    total = await db.security_events.count_documents(query)
    items = await db.security_events.find(query, {'_id': 0}).sort('timestamp', -1)\
        .skip((page - 1) * page_size).to_list(page_size)
    return {'items': items, 'total': total, 'page': page, 'page_size': page_size}


# ---------- Settings ----------
@api_router.get('/v1/settings')
async def get_settings():
    settings = await get_settings_doc()
    return settings

@api_router.put('/v1/settings')
async def update_settings(payload: SettingsUpdate):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if updates:
        await db.gateway_settings.update_one({'key': 'global'}, {'$set': updates}, upsert=True)
    return await get_settings_doc()


# ---------- Status checks (legacy) ----------
@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_obj = StatusCheck(**input.model_dump())
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    return status_checks


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[],
    allow_origin_regex='.*',
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def seed_defaults():
    if await db.policies.count_documents({}) == 0:
        now = datetime.now(timezone.utc).isoformat()
        await db.policies.insert_many([
            {**p, 'id': f"pol_{uuid.uuid4().hex[:8]}", 'created_at': now} for p in DEFAULT_POLICIES
        ])
        logger.info('Seeded default security policies')

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
