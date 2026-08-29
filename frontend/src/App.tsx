import { useCallback, useEffect, useRef, useState } from 'react';
import { BrowserRouter, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Activity, AlertTriangle, ArrowUpRight, Bell, Bot, Check, ChevronDown, ChevronLeft, ChevronRight, CircleHelp, Code2, Database, FileClock, Filter, KeyRound, LayoutDashboard, Menu, MoreHorizontal, Plus, RotateCw, Search, Send, Settings as SettingsIcon, ShieldCheck, ShieldX, SlidersHorizontal, Sparkles, Terminal, Trash2, UserRound, X, Zap } from 'lucide-react';
import { Toaster, toast } from 'sonner';
import { api } from './services/api.ts';
import type { ChatDecision, SecurityEvent, SecurityPolicy } from './types/index.ts';
import './App.css';

type Action = 'ALLOWED' | 'MASKED' | 'BLOCKED';
type AuthUser = { user_id: string; email: string; name: string; picture?: string };
const API_ROOT = `${process.env.REACT_APP_BACKEND_URL}/api`;

const nav = [{ to: '/', label: 'Overview', icon: LayoutDashboard }, { to: '/console', label: 'AI Security Console', icon: Terminal }, { to: '/events', label: 'Live Events', icon: Activity }, { to: '/policies', label: 'Policies', icon: SlidersHorizontal }, { to: '/audit', label: 'Audit Logs', icon: FileClock }, { to: '/settings', label: 'Settings', icon: SettingsIcon }];
const DATA_TYPES: [string, string][] = [['any', 'Any sensitive data'], ['email', 'Email address'], ['phone', 'Phone number'], ['credit_card', 'Credit card'], ['aadhaar', 'Aadhaar number'], ['pan', 'PAN number'], ['password', 'Password'], ['api_key', 'API key'], ['jwt_token', 'JWT token'], ['secret_key', 'Secret key']];

function timeAgo(iso: string) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return 'Just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} hr ago`;
  return new Date(iso).toLocaleDateString();
}
const riskClass = (score: number) => (score > 80 ? 'critical' : score > 50 ? 'high' : score > 25 ? 'medium' : 'low');

function Badge({ action }: { action: Action }) { return <span data-testid={`status-badge-${action.toLowerCase()}`} className={`badge ${action.toLowerCase()}`}><span />{action}</span>; }
function SectionTitle({ eyebrow, title, sub, action }: { eyebrow: string; title: string; sub: string; action?: React.ReactNode }) { return <div className="section-head"><div><p className="eyebrow">{eyebrow}</p><h1 data-testid="page-title">{title}</h1><p className="subtle">{sub}</p></div>{action}</div>; }
function Metric({ label, value, change, icon: Icon, tone }: { label: string; value: string; change: string; icon: any; tone: string }) { return <div className="metric" data-testid={`metric-${label.toLowerCase().replaceAll(' ', '-')}`}><div className={`metric-icon ${tone}`}><Icon size={18} /></div><div><p>{label}</p><strong>{value}</strong><small className={change.startsWith('+') ? 'up' : 'down'}>{change} <span>vs last 24h</span></small></div></div>; }
function ChartCard({ title, children, note }: { title: string; children: React.ReactNode; note: string }) { return <section className="panel chart-card"><div className="panel-head"><div><h2>{title}</h2><p>{note}</p></div><button className="icon-btn" data-testid={`${title.toLowerCase().replaceAll(' ', '-')}-menu-button`} aria-label={`${title} options`}><MoreHorizontal size={18} /></button></div>{children}</section>; }
function PageLoader({ label = 'Loading gateway data...' }: { label?: string }) { return <div className="auth-loading" data-testid="page-loading-state" style={{ minHeight: 320 }}><div className="scan-spinner" /><p>{label}</p></div>; }
function EmptyRow({ colSpan, text }: { colSpan: number; text: string }) { return <tr><td colSpan={colSpan} className="muted" style={{ textAlign: 'center', padding: '28px 0' }} data-testid="empty-table-state">{text}</td></tr>; }

function EventTable({ compact = false, rows, onRowClick }: { compact?: boolean; rows: SecurityEvent[]; onRowClick?: (e: SecurityEvent) => void }) {
  return <div className="table-wrap"><table data-testid="security-events-table"><thead><tr><th>Time</th><th>Request ID</th><th>User</th><th>Detected data</th><th>Risk</th><th>Action</th></tr></thead><tbody>
    {rows.length === 0 && <EmptyRow colSpan={6} text="No security events yet. Send a prompt from the AI Security Console." />}
    {rows.slice(0, compact ? 4 : rows.length).map(e => <tr key={e.id} onClick={onRowClick ? () => onRowClick(e) : undefined} style={onRowClick ? { cursor: 'pointer' } : undefined}><td className="muted">{timeAgo(e.timestamp)}</td><td className="mono">{e.id}</td><td>{e.user}</td><td>{e.data}</td><td><span className={`risk-score ${riskClass(e.score)}`}>{e.score}</span></td><td><Badge action={e.action} /></td></tr>)}
  </tbody></table></div>;
}

function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [modelStats, setModelStats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [s, m] = await Promise.all([api.getDashboard(), api.getModelAnalytics()]);
      setStats(s); setModelStats(m.items);
    } catch (e: any) { toast.error(`Could not load dashboard: ${e.message}`); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const t = window.setInterval(() => load(true), 60000); return () => window.clearInterval(t); }, [load]);
  useEffect(() => {
    const es = new EventSource(`${api.baseUrl}/v1/events/stream`);
    es.onmessage = () => load(true);
    return () => es.close();
  }, [load]);
  if (loading && !stats) return <PageLoader />;
  if (!stats) return <div className="page"><PageLoader label="Dashboard unavailable. Retrying..." /></div>;
  const t = stats.totals;
  return <div className="page"><SectionTitle eyebrow="Security overview / 24 hours" title="Gateway overview" sub="Your gateway is live. Here’s what happened across your AI traffic." action={<button className="secondary-btn" data-testid="dashboard-refresh-button" onClick={() => { load(); toast.success('Dashboard refreshed'); }}><RotateCw size={15} /> Refresh data</button>} />
    <div className="metrics"><Metric label="Total Requests" value={t.requests.toLocaleString()} change={t.requests_change} icon={Zap} tone="blue" /><Metric label="Threats Detected" value={t.threats.toLocaleString()} change={t.threats_change} icon={AlertTriangle} tone="amber" /><Metric label="Requests Blocked" value={t.blocked.toLocaleString()} change={t.blocked_change} icon={ShieldCheck} tone="red" /><Metric label="Sensitive Data Events" value={t.sensitive.toLocaleString()} change={t.sensitive_change} icon={Database} tone="green" /></div>
    <div className="chart-grid">
      <ChartCard title="Security activity" note="Requests and threats detected"><ResponsiveContainer width="100%" height={225}><AreaChart data={stats.trend}><defs><linearGradient id="req" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3986ff" stopOpacity={.25} /><stop offset="100%" stopColor="#3986ff" stopOpacity={0} /></linearGradient></defs><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e8edf4" /><XAxis dataKey="name" tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: '#8995a7' }} /><YAxis hide /><Tooltip /><Area type="monotone" dataKey="requests" stroke="#3986ff" strokeWidth={2.5} fill="url(#req)" /><Area type="monotone" dataKey="threats" stroke="#f6b73c" strokeWidth={2} fill="none" /></AreaChart></ResponsiveContainer><div className="legend"><span><i className="blue-dot" />Requests</span><span><i className="amber-dot" />Threats</span><b>{t.requests_change} <ArrowUpRight size={13} /></b></div></ChartCard>
      <ChartCard title="Risk distribution" note="Analyzed requests by risk level"><div className="donut-wrap"><ResponsiveContainer width="55%" height={185}><PieChart><Pie data={stats.total_analyzed ? stats.risk_distribution : [{ name: 'None', value: 100, color: '#e8edf4' }]} innerRadius={56} outerRadius={78} dataKey="value" strokeWidth={0}>{(stats.total_analyzed ? stats.risk_distribution : [{ name: 'None', value: 100, color: '#e8edf4' }]).map((x: any) => <Cell key={x.name} fill={x.color} />)}</Pie></PieChart></ResponsiveContainer><div className="donut-center"><strong>{stats.total_analyzed >= 1000 ? `${(stats.total_analyzed / 1000).toFixed(1)}k` : stats.total_analyzed}</strong><span>requests</span></div><div className="risk-list">{stats.risk_distribution.map((x: any) => <div key={x.name}><span><i style={{ background: x.color }} />{x.name}</span><b>{x.value}%</b></div>)}</div></div></ChartCard>
    </div>
    <div className="lower-grid">
      <section className="panel"><div className="panel-head"><div><h2>Live security events</h2><p>Streaming from your gateway in real time</p></div><NavLink to="/events" className="text-link" data-testid="view-all-events-link">View all <ArrowUpRight size={14} /></NavLink></div><EventTable compact rows={stats.recent_events} /></section>
      <section className="panel providers"><div className="panel-head"><div><h2>AI provider status</h2><p>Health across connected models</p></div><span className="live-pill"><span /> All systems operational</span></div>{stats.providers.map((p: any) => <div className="provider" key={p.name} data-testid={`provider-status-${p.name.toLowerCase().replace(' ', '-')}`}><span className="provider-logo">{p.name === 'Local AI' ? <Code2 size={16} /> : <Bot size={16} />}</span><div><b>{p.name}</b><small>{p.kind}</small></div>{p.status === 'connected' ? <span className="provider-health"><span /> {p.uptime}</span> : <span className="disconnected">Not configured</span>}</div>)}</section>
    </div>
    <section className="panel full-table" data-testid="model-analytics-panel"><div className="panel-head"><div><h2>Model usage analytics</h2><p>Requests, risk, and estimated cost per model · last 7 days</p></div><span className="live-pill"><span /> Live</span></div>
      <div className="table-wrap"><table data-testid="model-analytics-table"><thead><tr><th>Model</th><th>Provider</th><th>Requests</th><th>Avg risk</th><th>Blocked</th><th>Avg latency</th><th>Est. tokens</th><th>Est. cost</th></tr></thead><tbody>
        {modelStats.length === 0 && <EmptyRow colSpan={8} text="No model usage yet. Send prompts from the AI Security Console." />}
        {modelStats.map((m: any) => <tr key={m.model} data-testid={`model-analytics-row-${m.model}`}><td className="mono">{m.model}</td><td>{m.provider}</td><td><div style={{ display: 'flex', alignItems: 'center', gap: 9 }}><span style={{ height: 6, width: 90, background: '#eef2f7', borderRadius: 4, display: 'inline-block' }}><span style={{ height: 6, width: `${m.share}%`, background: '#3986ff', borderRadius: 4, display: 'block' }} /></span><b>{m.requests}</b></div></td><td><span className={`risk-score ${riskClass(m.avg_score)}`}>{m.avg_score}</span></td><td>{m.blocked}</td><td className="muted">{m.avg_latency_ms} ms</td><td className="muted">{m.tokens_est.toLocaleString()}</td><td><b>${m.est_cost.toFixed(4)}</b></td></tr>)}
      </tbody></table></div>
    </section></div>;
}

function Events() {
  const [query, setQuery] = useState('');
  const [rows, setRows] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try { const res = await api.getEvents(); setRows(res.items); } catch (e: any) { toast.error(`Could not load events: ${e.message}`); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const t = window.setInterval(() => load(true), 60000); return () => window.clearInterval(t); }, [load]);
  useEffect(() => {
    const es = new EventSource(`${api.baseUrl}/v1/events/stream`);
    es.onmessage = m => {
      const ev = JSON.parse(m.data);
      setRows(r => [ev, ...r.filter(x => x.id !== ev.id)]);
    };
    return () => es.close();
  }, []);
  const filtered = rows.filter(e => [e.id, e.user, e.data, e.policy, e.provider, e.action].some(v => String(v).toLowerCase().includes(query.toLowerCase())));
  return <div className="page"><SectionTitle eyebrow="Real-time monitoring" title="Live security events" sub="Track every decision made by the SentinelGuard gateway." action={<span className="live-pill"><span /> Auto-refreshing</span>} />
    <div className="toolbar"><label className="search"><Search size={16} /><input data-testid="events-search-input" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search events, users, request IDs..." /></label><button className="filter-btn" data-testid="events-filter-button"><Filter size={15} /> Risk: All <ChevronDown size={14} /></button><button className="filter-btn" data-testid="events-date-filter-button"><FileClock size={15} /> Last 24 hours <ChevronDown size={14} /></button></div>
    <section className="panel full-table"><div className="panel-head"><div><h2>Gateway activity</h2><p>{filtered.length} events in the current view</p></div><button className="icon-btn" data-testid="events-refresh-button" onClick={() => { load(); toast.success('Events refreshed'); }}><RotateCw size={17} /></button></div>
      {loading && rows.length === 0 ? <PageLoader label="Loading live events..." /> : <EventTable rows={filtered} />}</section></div>;
}

type Msg = { role: 'user' | 'assistant'; text: string; blocked?: boolean; masked?: boolean; error?: boolean; at: string };
const PIPELINE = ['Scanning request', 'Detecting sensitive data', 'Calculating risk score', 'Checking security policy', 'Decision', 'Sending protected request'];

function Console() {
  const [provider, setProvider] = useState('Gemini');
  const [providerCfg, setProviderCfg] = useState<any[]>([]);
  const [model, setModel] = useState('');
  const [message, setMessage] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [history, setHistory] = useState<Msg[]>([]);
  const [analysis, setAnalysis] = useState<(ChatDecision & { latency: number; provider: string; model?: string }) | null>(null);
  const [sessionId, setSessionId] = useState(() => crypto.randomUUID());
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => { api.getModels().then((r: any) => { setProviderCfg(r.providers); setModel(r.providers[0]?.default || ''); }).catch(() => {}); }, []);
  const models: string[] = providerCfg.find((p: any) => p.name === provider)?.models || [];
  const pickProvider = (p: string) => { setProvider(p); setModel(providerCfg.find((x: any) => x.name === p)?.default || ''); };
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [history, scanning]);
  useEffect(() => { if (!scanning) return; setScanStep(0); const t = window.setInterval(() => setScanStep(s => Math.min(s + 1, 4)), 550); return () => window.clearInterval(t); }, [scanning]);
  const now = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const send = async () => {
    const text = message.trim();
    if (!text || scanning) return;
    setMessage(''); setScanning(true);
    setHistory(h => [...h, { role: 'user', text, at: now() }]);
    try {
      const res = await api.secureChat({ message: text, provider, model: model || undefined, session_id: sessionId });
      setAnalysis({ ...res.decision, latency: res.latency_ms, provider, model: res.model });
      if (res.decision.action === 'BLOCKED') {
        setHistory(h => [...h, { role: 'assistant', blocked: true, text: `Request blocked by policy “${res.decision.policy}”. No data left the gateway.`, at: now() }]);
        toast.error('Request blocked by security policy');
      } else if (res.error) {
        setHistory(h => [...h, { role: 'assistant', error: true, text: res.error!, at: now() }]);
        toast.error('Provider error');
      } else {
        setHistory(h => [...h, { role: 'assistant', masked: res.decision.action === 'MASKED', text: res.response || '', at: now() }]);
      }
    } catch (e: any) {
      setHistory(h => [...h, { role: 'assistant', error: true, text: `Gateway error: ${e.message}`, at: now() }]);
      toast.error(e.message);
    } finally { setScanning(false); }
  };
  const reset = () => { setHistory([]); setAnalysis(null); setSessionId(crypto.randomUUID()); toast.success('New protected conversation started'); };
  const firstDetected = analysis?.detected?.[0];
  return <div className="page console-page"><SectionTitle eyebrow="Protected inference" title="AI Security Console" sub="Test prompts safely through your active governance policies." action={<div className="secure-state"><ShieldCheck size={15} /> Gateway protected</div>} />
    <div className="console-layout">
      <section className="panel chat-panel">
        <div className="chat-top"><div className="conversation-label"><span className="blue-square"><Sparkles size={16} /></span><div><b>Protected conversation</b><small>Session {sessionId.slice(0, 8)} · Policy enforcement live</small></div></div><button className="icon-btn" data-testid="new-conversation-button" aria-label="New conversation" onClick={reset}><Plus size={18} /></button></div>
        <div className="messages" data-testid="conversation-history">
          <div className="message assistant"><span className="avatar"><ShieldCheck size={15} /></span><div><small>SentinelGuard <em>{now()}</em></small><p>Ready when you are. Every prompt will be scanned and protected before reaching the model.</p></div></div>
          {history.map((m, i) => m.role === 'user'
            ? <div className="message user" key={i}><span className="avatar user-avatar"><UserRound size={15} /></span><div><small>You <em>{m.at}</em></small><p>{m.text}</p></div></div>
            : <div className="message assistant" key={i}><span className="avatar">{m.blocked ? <ShieldX size={15} /> : <ShieldCheck size={15} />}</span><div><small>SentinelGuard <em>{m.at}</em></small>{m.masked && <p className="success-text"><Check size={14} /> Request masked and delivered securely</p>}{m.blocked ? <p className="success-text" style={{ color: '#c94b63' }} data-testid="blocked-message"><ShieldX size={14} /> {m.text}</p> : m.error ? <p style={{ color: '#c94b63' }} data-testid="provider-error-message">{m.text}</p> : <p style={{ whiteSpace: 'pre-wrap' }} data-testid="ai-response-message">{m.text}</p>}</div></div>)}
          <div ref={bottomRef} />
        </div>
        {scanning && <div className="scan-strip" data-testid="security-scan-progress"><div className="scan-spinner" /><div><b>Scanning request...</b><span>Detecting sensitive data · calculating risk · checking policy</span></div><strong>{String(Math.min(scanStep + 1, 6)).padStart(2, '0')} / 06</strong></div>}
        <div className="composer">
          <div style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="provider-select"><Bot size={16} /><select data-testid="ai-provider-select" value={provider} onChange={e => pickProvider(e.target.value)}>{['Gemini', 'OpenAI', 'Claude', 'Local AI'].map(p => <option key={p}>{p}</option>)}</select><ChevronDown size={14} /></div>
            <div className="provider-select"><Sparkles size={16} /><select data-testid="ai-model-select" value={model} onChange={e => setModel(e.target.value)}>{(models.length ? models : [model || '...']).map((m: string) => <option key={m}>{m}</option>)}</select><ChevronDown size={14} /></div>
          </div>
          <textarea data-testid="secure-prompt-input" value={message} onChange={e => setMessage(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }} placeholder="Send a prompt through the security gateway..." rows={3} />
          <div className="composer-bottom"><span><KeyRound size={13} /> PII masking active</span><button className="primary-btn" data-testid="secure-send-button" onClick={send} disabled={scanning}><Send size={15} /> {scanning ? 'Securing...' : 'Secure send'}</button></div>
        </div>
      </section>
      <aside className="panel analysis-card">
        <div className="panel-head"><div><h2>Security analysis</h2><p>{analysis ? 'Latest request inspection' : 'Awaiting first request'}</p></div><span className="analysis-dot" /></div>
        <div className="pipeline">{PIPELINE.map((s, i) => {
          const done = !scanning && analysis && (i < 5 || analysis.action !== 'BLOCKED');
          const active = scanning && i === scanStep;
          const label = i === 4 && analysis && !scanning ? `Decision: ${analysis.action}` : s;
          const sub = !scanning && analysis ? (i === 1 ? `${analysis.detected.length} item${analysis.detected.length === 1 ? '' : 's'} detected` : i === 2 ? `Score ${analysis.score} / 100` : i === 4 ? `${analysis.risk_level} risk` : i === 5 ? (analysis.action === 'BLOCKED' ? 'Blocked before send' : `${analysis.model || analysis.provider} · ${analysis.latency}ms`) : '') : '';
          return <div key={s} className={`pipeline-step ${active ? 'active' : done ? 'done' : ''}`}><span>{done ? <Check size={12} /> : i + 1}</span><p>{label}<small>{sub}</small></p></div>;
        })}</div>
        {analysis ? <div className="analysis-result" data-testid="analysis-result">
          <div className="result-head"><span>Decision</span><Badge action={analysis.action} /></div>
          <div className="result-grid"><div><small>Detected data</small><b>{analysis.detected.length ? analysis.detected.map(d => d.label).join(', ') : 'None'}</b></div><div><small>Risk score</small><b>{analysis.score} / 100</b></div><div><small>Risk level</small><b className={analysis.risk_level === 'Low' ? '' : 'amber-text'}>{analysis.risk_level.toUpperCase()}</b></div></div>
          <div className="result-grid" style={{ marginTop: 10 }}><div><small>Policy applied</small><b>{analysis.policy}</b></div></div>
          {firstDetected && <div className="data-transform"><div><small>Original data</small><code>{firstDetected.original}</code></div><ArrowUpRight size={16} /><div><small>Protected data</small><code>{firstDetected.masked}</code></div></div>}
        </div> : <div className="analysis-result"><p className="muted" data-testid="analysis-empty-state" style={{ fontSize: 13 }}>Send a prompt to see live detection, masking, risk scoring, and the policy decision here.</p></div>}
      </aside>
    </div></div>;
}

function Policies() {
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [whenType, setWhenType] = useState('any');
  const [risk, setRisk] = useState('Critical');
  const [action, setAction] = useState('BLOCK');
  const [saving, setSaving] = useState(false);
  const load = useCallback(async () => {
    try { const res = await api.getPolicies(); setPolicies(res.items); } catch (e: any) { toast.error(`Could not load policies: ${e.message}`); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);
  const save = async () => {
    if (saving) return;
    setSaving(true);
    const label = DATA_TYPES.find(d => d[0] === whenType)?.[1] || 'Sensitive data';
    try {
      await api.createPolicy({ name: name.trim() || `${label} ${action.toLowerCase()} policy`, when: [whenType], risk, then: action });
      setName(''); toast.success('Policy saved and enforced'); load();
    } catch (e: any) { toast.error(e.message); } finally { setSaving(false); }
  };
  const toggle = async (p: SecurityPolicy) => {
    setPolicies(ps => ps.map(x => x.id === p.id ? { ...x, enabled: !x.enabled } : x));
    try { await api.updatePolicy(p.id, { enabled: !p.enabled }); toast.success(`Policy ${!p.enabled ? 'enabled' : 'disabled'}`); }
    catch (e: any) { toast.error(e.message); load(); }
  };
  const remove = async (p: SecurityPolicy) => {
    setPolicies(ps => ps.filter(x => x.id !== p.id));
    try { await api.deletePolicy(p.id); toast.success('Policy deleted'); } catch (e: any) { toast.error(e.message); load(); }
  };
  const selStyle = { borderColor: '#1f6fff', color: '#1f6fff', background: '#eef4ff' };
  return <div className="page"><SectionTitle eyebrow="Governance" title="Policy management" sub="Define the decisions your gateway makes before inference." action={<button className="primary-btn" data-testid="create-policy-button" onClick={save} disabled={saving}><Plus size={15} /> Create policy</button>} />
    <div className="policy-layout">
      <section className="panel builder"><div className="panel-head"><div><h2>Visual policy builder</h2><p>Compose a new rule with plain language controls</p></div><span className="draft-pill">Draft</span></div>
        <div className="rule">
          <label>POLICY NAME</label>
          <input data-testid="policy-name-input" value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Finance PII lockdown" style={{ width: '100%', padding: '10px 12px', border: '1px solid #dde4ee', borderRadius: 10, fontSize: 13, fontFamily: 'inherit', outline: 'none', background: '#fbfcfe' }} />
          <label>WHEN</label>
          <div className="rule-select" style={{ position: 'relative' }}><select data-testid="policy-when-select" value={whenType} onChange={e => setWhenType(e.target.value)} style={{ position: 'absolute', inset: 0, opacity: 0, cursor: 'pointer', width: '100%' }}>{DATA_TYPES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>{DATA_TYPES.find(d => d[0] === whenType)?.[1]} <ChevronDown size={15} /></div>
          <label>AND RISK IS AT LEAST</label>
          <div className="risk-options">{['Low', 'Medium', 'High', 'Critical'].map(r => <button key={r} className={`risk-option ${risk === r ? 'selected' : ''}`} style={risk === r ? selStyle : undefined} data-testid={`policy-risk-${r.toLowerCase()}`} onClick={() => setRisk(r)}>{r}</button>)}</div>
          <label>THEN</label>
          <div className="action-options">{['ALLOW', 'MASK', 'BLOCK'].map(a => <button key={a} className={`action-option ${action === a && a === 'BLOCK' ? 'selected-block' : ''}`} style={action === a && a !== 'BLOCK' ? selStyle : undefined} data-testid={`policy-action-${a.toLowerCase()}`} onClick={() => setAction(a)}>{a}</button>)}</div>
        </div>
        <button className="primary-btn wide" data-testid="save-policy-button" onClick={save} disabled={saving}><Check size={15} /> {saving ? 'Saving...' : 'Save policy'}</button>
      </section>
      <section className="panel"><div className="panel-head"><div><h2>Active policies</h2><p>{policies.filter(p => p.enabled).length} enabled policies</p></div><button className="icon-btn" data-testid="policies-filter-button"><Filter size={17} /></button></div>
        {loading ? <PageLoader label="Loading policies..." /> : <div className="policy-list">
          {policies.length === 0 && <p className="muted" style={{ padding: 16 }} data-testid="policies-empty-state">No policies yet. Create one with the builder.</p>}
          {policies.map(p => <div className="policy-row" key={p.id} data-testid={`policy-row-${p.id}`}><div className="policy-symbol"><ShieldCheck size={17} /></div><div className="policy-info"><b>{p.name}</b><span>WHEN <strong>{p.when_label}</strong> · RISK <strong>{p.risk}+</strong> · THEN <strong className={p.then.toLowerCase()}>{p.then}</strong></span></div><button className={`toggle ${p.enabled ? 'on' : ''}`} data-testid={`policy-toggle-${p.id}`} aria-label={`Toggle ${p.name}`} onClick={() => toggle(p)}><span /></button><button className="icon-btn subtle-icon" data-testid={`policy-delete-${p.id}`} aria-label={`Delete ${p.name}`} onClick={() => remove(p)}><Trash2 size={15} /></button></div>)}
        </div>}
      </section>
    </div></div>;
}

function Audit() {
  const [open, setOpen] = useState<SecurityEvent | null>(null);
  const [search, setSearch] = useState('');
  const [action, setAction] = useState('ALL');
  const [page, setPage] = useState(1);
  const [data, setData] = useState<{ items: SecurityEvent[]; total: number }>({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const pageSize = 10;
  useEffect(() => {
    const t = window.setTimeout(async () => {
      setLoading(true);
      try { setData(await api.getAuditLogs({ search, action, page, page_size: pageSize })); }
      catch (e: any) { toast.error(`Could not load audit logs: ${e.message}`); }
      finally { setLoading(false); }
    }, search ? 350 : 0);
    return () => window.clearTimeout(t);
  }, [search, action, page]);
  const pages = Math.max(1, Math.ceil(data.total / pageSize));
  const exportCsv = () => {
    if (!data.items.length) { toast.error('Nothing to export'); return; }
    const head = 'Event ID,Timestamp,User,Sensitive data,Risk score,Risk level,Policy,Provider,Action';
    const rows = data.items.map(e => [e.id, e.timestamp, e.user, `"${e.data}"`, e.score, e.risk_level, `"${e.policy}"`, e.provider, e.action].join(','));
    const blob = new Blob([[head, ...rows].join('\n')], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'sentinelguard-audit.csv'; a.click();
    toast.success('Audit CSV exported');
  };
  return <div className="page"><SectionTitle eyebrow="Traceability" title="Audit logs" sub="A complete, immutable record of security decisions." action={<button className="secondary-btn" data-testid="export-audit-button" onClick={exportCsv}><ArrowUpRight size={15} /> Export CSV</button>} />
    <div className="toolbar"><label className="search"><Search size={16} /><input data-testid="audit-search-input" value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} placeholder="Search by event ID, user, or policy..." /></label>
      <div className="filter-btn" style={{ position: 'relative' }}><Filter size={15} /><select data-testid="audit-action-filter" value={action} onChange={e => { setAction(e.target.value); setPage(1); }} style={{ border: 'none', background: 'transparent', fontSize: 13, fontFamily: 'inherit', color: 'inherit', outline: 'none', cursor: 'pointer' }}><option value="ALL">All actions</option><option value="ALLOWED">Allowed</option><option value="MASKED">Masked</option><option value="BLOCKED">Blocked</option></select></div></div>
    <section className="panel full-table"><div className="panel-head"><div><h2>Decision history</h2><p>{data.total === 0 ? 'No events recorded' : `Showing ${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, data.total)} of ${data.total.toLocaleString()} events`}</p></div><span className="muted">{loading ? 'Loading...' : 'Up to date'}</span></div>
      <div className="table-wrap"><table data-testid="audit-logs-table"><thead><tr><th>Event ID</th><th>Timestamp</th><th>User</th><th>Sensitive data</th><th>Risk score</th><th>Policy applied</th><th>Action</th></tr></thead><tbody>
        {data.items.length === 0 && !loading && <EmptyRow colSpan={7} text="No audit records match this view." />}
        {data.items.map(e => <tr key={e.id} onClick={() => setOpen(e)} data-testid={`audit-row-${e.id}`} style={{ cursor: 'pointer' }}><td className="mono">{e.id}</td><td className="muted">{new Date(e.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</td><td>{e.user}</td><td>{e.data}</td><td><span className={`risk-score ${riskClass(e.score)}`}>{e.score}</span></td><td>{e.policy}</td><td><Badge action={e.action} /></td></tr>)}
      </tbody></table></div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, padding: '14px 4px 2px', alignItems: 'center' }}>
        <span className="muted" style={{ fontSize: 12.5 }}>Page {page} of {pages}</span>
        <button className="filter-btn" data-testid="audit-prev-page" disabled={page <= 1} onClick={() => setPage(p => p - 1)} style={page <= 1 ? { opacity: .45 } : undefined}><ChevronLeft size={14} /> Prev</button>
        <button className="filter-btn" data-testid="audit-next-page" disabled={page >= pages} onClick={() => setPage(p => p + 1)} style={page >= pages ? { opacity: .45 } : undefined}>Next <ChevronRight size={14} /></button>
      </div>
    </section>
    {open && <div className="modal-backdrop" onClick={() => setOpen(null)}><div className="modal" onClick={e => e.stopPropagation()} data-testid="audit-event-modal"><button className="modal-close" data-testid="close-audit-modal-button" onClick={() => setOpen(null)}><X size={17} /></button><p className="eyebrow">Event detail</p><h2>{open.id}</h2><Badge action={open.action} /><div className="detail-list"><span>Actor <b>{open.user}</b></span><span>Provider <b>{open.provider}</b></span><span>Model <b>{open.model || '—'}</b></span><span>Detected data <b>{open.data}</b></span><span>Risk <b>{open.risk_level} · {open.score}/100</b></span><span>Policy applied <b>{open.policy}</b></span><span>Latency <b>{open.latency_ms ?? '—'} ms</b></span><span>Timestamp <b>{new Date(open.timestamp).toLocaleString()}</b></span></div></div></div>}
  </div>;
}

function Settings() {
  const [settings, setSettings] = useState<any>(null);
  const [providers, setProviders] = useState<any[]>([]);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    api.getSettings().then(setSettings).catch((e: any) => toast.error(`Could not load settings: ${e.message}`));
    api.getDashboard().then(d => setProviders(d.providers)).catch(() => {});
  }, []);
  const save = async () => {
    if (!settings || saving) return;
    setSaving(true);
    try { setSettings(await api.updateSettings(settings)); toast.success('Settings saved'); }
    catch (e: any) { toast.error(e.message); } finally { setSaving(false); }
  };
  if (!settings) return <div className="page"><PageLoader label="Loading settings..." /></div>;
  const secToggles: [string, string, string][] = [['block_critical', 'Block critical requests', 'Prevent high-impact secrets from reaching providers'], ['scan_output', 'Scan model output', 'Inspect responses for accidental disclosure'], ['strict_policy', 'Strict policy enforcement', 'Block any sensitive request without an explicit matching policy']];
  const notifToggles: [string, string, string][] = [['notify_blocked', 'Blocked request alerts', 'Notify security admins immediately'], ['daily_digest', 'Daily security digest', 'A summary at 09:00 every morning']];
  const flip = (k: string) => setSettings((s: any) => ({ ...s, [k]: !s[k] }));
  return <div className="page"><SectionTitle eyebrow="Control plane" title="Settings" sub="Configure providers, security behavior, and workspace preferences." action={<button className="primary-btn" data-testid="save-settings-button" onClick={save} disabled={saving}><Check size={15} /> {saving ? 'Saving...' : 'Save changes'}</button>} />
    <div className="settings-grid">
      <section className="panel settings-section"><div className="setting-title"><Bot size={18} /><div><h2>AI provider configuration</h2><p>Connect the models your teams use</p></div></div>
        {providers.map(p => <div className="setting-row" key={p.name}><div className="provider-mini"><span className="provider-logo">{p.name === 'Local AI' ? <Code2 size={15} /> : <Bot size={15} />}</span><div><b>{p.name}</b><small>{p.kind}</small></div></div>{p.status === 'connected' ? <span className="connected"><span /> Connected</span> : <span className="disconnected">Not configured</span>}<button className="text-button" data-testid={`configure-${p.name.toLowerCase().replace(' ', '-')}-button`} onClick={() => toast.info(`${p.name} is managed via secure environment configuration`)}>Configure</button></div>)}
      </section>
      <section className="panel settings-section"><div className="setting-title"><ShieldCheck size={18} /><div><h2>Security behavior</h2><p>How SentinelGuard handles risk</p></div></div>
        {secToggles.map(([k, t, d], i) => <div className="setting-row" key={k}><div><b>{t}</b><small>{d}</small></div><button className={`toggle ${settings[k] ? 'on' : ''}`} data-testid={`security-toggle-${i}`} onClick={() => flip(k)}><span /></button></div>)}
        <div className="setting-row"><div><b>Theme</b><small>Choose your workspace appearance</small></div><select className="simple-select" data-testid="theme-select" value={settings.theme} onChange={e => setSettings((s: any) => ({ ...s, theme: e.target.value }))}><option>Light</option><option>Dark</option><option>System</option></select></div>
      </section>
      <section className="panel settings-section"><div className="setting-title"><Bell size={18} /><div><h2>Notifications</h2><p>Keep your team informed</p></div></div>
        {notifToggles.map(([k, t, d], i) => <div className="setting-row" key={k}><div><b>{t}</b><small>{d}</small></div><button className={`toggle ${settings[k] ? 'on' : ''}`} data-testid={`notification-toggle-${i}`} onClick={() => flip(k)}><span /></button></div>)}
      </section>
    </div></div>;
}

function SignIn() { const login = () => { const redirectUrl = window.location.origin + '/'; // REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
  window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`; }; return <main className="auth-page"><div className="auth-art"><div className="auth-grid" /><div className="auth-brand"><span className="brand-mark"><ShieldCheck size={19} /></span><span>SENTINEL<span>GUARD</span></span></div><div className="auth-quote"><span className="eyebrow">AI runtime security</span><h1>Trust every<br /><em>inference.</em></h1><p>Govern sensitive data at the speed of AI, before it ever leaves your environment.</p><div className="auth-signal"><ShieldCheck size={15} /><span>Gateway policy engine <b>● Active</b></span></div></div></div><div className="auth-card-wrap"><div className="auth-card"><span className="auth-icon"><ShieldCheck size={22} /></span><p className="eyebrow">Secure workspace</p><h2>Welcome to SentinelGuard</h2><p className="auth-sub">Sign in to access your security control plane.</p><button className="google-btn" data-testid="google-sign-in-button" onClick={login}><span className="google-g">G</span> Continue with Google</button><p className="auth-note"><KeyRound size={12} /> Protected by Emergent managed authentication</p></div><span className="auth-footer">SentinelGuard · AI Runtime Security & Governance Gateway</span></div></main>; }
function AuthCallback() { const navigate = useNavigate(); const processed = useRef(false); const [error, setError] = useState(''); useEffect(() => { if (processed.current) return; processed.current = true; const sessionId = new URLSearchParams(window.location.hash.replace(/^#/, '')).get('session_id'); if (!sessionId) { navigate('/login', { replace: true }); return; } fetch(`${API_ROOT}/auth/session`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ session_id: sessionId }) }).then(r => { if (!r.ok) throw new Error('Sign-in could not be completed'); return r.json(); }).then(() => { window.history.replaceState(null, '', window.location.pathname); navigate('/', { replace: true }); }).catch(() => setError('We could not complete Google sign-in. Please try again.')); }, [navigate]); return <div className="auth-loading" data-testid="auth-callback-state"><div className="scan-spinner" /><p>{error || 'Securing your workspace...'}</p>{error && <button className="primary-btn" data-testid="auth-callback-retry-button" onClick={() => navigate('/login')}>Return to sign in</button>}</div>; }
function ProtectedWorkspace() { const [status, setStatus] = useState<'checking' | 'authenticated' | 'unauthenticated'>('checking'); const [user, setUser] = useState<AuthUser | null>(null); const navigate = useNavigate(); useEffect(() => { fetch(`${API_ROOT}/auth/me`, { credentials: 'include' }).then(r => { if (!r.ok) throw new Error('unauthenticated'); return r.json(); }).then(data => { setUser(data); setStatus('authenticated'); }).catch(() => { setStatus('unauthenticated'); navigate('/login', { replace: true }); }); }, [navigate]); if (status === 'checking') return <div className="auth-loading" data-testid="auth-checking-state"><div className="scan-spinner" /><p>Checking secure session...</p></div>; return status === 'authenticated' ? <Shell user={user!} /> : null; }
function Shell({ user }: { user: AuthUser }) { const [mobile, setMobile] = useState(false); const location = useLocation(); const title = nav.find(n => n.to === location.pathname)?.label || 'Overview'; const logout = async () => { await fetch(`${API_ROOT}/auth/logout`, { method: 'POST', credentials: 'include' }); window.location.href = '/login'; }; return <div className="app-shell"><aside className={`sidebar ${mobile ? 'mobile-open' : ''}`}><div className="brand"><span className="brand-mark"><ShieldCheck size={19} /></span><span>SENTINEL<span>GUARD</span></span><button className="mobile-close" data-testid="close-mobile-nav-button" onClick={() => setMobile(false)}><X size={17} /></button></div><div className="workspace"><span className="workspace-avatar">{user.name.slice(0, 2).toUpperCase()}</span><div><b>Acme Corporation</b><small>Security workspace</small></div><ChevronDown size={14} /></div><nav data-testid="main-navigation">{nav.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} data-testid={`nav-${label.toLowerCase().replaceAll(' ', '-')}`} onClick={() => setMobile(false)}><Icon size={17} /><span>{label}</span></NavLink>)}</nav><div className="sidebar-bottom"><div className="help"><CircleHelp size={16} /><span><b>Need help?</b><small>Read the docs</small></span><ArrowUpRight size={14} /></div><button className="user-card" data-testid="logout-button" onClick={logout}><span className="user-avatar">{user.name.slice(0, 2).toUpperCase()}</span><div><b>{user.name}</b><small>{user.email}</small></div><MoreHorizontal size={17} /></button></div></aside><main className="main"><header className="topbar"><button className="mobile-menu" data-testid="open-mobile-nav-button" onClick={() => setMobile(true)}><Menu size={20} /></button><div className="breadcrumbs"><span>Workspace</span><span>/</span><b>{title}</b></div><div className="top-actions"><button className="top-search" data-testid="global-search-button"><Search size={16} /><span>Search</span><kbd>⌘ K</kbd></button><button className="top-icon" data-testid="notifications-button" aria-label="Notifications"><Bell size={18} /><i /></button><div className="system"><span /><b>Systems operational</b></div><span className="top-avatar">{user.name.slice(0, 2).toUpperCase()}</span></div></header><Routes><Route path="/" element={<Dashboard />} /><Route path="/console" element={<Console />} /><Route path="/events" element={<Events />} /><Route path="/policies" element={<Policies />} /><Route path="/audit" element={<Audit />} /><Route path="/settings" element={<Settings />} /><Route path="*" element={<Navigate to="/" replace />} /></Routes></main></div>; }
function AppRouter() { const location = useLocation(); if (location.hash?.includes('session_id=')) return <AuthCallback />; return <Routes><Route path="/login" element={<SignIn />} /><Route path="*" element={<ProtectedWorkspace />} /></Routes>; }
export default function App() { return <BrowserRouter><Toaster position="top-right" richColors /><AppRouter /></BrowserRouter>; }
