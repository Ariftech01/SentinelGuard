# SentinelGuard PRD

## Original problem statement
Build SENTINELGUARD, a premium enterprise AI Runtime Security & Governance Gateway: Dashboard, AI Security Console, Live Security Events, Policy Management, Audit Logs, and Settings. Frontend first (React, Tailwind-style custom CSS, Lucide, Recharts, responsive, mock data), then a production backend with a security pipeline (PII/secrets detection → masking → risk scoring → policy decision ALLOW/MASK/BLOCK), provider connectors, and full frontend wiring.

## Final architecture decisions (user-approved)
- **MongoDB for everything** (PostgreSQL dropped — not available/deployable on Emergent). Collections: `users`, `user_sessions`, `policies`, `security_events`, `chat_messages`, `gateway_settings`, `status_checks`.
- **Auth**: Emergent-managed Google sign-in only (JWT email/password auth dropped). Sessions in Mongo, httpOnly cookie, `/api/auth/session|me|logout`.
- **AI providers**: Emergent Universal LLM Key via `emergentintegrations` — Gemini (`gemini-3-flash-preview`), OpenAI (`gpt-5.4`), Claude (`claude-sonnet-4-6`). Local AI = OpenAI-compatible endpoint via `LOCAL_AI_BASE_URL` (not configured → clear error).
- Frontend: single-file `App.tsx` (CRA/CRACO, TS), API client in `src/services/api.ts`, types in `src/types/index.ts`. Imports of local .ts modules need explicit `.ts` extension.

## Backend API (all /api prefixed)
- `POST /api/v1/secure/chat` {message, provider, session_id} → detection/masking (email, phone, credit card, Aadhaar, PAN, password, API key, JWT, secret), risk score 0-100 + level, policy evaluation (Mongo policies + Critical guard + strict mode), decision; MASK/ALLOW → real LLM call with multi-turn context from `chat_messages`; output scanning/redaction; event persisted WITHOUT raw PII.
- `GET /api/v1/dashboard/stats` — 24h totals + change vs prior 24h, 8-point trend, risk distribution, recent events, provider health.
- `GET /api/v1/events?search&limit`, `GET/POST/PUT/DELETE /api/v1/policies`, `GET /api/v1/audit-logs?search&action&page&page_size`, `GET/PUT /api/v1/settings`.
- 4 default policies seeded on startup when collection empty (PII standard protection, PCI data block, Secrets critical block, Identity document masking).

## What's been implemented
### 2026-02-22
- Full six-page frontend (initially mock data) + Google managed sign-in gate.
### 2026-08-29 — Backend + full wiring (this session)
- Built `/app/backend/security.py` (detectors/masking/risk/policy engine) and rewrote `server.py` with all endpoints above; async httpx for auth exchange.
- Wired ALL frontend pages to real APIs: live dashboard (auto-refresh 20s), console with real streaming-free AI responses + live analysis panel (detected items, original→masked transform, policy, latency), events (poll 15s, search), policy builder with name/type/risk/action + toggle/delete persistence, audit logs with server-side search/action filter/pagination/CSV export/detail modal, settings persistence, sonner toasts, loading/empty states.
- QA session seeded for testing (see /app/memory/test_credentials.md).
- **Testing**: iteration_4 — 19/19 backend pytest passed, 100% frontend flows passed (testing agent). Regression suite: `/app/backend/tests/test_sentinelguard_backend.py`.

### 2026-08-29 — Per-provider model picker
- `GET /api/v1/models` catalog; `model` field on secure/chat (validated per provider, 400 on unknown).
- Models: OpenAI (gpt-5.4 default, gpt-5.4-mini, gpt-5.2, gpt-4.1, gpt-4o, gpt-4o-mini), Claude (claude-sonnet-4-6 default, claude-opus-4-6, claude-haiku-4-5-20251001), Gemini (gemini-3-flash-preview default, gemini-3.1-pro-preview, gemini-2.5-pro, gemini-2.5-flash).
- BYOK: if `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/`GEMINI_API_KEY` set in backend/.env, that provider uses the user's own key instead of the Emergent Universal Key (`key_source` in /v1/models). User was asked for their OpenAI key but has not provided one yet.
- Console UI: model select next to provider select, model shown in analysis pipeline + audit modal; events store `model`.
- Self-tested: curl (haiku, gpt-5.4-mini, invalid model 400) + Playwright E2E (Claude Haiku real response).

### 2026-08-29 — Live event stream + model analytics
- SSE endpoint `GET /api/v1/events/stream` (in-process pub/sub, keepalive pings, X-Accel-Buffering off); secure/chat publishes each new event.
- Dashboard subscribes via EventSource → silently reloads stats on every new event (verified: metric updated without refresh). Live Events page prepends streamed events instantly (polling reduced to 60s reconciliation).
- `GET /api/v1/analytics/models`: last-7-days per-model requests/blocked/avg risk/avg latency/est tokens/est cost (MODEL_PRICES table, tokens_est = chars/4 stored per event going forward). New "Model usage analytics" panel on dashboard with usage bars.
- Self-tested: SSE via external URL curl + Playwright live-update proof + analytics rows rendered.
- NOTE: dashboard/events pages hold an open SSE connection — `networkidle` waits will time out in automation; use `domcontentloaded`.

## Prioritized backlog
- **P1**: Real Google OAuth E2E verification (needs a real Google identity — user to verify by signing in).
- **P1**: Real-time event streaming (WebSocket/SSE) instead of polling.
- **P2**: Streaming AI responses (SSE token-by-token) in console.
- **P2**: Role-based access (admin vs analyst), policy edit-in-place, dark theme actually applied, CSV export of full audit history (server-side), email alerts for blocked requests (needs Resend/SendGrid).
- **P2**: Tighten CORS for production; provider keys per-workspace config UI.

## Known notes
- Events risk colors: Low<25, Medium<50, High<80, Critical>=80.
- Policies collection re-seeds only when empty + backend restart.
- LLM calls take 3-15s; console send button disabled while scanning.
