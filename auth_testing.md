# Emergent Managed Google Auth Testing Playbook

1. Create a test user and `user_sessions` record in the configured MongoDB database using a custom `user_id` and a session token expiring in seven days.
2. Verify `GET /api/auth/me` with an Authorization Bearer session token returns the user without MongoDB `_id`.
3. Set a `session_token` cookie in a browser and verify the app opens the protected dashboard.
4. Verify an unauthenticated browser is redirected to `/login`.
5. Verify the OAuth callback reads `session_id` from the URL fragment, exchanges it through the backend, and redirects to `/`.
6. Verify logout clears the backend session and returns to `/login`.
7. Never store Google passwords; record only allowed test identities and roles in `/app/memory/test_credentials.md`.

## JWT authentication

- Register with `POST /api/auth/register` and login with `POST /api/auth/login`.
- Verify the returned bearer token with `GET /api/auth/me`.
- Development admin: `sentinel.admin@local.dev` / `SentinelGuard!2026` (ADMIN).
- Verify role restrictions on policy creation and deletion.