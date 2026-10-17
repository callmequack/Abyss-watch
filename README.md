# Abyss Watch — Aion 2

Community danger-map tool. Visitors can mark the map and export a PNG. Publishing uses a private publishing code and sends reports to the configured webhook. There is no Discord login, OAuth, or role-based access. Live Sessions use owner, viewer, and shotcaller invitation codes.

## Website deployment (GitHub Pages)

The GitHub Actions workflow in `.github/workflows/pages.yml` publishes the root `index.html`.

Expected site URL: https://callmequack.github.io/Abyss-watch/

## Cloudflare Worker deployment

The backend source is in `worker/src/index.js`.

1. From the `worker` directory, copy `wrangler.toml.example` to `wrangler.toml`.
2. Deploy from that directory with `npx wrangler deploy`.
3. Set these Worker secrets in Cloudflare (or with Wrangler); never commit secret values:
   - `PUBLISH_CODE` — private code used to publish reports.
   - `DISCORD_WEBHOOK_URL` — webhook destination for reports. This is the only Discord-related integration retained, strictly as a report delivery destination.
4. `SESSION_SECRET` is no longer used by the code-based live Sessions system and does not need to be configured.
5. Ensure the Worker has a Durable Object binding named `LIVE_SESSIONS` targeting class `LiveSession`, with the SQLite migration shown in `wrangler.toml.example`.
6. Verify `https://abyss-watch-api.callmequackttv.workers.dev/health`, then test publishing and creating a private/public live session.

## Worker configuration

- `ALLOWED_ORIGIN`: `https://callmequack.github.io`
- `LIVE_SESSIONS`: required Durable Object binding for live sessions.
- `PUBLISH_CODE`: private publishing credential, configured as a secret.
- `DISCORD_WEBHOOK_URL`: webhook used only to deliver published reports.

## Private live sessions

The separate route is `/Abyss-watch/Sessions/`. Private sessions create owner, viewer, and shotcaller codes. Viewer codes are read-only; shotcaller codes can edit; the owner can manage participants and rotate invitation codes. Public sessions allow anyone with the link to view and edit. No login or third-party account is required.

## Important notes

- The published map begins with an illustrative placeholder unless the real map asset is supplied.
- GitHub Pages is static hosting; never put the publishing code or webhook URL in frontend files.
- Deploy the Worker from the `worker` directory, not the repository root as a static assets site.
