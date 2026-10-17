# Abyss Watch — Aion 2

Community danger-map tool. Visitors can mark the map and export a PNG. Discord publishing is designed to require a verified `Police Patrol` role in the configured Discord server.

## Website deployment (GitHub Pages)

A GitHub Actions workflow is included at `.github/workflows/pages.yml`. In the repository, open **Settings → Pages** and set the build/deployment source to **GitHub Actions**. The workflow will publish the root `index.html` after it runs successfully.

Expected site URL: https://callmequack.github.io/Abyss-watch/

## Secure Discord backend (Cloudflare Worker)

The backend source is in `worker/src/index.js`. It never puts the Discord client secret or webhook URL in browser JavaScript or repository files.

1. Create a Cloudflare account and install Wrangler locally.
2. From the `worker` directory, copy `wrangler.toml.example` to `wrangler.toml`.
3. Replace `REPLACE-WITH-YOUR-WORKER` with the Worker hostname you deploy. Use the exact same callback URL in the Discord Developer Portal OAuth2 redirect list.
4. Set the production GitHub Pages origin in `ALLOWED_ORIGIN`. If you later use a custom domain, update it to that exact origin.
5. Set secrets with Wrangler (never commit these values):
   - `npx wrangler secret put DISCORD_CLIENT_SECRET`
   - `npx wrangler secret put DISCORD_WEBHOOK_URL`
   - `npx wrangler secret put SESSION_SECRET` (use a long random value)
6. Deploy from the `worker` directory with `npx wrangler deploy`.
7. In the Discord Developer Portal, add the exact Worker callback URL as an OAuth2 redirect URI. OAuth scopes required: `identify` and `guilds.members.read`.
8. Verify the Worker `/health` route, then test `/login`, `/me`, and publishing with a test channel before announcing it.

Configured Discord IDs:
- Application client ID: `490974727767326720`
- Server ID: `1558145560148443168`
- Publishing role: `1560442485879083108` (Police Patrol)
- Destination channel: `1560635671436337152`

## Important current limitations

- The published map begins with an illustrative placeholder. Upload the actual Aion 2 Abyss map image to mark the real map.
- The Worker source enforces the role on the server for every publish request, but the frontend still needs the deployed Worker URL configured and its sign-in/publish controls wired to the API before end-to-end Discord posting is live.
- GitHub Pages is static hosting; it cannot keep Discord secrets private. Do not add webhook URLs, client secrets, or session secrets to GitHub files or public JavaScript.
- The Discord webhook destination must be managed by someone with permission in the target server/channel.


## Private live sessions

The separate GitHub Pages route is `/Abyss-watch/Sessions/`. It creates an unguessable invite URL; anyone holding that URL can view the room, while edits are enforced by the Worker and require the Discord **Shotcaller** role ID `1558500349835354242`. Session state is stored in a Cloudflare Durable Object and polled by viewers for live updates. The main `index.html` map and Police Patrol publishing permission are separate.

To enable sessions on an existing Worker deployment:

1. Copy the `[[durable_objects.bindings]]` and `[[migrations]]` entries from `worker/wrangler.toml.example` into your actual `worker/wrangler.toml` (keep your existing production vars and secrets).
2. Deploy the updated Worker from the `worker` directory with `npx wrangler deploy`.
3. Wait for the GitHub Pages workflow to finish deploying the new `Sessions/index.html` page.
4. Test Discord login, create a session, open the invite link in a second browser, and confirm that a non-Shotcaller can view but cannot edit.

The Worker must be redeployed for the new session endpoints and Durable Object to become available. The public page alone cannot enforce permissions securely.
