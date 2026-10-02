# Google Health API token tool

Web application that runs the Google OAuth flow and hands you an access token for the
[Google Health API](https://developers.google.com/health) (`https://health.googleapis.com/v4`).
Supports **Vercel** serverless deployments (stateless via HTTP-only cookies) or **local** development (Node 18+).

---

## 🚀 Deploying to Vercel

### 1. Google Cloud Console Setup
1. In [Google Cloud Console](https://console.cloud.google.com), pick your project and enable **Google Health API**.
2. **APIs & Services > Credentials > Create credentials > OAuth client ID > Web application**.
3. Under **Authorized redirect URIs**, add your Vercel deployment URL callback:
   * `https://<your-vercel-domain>.vercel.app/callback`
4. Under **APIs & Services > OAuth consent screen**: add your Google account under **Test users** (if in Testing mode).

### 2. Set Environment Variables on Vercel
In your Vercel project settings (**Settings > Environment Variables**), add:
* `GOOGLE_CLIENT_ID` - Your Google OAuth Client ID
* `GOOGLE_CLIENT_SECRET` - Your Google OAuth Client Secret
* `UPSTASH_REDIS_REST_URL` *(optional)* - Upstash Redis REST URL for persisting OAuth tokens across serverless instances
* `UPSTASH_REDIS_REST_TOKEN` *(optional)* - Upstash Redis REST Token
* `GOOGLE_SCOPE` *(optional)* - Default: `https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly`

---

## 💻 Local Setup

1. Under **Authorized redirect URIs** in GCP, add: `http://localhost:8080/callback`
2. `cp .env.example .env` and fill in `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and optionally `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`.
3. Start the server:
   ```bash
   node server.js
   ```
4. Open [http://localhost:8080](http://localhost:8080) and click **Sign in with Google**.

---

## 🔒 Token Storage

* **Upstash Redis**: When `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` are set, OAuth tokens (both default tokens and clientKey-linked tokens) are persisted in Upstash Redis (`oauth:default_tokens` and `oauth:client:<clientKey>`).
* **On Vercel**: Tokens are stored securely in `HttpOnly` cookies (`google_health_tokens`) and Upstash Redis if configured.
* **Locally**: Tokens are stored in `HttpOnly` cookies, Upstash Redis (if configured), and saved locally to `tokens.json`.
* Tokens auto-refresh when expired.
