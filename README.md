# Strava token tool

Web application that executes the Strava OAuth authorization flow and hands you your access and refresh tokens. Works seamlessly on **Vercel** (stateless via HTTP-only cookies) or **locally** (Node 18+).

---

## 🚀 Deploying to Vercel

### 1. Configure Strava Application Callback Domain
1. Go to [Strava API Settings](https://www.strava.com/settings/api).
2. Set **Authorization Callback Domain** to your Vercel deployment domain (e.g. `your-app.vercel.app`).
   * *Note: Do not include `https://` or trailing slashes.*

### 2. Set Environment Variables on Vercel
In your Vercel project settings (**Settings > Environment Variables**), add:
* `STRAVA_CLIENT_ID` - Your Strava Client ID
* `STRAVA_CLIENT_SECRET` - Your Strava Client Secret
* `STRAVA_SCOPE` *(optional)* - Default: `read,activity:read_all,profile:read_all`

### 3. Deploy
Deploy using the Vercel CLI or connect your GitHub repository:
```bash
vercel
```

---

## 💻 Local Development

1. Create an API app at [Strava API Settings](https://www.strava.com/settings/api).
   Set **Authorization Callback Domain** to `localhost`.
2. Copy `.env.example` to `.env` and fill in your client ID and secret.
3. Start the server:
   ```bash
   node server.js
   ```
4. Open [http://localhost:8080](http://localhost:8080) and click **Connect with Strava**.

---

## 🔒 Token Storage

* **On Vercel**: Tokens are stored securely in stateless, `HttpOnly` cookies (`strava_tokens`), requiring no database or file system writes.
* **Locally**: Tokens are stored in `HttpOnly` cookies and also saved locally to `tokens.json`.
* Access tokens last 6 hours; reloading the page auto-refreshes the access token using the refresh token seamlessly.
