# SOSKS5 Backend Deployment & Security

## Before deployment
The container is built from the repository root and runs the FastAPI app from main.py on port 8080. Configure environment variables in the hosting platform; do not put real secrets in Git or in the static HTML.

Copy the names from .env.example into the deployment environment and replace every placeholder. If NODE_API_TOKEN is not configured, /api/create intentionally fails closed. ADMIN_AUTH_VERIFY_URL must point to a real endpoint that validates the supplied Bearer token and admin permission; a public health endpoint is not suitable.

## OSS / Cloudflare flow
1. Create a dedicated bucket in Alibaba OSS or another S3-compatible service. Create a dedicated access key with the minimum object read/write permissions required.
2. Configure S3_ENDPOINT_URL, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY in the container runtime.
3. Bind the public media hostname to the bucket/custom-domain origin and set MEDIA_PUBLIC_BASE_URL to the HTTPS hostname. Public read access should apply only to intended image objects, not credentials or administrative JSON.
4. Route /api/v1/admin/media/upload, /api/v1/admin/home-banners, /api/v1/public/home-banners, and /api/v1/user/orders to this FastAPI service. The static admin currently uses https://api.lynli.me/api/v1/admin by default; if this service uses a different hostname, set window.SOSKS5_MEDIA_API_BASE before the admin module runs to the full admin API base ending in /api/v1/admin.
5. Set ADMIN_AUTH_VERIFY_URL to an authenticated admin-only endpoint on your existing identity/API service. Set USER_API_BASE to the upstream user API base; the order proxy forwards the user Bearer token and does not accept a user_id parameter. Verify a valid admin token succeeds and a normal user token fails.
6. Upload a test image, verify the returned HTTPS URL opens through Cloudflare, publish a banner, then check the public JSON endpoint and homepage from a separate browser/device.

The backend re-encodes accepted JPEG/PNG/WebP/GIF input as WebP, limits input to 8 MB and 24 million pixels, assigns random object keys, and never returns storage credentials. Banner JSON is written to the configured object store key and served through the public API endpoint, not as a public JSON object.

## Security checks
- Restrict origin access to Cloudflare IP ranges where applicable; do not expose SSH, database, or container admin ports publicly.
- Enable HTTPS, WAF managed rules, bot controls, and rate limits for login, registration, checkout, and upload endpoints. Test challenges against legitimate payment callbacks and API clients before enforcing them.
- Browser JavaScript and robots.txt cannot prevent scraping. Enforce rate limits, authorization, pagination, and field minimization on the server.
- Never trust client-provided prices, order ownership, user IDs, or delivery status. Derive identity from the verified token and recalculate checkout totals on the server.
- Never serve order card keys, subscription URLs, API keys, or private order JSON through a public CDN hostname.
- Keep object storage access keys server-side and rotate them immediately if exposed.
- Monitor API errors and storage usage; set object-storage lifecycle/size budgets and alert on unusual upload bursts.

## Important deployment note
Committing code does not configure the hosting platform, bucket permissions, Cloudflare DNS, reverse-proxy routes, or runtime secrets. The OSS/admin APIs remain disabled until the required environment variables and reverse proxy routes are configured and verified. The order proxy returns an error unless an upstream order-list route is actually available; it never fabricates orders.
