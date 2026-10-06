# My Cloud Office (full-stack)

Quotations, invoices, clients, multiple companies, dashboard, templates, footer and signature, with a real server-side login and database.

- **Backend:** Node.js + Express + SQLite (`better-sqlite3`). Passwords hashed with scrypt, sessions in HttpOnly cookies, login rate-limited.
- **Frontend:** `public/index.html` (the app) and `public/login.html` (sign-in page). No build step.
- **Data:** one SQLite file, `DATA_DIR/office.db`. Back it up by copying that file.

## Run it on your computer
```
npm install
npm start          # http://localhost:3000
```
The first person to open the site creates the owner account. After that, sign-ups are closed unless you set `ALLOW_SIGNUP=true`.

## Environment variables
| Name | Default | Purpose |
|---|---|---|
| `PORT` | 3000 | Port to listen on |
| `DATA_DIR` | `./data` | Where `office.db` is stored (must be persistent) |
| `NODE_ENV` | none | Set to `production` online so cookies are HTTPS-only |
| `ALLOW_SIGNUP` | false | Allow more people to create their own accounts (each gets separate data) |

## Hosting it online
You need a host that runs Node or Docker and keeps a **persistent disk** (SQLite lives on disk). With the included `Dockerfile`:
1. Push this folder to a GitHub repository.
2. Create a new web service from that repo on your host (Render, Railway, Fly.io, a VPS, etc.) using the Dockerfile.
3. Attach a persistent volume/disk mounted at `/data`.
4. Set `NODE_ENV=production`. Open the URL the host gives you and create your account.
5. Optionally point your own domain at it.

On a plain VPS: `docker build -t office . && docker run -d -p 80:3000 -v office-data:/data --restart unless-stopped office` (put a reverse proxy such as Caddy in front for HTTPS).

## Moving data from the preview version
In the preview app open Settings, then **Backup / import**, and copy the text. In this app open Settings, then **Backup / import**, paste it and press Import.

## Notes
- Each account has its own companies and documents. Two people cannot yet work in the same company at once.
- Saving uses a version check: if the same account is edited on two devices, the older one is asked to reload instead of overwriting.
