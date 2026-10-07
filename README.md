# My Cloud Office (full-stack)

Quotations, invoices, clients, multiple companies, dashboard, templates, footer and signature, with a real server-side login and a Postgres database.

- **Backend:** Node.js + Express + Postgres (`pg`). Passwords hashed with scrypt, sessions in HttpOnly cookies.
- **Frontend:** `public/index.html` (the app) and `public/login.html` (sign-in page). No build step.
- **Data:** stored in Postgres, so it works on Vercel and any other host.

## Environment variables
| Name | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string (`POSTGRES_URL` also works) |
| `ALLOW_SIGNUP` | no | `true` lets more people create their own accounts (each gets separate data). The first account is always allowed. |
| `NODE_ENV` | no | `production` on hosts (Vercel sets it) so cookies are HTTPS-only |

## Deploy on Vercel
1. Import this GitHub repo into Vercel.
2. In the project, open **Storage**, create a **Postgres** database (Neon) and connect it to the project. This adds `DATABASE_URL` automatically. If it adds a different variable name, add `DATABASE_URL` yourself in **Settings → Environment Variables**.
3. Redeploy. Open the site and create your owner account. The tables are created automatically.

## Run on your computer
```
npm install
DATABASE_URL=postgres://user:pass@localhost:5432/office npm start    # http://localhost:3000
```

## Other hosts
Any host that runs Node or Docker works (Render, Railway, Fly.io, a VPS). Set `DATABASE_URL` to any Postgres database. A `Dockerfile` is included.

## Moving data from the preview version
In the preview app open Settings, then **Backup / import**, and copy the text. In this app open Settings, then **Backup / import**, paste it and press Import.

## Notes
- Each account has its own companies and documents. Two people cannot yet work in the same company at once.
- Saving uses a version check: if the same account is edited on two devices, the older one is asked to reload instead of overwriting.
- Requests are limited to about 4 MB on Vercel, so keep logos and signatures small (the app shrinks them automatically).
