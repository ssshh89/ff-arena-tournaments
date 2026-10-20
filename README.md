# FF Arena — Free Fire Tournament Platform

A responsive web app for Free Fire tournament registration, player accounts, squads, tournament schedules, admin management, room details, match results and leaderboards. Uses Express + PostgreSQL.

## Features
- Player registration/sign-in (bcrypt password hashes; JWT sessions)
- Tournament list, mode filters, slots and schedule
- Solo registrations and Duo/Squad registration with registered teammates
- Squad creation and captain-only teammate invitations by Free Fire UID
- Admin sign-in, tournament creation/status updates, room details, registration list and results entry
- Global and per-tournament leaderboards
- PostgreSQL schema initialized automatically at startup
- Helmet security headers and API rate limiting

## Local run
1. Install Node.js 20+ and PostgreSQL.
2. Create a database and copy `.env.example` to `.env`.
3. Set `DATABASE_URL`, a random `JWT_SECRET` (32+ characters), `ADMIN_EMAIL`, and `ADMIN_PASSWORD` (12+ characters). Set `PGSSL=false` for local PostgreSQL.
4. Run `npm install` then `npm start`.
5. Open `http://localhost:3000`.

Do not commit `.env` or share production secrets. For production use a strong unique admin password and secret. This MVP does not process payments. `entry_fee_paise` is metadata only; do not advertise paid entries as operational until a compliant payment provider and refund/dispute process are implemented. Room details are exposed only to registered entrants when the tournament is live or completed; admins should publish them only at the appropriate time.

## Deploy on Render
`render.yaml` defines a Node web service and a PostgreSQL database in Singapore. Push this folder to a Git repository, then use Render Blueprint deployment. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` as secret environment values in Render. Check Render's current plan availability and pricing before applying the Blueprint; free database plans and regions can change.

## API overview
- `POST /api/register`, `POST /api/login`, `POST /api/admin/login`
- `GET /api/tournaments`, `POST /api/tournaments` (admin)
- `POST /api/teams`, `GET /api/teams/mine`, `POST /api/teams/:id/members`
- `POST /api/tournaments/:id/join`, `GET /api/registrations/mine`
- `PATCH /api/tournaments/:id` (admin), `POST /api/admin/results` (admin)
- `GET /api/leaderboard`, `GET /api/tournaments/:id/leaderboard`

## Important limitations
- No email verification, password reset, moderation console, automated room assignment, or payment integration yet.
- Team membership uses a single registered player UID lookup; captains must ensure their team has the required member count.
- Admin identity is configured through environment variables rather than an admin user table.
- The UI is a first production-oriented MVP; test on a staging database before public tournament use.
