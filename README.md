# Rawdat ul-Huda API

Standalone Express API for public site content and owner-only content management. Supabase credentials belong in this service, never in the frontend.

## Setup

1. Create a Supabase project and run `../supabase/migrations/20261012000000_owner_cms.sql`.
2. Copy `.env.example` to `.env` and set the project URL, anon key, service-role key, and a random session secret of at least 32 characters.
3. Add the owner's Supabase user ID to `public.site_admins` after creating that user in Supabase Auth.
4. Run `npm install` and `npm run dev` from this directory.

The API listens on port 4000 by default. Configure `BACKEND_API_URL=http://localhost:4000` in the frontend environment. The service-role key must only be configured here.

## Routes

- `GET /api/site/content/:locale` and `GET /api/site/settings` are public.
- `POST /api/admin/auth/login` exchanges owner credentials for a short-lived API token.
- `GET /api/admin/me`, `GET /api/admin/content/:locale`, and the protected `PUT` routes require `Authorization: Bearer <token>`.
- `PUT /api/admin/content/:locale` accepts `{ "section": "pricing", "content": {} }`.
- `PUT /api/admin/settings` accepts the editable public site settings.