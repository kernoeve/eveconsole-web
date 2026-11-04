# EVE Console services

The calls the EVE Console app makes on eveconsole.com: signing in with an EVE character, and hosting images so a Slack incoming webhook can show them. A webhook can only show an image at a public URL, and it cannot carry a file.

There is no website here and no upload page. It is a Cloudflare Worker with D1 for the records and R2 for the images, deployed apart from the homepage in the folder above.

| Address | What it does |
|---|---|
| `api.eveconsole.com` | The calls below |
| `img.eveconsole.com` | Serves stored images and nothing else |

## Signing in

Signing in is optional in the app, and the services are unavailable until it is done. It belongs to the app's database, not to one machine: every client on that database shares one character and one key.

1. The app runs the EVE sign-in itself, with PKCE, using an EVE application that has no scopes.
2. It sends the access token to `POST /v1/auth/eve`. The token is checked against EVE's published keys and thrown away. A token issued to another application, or one carrying scopes, is refused.
3. The answer holds a key. It stands for that character until signed out, and only its hash is stored here.

Every other call sends `Authorization: Bearer <key>`.

## Calls

| Call | What it does |
|---|---|
| `POST /v1/auth/eve` `{"accessToken": "…"}` | Signs in. Answers `key`, `character`, `limits`, `usage` |
| `POST /v1/auth/sign-out` | Ends this key. The character's images stay |
| `GET /v1/me` | `character`, `limits`, `usage` |
| `POST /v1/images?expiresInDays=30` | Uploads the request body. Answers `201` with the image's fields below and `usage` |
| `GET /v1/images?limit=100&cursor=…` | This character's active images, newest first, with `nextCursor`, `limits`, `usage` |
| `POST /v1/images/delete` `{"ids": ["…"]}` | Deletes up to 90 of this character's images. Answers `deleted`, `notFound`, `usage` |

An image's fields are `id`, `url`, `type`, `size`, `width`, `height`, `createdAt` and `expiresAt`.

`usage` is `storedBytes`, `activeImages` and `uploadsToday`. `limits` is `maxImageBytes`, `maxStoredBytes`, `maxUploadsPerDay` and `maxExpiresInDays`.

A refusal answers `{"error": "<code>", "message": "…"}`:

| Status | Code | Meaning |
|---|---|---|
| 400 | `bad_request`, `bad_expiry`, `token_has_scopes` | The request is wrong |
| 401 | `not_signed_in`, `invalid_token` | Sign in, or sign in again |
| 403 | `banned` | This character may not use the service |
| 409 | `storage_limit` | Delete some images first. Carries `limits` and `usage` |
| 413 | `image_too_large` | Over the size limit |
| 415 | `not_an_image` | Not a real PNG or JPEG |
| 429 | `daily_limit` | Over the day's uploads, with `Retry-After`. Deleting does not give uploads back |
| 502 | `eve_unavailable` | EVE's keys could not be read. Try again |

## Limits

Per character, set in `wrangler.jsonc`:

- 5 MB an image
- 100 MB held at once
- 50 uploads a UTC day
- 365 days at most before an image expires, which is also the default

Any EVE character may sign in, and characters are free to create, so signing in gives tracking rather than a gate. The limits and bans do that job.

## Images

- **PNG and JPEG only,** judged from the bytes. The stored type comes from there, never from the request, and images are served with `nosniff` and a sandbox policy so a browser treats them only as pictures. A Worker cannot decode an image, so this checks the file's structure rather than its pixels.
- **URLs are public** to anyone who has one. The address holds 128 random bits, so it cannot be guessed.
- **Expiry:** an image stops being served the moment it expires, and a daily job deletes it. Expired images do not count against the limit.

## Takedowns and bans

These need `Authorization: Bearer <ADMIN_TOKEN>`. Without it they answer as if they did not exist.

| Call | What it does |
|---|---|
| `GET /v1/admin/images/{id}` | Who uploaded it, and when |
| `POST /v1/admin/images/{id}/take-down` | Removes it |
| `POST /v1/admin/characters/{id}/ban` `{"reason": "…"}` | Ends their keys, removes all their images, refuses new sign-ins |
| `POST /v1/admin/characters/{id}/unban` | Lifts the ban |

## Setting it up

Run these from this folder. ⚠️ The config has to stay `wrangler.jsonc`; the note at the top of it says why.

1. Register an EVE application at [developers.eveonline.com](https://developers.eveonline.com/applications) with no scopes. Put its Client ID in `EVE_CLIENT_ID`.
2. `npx wrangler d1 create eveconsole-services`, and put the id in `database_id`.
3. `npx wrangler r2 bucket create eveconsole-images`
4. `npx wrangler r2 bucket lifecycle add eveconsole-images expire-all --expire-days 366` as a backstop behind the daily job.
5. `npx wrangler secret put ADMIN_TOKEN`, with a long random value.
6. `npm run deploy`. The schema is created on the first request.

## Checking it

```bash
npm ci
npm run typecheck
npm test
```

The tests run in the Workers runtime against local D1 and R2. Tokens are signed with real keys and checked the real way; only the fetch of EVE's key set is faked.
