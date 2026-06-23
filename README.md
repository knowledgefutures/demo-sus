# SUS · the Simplest Underlay Server

A complete [Underlay](https://underlay.org) server in one file, with zero
dependencies. The whole protocol (content-addressed records and schemas,
derived semantic versioning, public/private hashing), plus an HTTP API and a
plain HTML console, all in `sus.mjs`.

```bash
node sus.mjs        # serves http://localhost:8080
```

A public instance runs at **[sus.knowledgefutures.org](https://sus.knowledgefutures.org)**.

> ⚠️ **It is a demo with no authentication.** Everything pushed is public and
> world-readable, so don't push anything private or sensitive. Anyone can delete
> anything; as a courtesy, don't delete collections newer than 24 hours unless
> space is short. Storage is capped (1 GB by default); once full, pushes are
> refused until someone deletes a collection to free space.

### Point an agent at it

Hand your agent a prompt like this:

> The server at https://sus.knowledgefutures.org is an Underlay node. Read
> https://sus.knowledgefutures.org for its API, then create a collection and
> push some JSON records with a JSON Schema. It needs no authentication. Do not
> include any private or sensitive data. Everything you push is public.

---

## Why this exists

The production Underlay server is a large app: auth, organizations, Postgres,
S3, ARK identifiers, mirror sync, a React frontend. None of that is _the
protocol_. SUS strips all of it away to show how simple the protocol actually is,
in a single file you can read in full.

The content-addressing core in `sus.mjs` (`canonicalize`, `hashRecord`,
`hashSchema`, `computeVersionHash`, `computePublicHash`, the privacy filters,
and semver derivation) is copied **verbatim** from the production server's
`src/lib/core/`. That code _is_ the protocol's wire contract: any two
implementations that agree on canonicalization produce byte-identical version
hashes and can therefore exchange collections. A version pushed to SUS hashes
exactly the same as it would on the real server.

## How it works

- **Content addressing.** Every record and schema is hashed (SHA-256 over a
  canonical, key-sorted JSON form) and stored under that hash as its filename.
  Identical content is stored once, so pushing the same record twice is a no-op.
- **Versions are manifests.** A version is a small JSON file listing the record
  and schema hashes it contains, plus one `hash` that is the content-address of
  the whole version.
- **Semver is derived, not chosen.** A schema change bumps major, a records
  change bumps minor, a metadata-only change bumps patch.
- **Public vs private hash.** Fields or whole types marked `"private": true` are
  stripped and re-hashed into a separate `publicHash` that can be shared without
  leaking private data. (This demo has no auth and serves the full owner view, so
  the data itself is not hidden on read — see [Protocol compliance](#protocol-compliance).)

### On-disk layout

The filesystem is the database. Deduplication is just "does this file exist?"

```
sus-data/
  records/<sha256>.json          one record object { id, type, data }
  schemas/<sha256>.json          one schema body
  files/<sha256>                 one binary blob (+ <sha256>.type)
  collections/<owner>/<slug>/
    meta.json                    { name, public, createdAt }
    v1.0.0.json                  a version manifest (lists the hashes above)
    v1.1.0.json
```

The store location defaults to `./sus-data` and can be moved with `SUS_DATA`.
Delete the folder to reset.

## Web console

The root serves a small server-rendered site (no SPA, no client router, just
real URLs and `<a>` links; reads need no JavaScript):

| Path                   | Page                                                                             |
| ---------------------- | -------------------------------------------------------------------------------- |
| `/`                    | intro, links, demo notice, live storage gauge, agent prompt, list of collections |
| `/new`                 | create a collection                                                              |
| `/c/:owner/:slug`      | a collection: its versions, latest records, push/delete                          |
| `/c/:owner/:slug/push` | push a version to that collection                                                |

The same data is available as JSON under `/api`:

## API

Collections:

| Method   | Path                                 | Body                              |
| -------- | ------------------------------------ | --------------------------------- |
| `GET`    | `/api/health`                        | (also reports storage used / cap) |
| `GET`    | `/api/collections`                   |                                   |
| `POST`   | `/api/collections`                   | `{ owner, slug, name }`           |
| `GET`    | `/api/collections/:owner/:slug`      |                                   |
| `DELETE` | `/api/collections/:owner/:slug`      | garbage-collects orphaned content |
| `POST`   | `/api/collections/:owner/:slug/fork` | `{ targetOrg, slug? }`            |

Push (negotiate protocol):

| Method   | Path                                                           | Body                                         |
| -------- | -------------------------------------------------------------- | -------------------------------------------- |
| `POST`   | `/api/collections/:owner/:slug/versions/negotiate`             | `{ base_version, schemas, manifest, files }` |
| `POST`   | `/api/collections/:owner/:slug/versions/negotiate/:id/records` | NDJSON records                               |
| `POST`   | `/api/collections/:owner/:slug/versions/negotiate/:id/commit`  |                                              |
| `GET`    | `/api/collections/:owner/:slug/versions/negotiate/:id`         | session status                               |
| `DELETE` | `/api/collections/:owner/:slug/versions/negotiate/:id`         | cancel session                               |
| `POST`   | `/api/collections/:owner/:slug/push`                           | one-shot convenience over the above          |

Pull / read:

| Method | Path                                                        | Notes                       |
| ------ | ----------------------------------------------------------- | --------------------------- |
| `GET`  | `/api/collections/:owner/:slug/versions/:semver`            | (`:semver` may be `latest`) |
| `GET`  | `/api/collections/:owner/:slug/versions/:semver/manifest`   | `?since=` for a delta       |
| `GET`  | `/api/collections/:owner/:slug/versions/:semver/diff?from=` | added / updated / removed   |
| `GET`  | `/api/collections/:owner/:slug/versions/:semver/records`    |                             |
| `GET`  | `/api/collections/:owner/:slug/versions/:semver/files`      |                             |
| `POST` | `/api/records/batch`                                        | `{ hashes }` → NDJSON       |
| `GET`  | `/api/records/:hash`                                        |                             |
| `GET`  | `/api/records/:hash/provenance`                             |                             |
| `GET`  | `/api/schemas/:hash`                                        |                             |

Files (content-addressed blobs):

| Method | Path                                               | Notes                        |
| ------ | -------------------------------------------------- | ---------------------------- |
| `PUT`  | `/api/collections/:owner/:slug/files/sha256:<hex>` | upload; server verifies hash |
| `GET`  | `/api/collections/:owner/:slug/files/:hash`        | download                     |
| `HEAD` | `/api/collections/:owner/:slug/files/:hash`        | existence + size + type      |

### Example

```bash
# create a collection
curl -X POST localhost:8080/api/collections \
  -H 'content-type: application/json' \
  -d '{"owner":"demo","slug":"people","name":"People"}'

# push a version (schema + records)
curl -X POST localhost:8080/api/collections/demo/people/push \
  -H 'content-type: application/json' \
  -d '{
    "message": "initial import",
    "schemas": {
      "person": {
        "type": "object",
        "properties": {
          "name":  { "type": "string" },
          "age":   { "type": "integer" },
          "email": { "type": "string", "private": true }
        },
        "required": ["name"]
      }
    },
    "records": [
      { "id": "alice", "type": "person", "data": { "name": "Alice", "age": 30, "email": "alice@example.com" } },
      { "id": "bob",   "type": "person", "data": { "name": "Bob",   "age": 25, "email": "bob@example.com" } }
    ]
  }'

# read it back
curl localhost:8080/api/collections/demo/people/versions/latest
```

The push response reports the derived version, the semver bump, and how much
content was deduplicated. Note that `publicHash` differs from `hash` because the
private `email` field is excluded from the public address.

## Protocol compliance

SUS implements the full [Underlay protocol](https://underlay.org/protocol):

- **Data model:** records, schemas, versions, and files, all content-addressed
  and globally deduplicated.
- **Identity:** record hashing, the `private:`/`public:` version hashes, and
  public-hash addressing (records of a type with private fields are listed and
  served under their filtered public hash). Hashes are byte-identical to the
  reference server.
- **Push:** the negotiate protocol (`negotiate` → send records as NDJSON →
  `commit`), with optimistic locking on `base_version` (409 on conflict),
  unknown-field rejection (422) and `strip_unknown_fields`, and missing-file
  detection (422). `POST .../push` is a one-shot convenience that funnels
  through the same commit path.
- **Pull:** full and delta (`?since=`) manifests, `diff?from=`, and
  `POST /api/records/batch` as an NDJSON stream.
- **Files:** `PUT` with server-side hash verification, `GET`/`HEAD`, dedup, and
  `{"$file":"sha256:..."}` references resolved at commit time.
- **Provenance** and **fork** (manifest-only copy via `forkedFrom`).

### What it leaves out (platform, not protocol)

- **Auth, organizations, API keys, rate limits.** Everything is open; ownership
  is just a slug. Since anyone can already read, write, and delete, SUS treats
  **every caller as the owner** and serves the full view: private types,
  records, and fields are all returned. The `private:`/`public:` version hashes
  are still computed and the filtered public documents are still stored (so a
  record resolves by either its private or its public hash), but on this
  unauthenticated demo, marking data private does **not** hide it on read.
  Don't push anything you wouldn't publish.
- **Postgres and S3.** The filesystem is the store.
- **Full JSON-Schema validation.** Replaced by a ~30-line structural check
  (required fields present, declared primitive types match).
- **ARK identifiers, mirror sync, the SQL query console, discussion threads.**
  Platform features layered on top of the protocol.

## Development

Running the server needs nothing but Node. The dev dependencies are only for
linting and formatting, matching the underlay repo's conventions (oxlint +
oxfmt):

```bash
pnpm install      # dev tooling only; the server still runs with bare `node sus.mjs`
pnpm fmt          # format (oxfmt)
pnpm fmt:check    # verify formatting
pnpm lint         # lint (oxlint)
```

A `simple-git-hooks` pre-commit hook runs `lint-staged` (oxfmt on staged files);
run `pnpm simple-git-hooks` once to install it. CI
([`.github/workflows/ci.yml`](./.github/workflows/ci.yml)) gates `fmt:check` and
`lint` on every push and PR.

## Deployment

SUS ships with Docker behind a host-level Caddy on any vm. See [`docker-compose.yml`](./docker-compose.yml).

```bash
docker compose up -d --build
```

This publishes the server on `127.0.0.1:3003` (container port `8080`) and persists the content store in the `sus-data` named volume. The compose file also caps memory (`256m`), CPU (`0.5`), and the content store (`SUS_MAX_BYTES`, 1 GB; pushes are refused once it's full). Add a block to the host Caddyfile (see [`Caddyfile.example`](./Caddyfile.example)) to expose it. The `tls internal` line matches the existing underlay Caddyfile, where real TLS is terminated upstream; drop it if this host faces the internet directly:

```
sus.knowledgefutures.org {
    tls internal
    reverse_proxy 127.0.0.1:3003
}
```

Then `systemctl reload caddy`.

### Continuous deployment (GitHub Actions)

[`.github/workflows/deploy.yml`](./.github/workflows/deploy.yml) deploys on every push to `main` (and on manual dispatch). It mirrors the underlay setup: the deploy target is kept out of git in an sops-encrypted env file, decrypted in CI to learn which host to ship to. The workflow then SSHes to the box, pulls the repo into `/srv/sus`, and runs `docker compose up -d --build`.

One-time setup:

1. Put the box's address in the encrypted env file (reuses the team age key, so
   it decrypts with the same key as the underlay repo):

   ```bash
   cp .env.prod.example .env.prod
   # set DEPLOY_HOST to the box IP or hostname
   npm run secrets:encrypt:prod
   git add .env.prod.enc && git commit -m "add deploy host"
   ```

   (`npm run secrets:decrypt:prod` reverses it. The plaintext `.env.prod` is
   gitignored; only `.env.prod.enc` is committed.)

2. Add these repository secrets in GitHub (the same values the underlay repo uses):

   | Secret                | Purpose                                     |
   | --------------------- | ------------------------------------------- |
   | `SOPS_AGE_SECRET_KEY` | age private key, to decrypt `.env.prod.enc` |
   | `SSH_PRIVATE_KEY`     | key authorized on the box                   |
   | `SSH_USER`            | SSH user on the box                         |

The box needs Docker and (for the first run) the host Caddy block above. The
workflow clones over HTTPS, which assumes this repo is public; if it is made
private, switch the `REPO_URL` in the workflow to `git@github.com:...` and add a
deploy key to the box.

### Resetting

Everything lives in the `sus-data` volume. To wipe the instance:

```bash
docker compose down
docker volume rm sus_sus-data
docker compose up -d --build
```
