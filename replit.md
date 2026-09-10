# MailTrace AI

MailTrace AI turns uploaded email evidence into persisted, explainable threat analysis and investigation records.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/mailtrace-ai/src/pages/mailtrace.tsx` — routed analyst workspace UI
- `artifacts/api-server/src/routes/mailtrace.ts` — upload, parsing, analysis, graph, investigations, and reports
- `lib/api-spec/openapi.yaml` — source-of-truth API contract
- `lib/db/src/schema/mailtrace.ts` — persisted MailTrace records
- `artifacts/mailtrace-ai/src/index.css` — cyber-forensics theme tokens

## Architecture decisions

- Email risk signals are calculated from observed headers and body content; unavailable external enrichment stays explicitly unavailable.
- Uploaded evidence is hashed and written to a restricted local development evidence directory while structured analysis is persisted in PostgreSQL.
- The dashboard intentionally starts empty and populates only after a real email upload.

## Product

- Upload `.eml`, `.msg`, or `.txt` email evidence.
- Parse headers, authentication results, URLs, domains, IPs, and relay hops.
- Produce evidence-backed risk findings, threat graph relationships, investigations, and report downloads.

## User preferences

 - Never present fabricated threat intelligence or populated dashboard values.

## Gotchas

- Use `pnpm --filter @workspace/api-spec run codegen` after changing `lib/api-spec/openapi.yaml`.
- API and web workflows are managed artifacts; restart them by their exact managed workflow names.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
