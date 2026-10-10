# PhishGuard — Project Rules & Coding Conventions

## Monorepo Layout
```
phishguard/
├── backend/    FastAPI service
├── ml/         Training pipeline (standalone)
├── cti/        Threat intelligence adapters
├── frontend/   React SOC dashboard (TypeScript)
├── extension/  Chrome Extension MV3 (TypeScript)
└── shared/     Cross-cutting Python constants & types
```

## Python (backend / ml / cti)
- Python 3.11+, type hints on every function signature
- Pydantic v2 for all request/response validation
- Async I/O via `asyncio` + `httpx` — no `requests`
- `black` formatter, `isort` for imports
- `logging` module only — no bare `print()`
- One public class per file; keep modules focused

## TypeScript (frontend / extension)
- `strict: true` in all `tsconfig.json` files
- Functional React components only — no class components
- No `any` types
- Tailwind for all styling — no inline `style` objects (exception: extension popup)
- `axios` in frontend, native `fetch` in extension

## Database
- SQLAlchemy 2.x ORM with async engine — **no raw SQL dialect strings**
- All DB access routes through `backend/app/services/db_service.py`
- Dev: `DATABASE_URL=sqlite+aiosqlite:///./phishguard.db`
- Prod: `DATABASE_URL=postgresql+asyncpg://...`  (swap, no code changes required)
- Never store raw API keys in DB rows

## ML Pipeline
- Feature list is the source of truth in `ml/features/extractor.py` → `FEATURE_ORDER`
- Model artifacts live in `ml/models/artifacts/` (gitignored, never committed)
- Retrain: `python ml/train.py` from repo root
- `ml/data/processed/metrics.json` is the authoritative eval record

## CTI Adapters
- Every adapter extends `BaseCTIAdapter` from `cti/base.py`
- `CTI_MOCK=true` (default) → `mock_adapters.py` is injected automatically
- API keys always come from environment — never hardcoded

## Comments
- Only when the **why** is non-obvious (hidden constraint, subtle invariant, workaround)
- No multi-line docstring blocks — one-line max per function
- No "added for X" or "used by Y" notes — those belong in PR descriptions

## Security
- Validate and sanitize all URL inputs server-side before processing
- CORS origins locked to known values in production (`.env`)
- No secrets in git history — use `.env` (gitignored)
