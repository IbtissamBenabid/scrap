# Research API Integration Guide

This document describes how to call the FastAPI `/research` endpoint exported from `api.py` so you can reuse the TPRM agent in another service.

## 1. Run the API server

- Activate the workspace virtual environment in `scrap`.
- Launch the server with `uvicorn api:app --reload`.
- By default the service listens on `http://127.0.0.1:8000`.

The same dependencies and environment variables the CLI/Streamlit experience uses must be available (Groq API key, search throttling values, etc.).

## 2. Endpoint contract

| Element | Details |
| --- | --- |
| Method | `POST` |
| Path | `/research` |
| Headers | `Content-Type: application/json` |
| Body schema | `{"company": "Cloudflare"}` (Pydantic `ResearchRequest` requires a non-empty string, minimum 2 characters) |
| Response model | `ResearchResponse` with `company`, `completed_at` (ISO timestamp), and `profile` (the agent payload mirroring the CLI/Streamlit output: `basic_info`, `security_compliance`, `security_incidents`, `raw_sources`, etc.) |

## 3. Example requests

### curl

```bash
curl -X POST http://127.0.0.1:8000/research \
  -H "Content-Type: application/json" \
  -d '{"company": "Cloudflare"}'
```

### Python (requests)

```python
import requests

resp = requests.post(
    "http://127.0.0.1:8000/research",
    json={"company": "Cloudflare"},
)
resp.raise_for_status()
data = resp.json()
print(data["profile"]["basic_info"]["name"])
```

## 4. Response handling

- `200 OK` with the agent profile when research succeeds.
- `404 Not Found` if the agent could not produce a profile for the supplied company.
- `500 Internal Server Error` on unexpected failures inside `run_graph`.
- `422 Unprocessable Entity` for invalid payloads (e.g., missing or too-short company name). Handle each status gracefully in your client.

## 5. Integration tips

1. Allow enough time for the call because the agent performs searches, scraping, and Groq LLM calls; consider a loading indicator and optional retry/backoff.
2. The API includes a disk cache (section 6) so repeat lookups return instantly while a background refresh keeps the stored profile up to date.
3. Use the `/health` endpoint (`GET /health`) to verify the FastAPI app is running before attempting `/research`.
4. If you need authorization, wrap FastAPI with additional middleware or proxy the call through a secured backend before exposing it.
5. Log `completed_at` along with the company to match responses to requests.

## 6. Caching and background refresh

- The endpoint stores every successful response under `.cache/research-cache.json` (override via `RESEARCH_CACHE_FILE`).
- Cached entries younger than `RESEARCH_CACHE_TTL_SECONDS` (default 86400 seconds) are returned immediately, and stale entries trigger an asynchronous job to refresh the cache while still returning the last known profile.
- When no cache exists, the client waits for `run_graph()` to finish and the response is saved for future hits.
- If you prefer to control refreshes manually, you can pre-populate the cache file with the same structure, but keep the company key normalized to lowercase and include `profile`, `completed_at`, and `cached_at` fields.

## 7. Reference

- [api.py](/api.py) contains the FastAPI app, request/response models, and the `/research` handler that calls `run_graph`.
- The README explains the agent payload structure under the “API Access” section.
