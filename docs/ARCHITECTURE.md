# Bug Bounty Platform Architecture

## Overview

A production-ready, cloud-native autonomous Bug Bounty Security Research Platform for authorized targets only.

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌───────────────┐
│  Next.js UI  │◄──►│  FastAPI API  │◄──►│  PostgreSQL   │
│  (React/TS)  │    │  (Python)    │    │  + Redis      │
└─────────────┘    └──────┬───────┘    └───────────────┘
                          │
                    ┌─────┴─────┐
                    │ Scope &   │
                    │ Policy    │
                    │ Engine    │
                    └─────┬─────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
        ┌─────┴────┐ ┌───┴────┐ ┌───┴──────┐
        │  Agent   │ │ LLM    │ │ Regression│
        │Framework │ │Gateway │ │ Engine    │
        └──────────┘ └────────┘ └───────────┘
```

## Key Components

### Scope & Policy Enforcement Engine
Every action must pass: Authorization → Scope → Policy → Rate Limit → Tool Permission → Execute

### Agent Framework
Extensible agent system with 10+ specialized agents (recon, crawler, API security, browser, injection, authorization, etc.)

### LLM Gateway
Provider-independent gateway supporting OpenAI, Anthropic, Ollama with fallback, cost tracking, and secret redaction.

### Finding Pipeline
Candidate → Validation → Evidence → LLM Review → Confidence → Validated/False Positive

### Regression Engine
Every validated finding becomes a reusable regression test.

## Development

```bash
make setup    # Install dependencies
make dev      # Run API server
make lab      # Run vulnerable lab
make test     # Run tests
make lint     # Run linters
```

## API Endpoints

- `POST /api/v1/organizations` – Create organization
- `POST /api/v1/programs` – Create program with scope
- `PUT /api/v1/programs/{id}/scope` – Update scope
- `POST /api/v1/scans` – Start scan (validates scope)
- `GET /api/v1/scans/{id}` – Get scan status
- `GET /api/v1/scans/{id}/events` – Get scan events
- `GET /api/v1/scans/{id}/stream` – SSE event stream
- `GET /api/v1/findings` – List findings
- `POST /api/v1/findings/{id}/validate` – Validate finding
- `POST /api/v1/findings/{id}/regression` – Create regression test
- `GET /api/v1/agents/types` – List agent types
- `POST /api/v1/reports` – Generate report

## CLI

```bash
bbp scan start --program-id <id> --target https://authorized-target.example
bbp scan status --scan-id <id>
bbp agents list
bbp findings list
bbp finding validate --finding-id <id>
bbp report generate --scan-id <id>
```
