# AI Sentinel Endpoint Agent

## Overview

The standalone agent collects real telemetry from the monitored machine and sends it to the AI Sentinel backend for detection and correlation. It runs independently of the backend server and communicates over HTTP.

## Architecture

```
Agent (this machine)
  ├── config.py    — environment-driven configuration
  ├── collector.py — psutil-based telemetry collection
  └── __main__.py  — main loop, heartbeat, retry, buffer
```

## Quick Start

```bash
# From the backend/ directory:
export SENTINEL_AGENT_KEY="your-agent-key"
export SENTINEL_AGENT_SERVER_URL="http://your-sentinel-server:8000"
python -m agent
```

Or with a `.env` file in the workspace root:

```
SENTINEL_AGENT_KEY=abc123
SENTINEL_AGENT_SERVER_URL=http://localhost:8000
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_AGENT_SERVER_URL` | `http://localhost:8000` | Backend API base URL |
| `SENTINEL_AGENT_KEY` | (required) | Shared agent key for authentication |
| `SENTINEL_AGENT_HOSTNAME` | auto-detected | Override reported hostname |
| `SENTINEL_AGENT_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval in seconds |
| `SENTINEL_AGENT_COLLECT_INTERVAL` | `15` | Telemetry collection interval in seconds |
| `SENTINEL_AGENT_BUFFER_MAX` | `500` | Max buffered events on backend failure |
| `SENTINEL_AGENT_RETRY_BASE_DELAY` | `2` | Base retry delay in seconds (exponential backoff) |
| `SENTINEL_AGENT_RETRY_MAX_DELAY` | `60` | Max retry delay in seconds |

## What It Collects

### System Metrics
- CPU usage (percent)
- Memory usage (percent, used GB, total GB)
- Disk usage (per partition)
- Uptime
- Process count
- Load average (Linux)
- Logged-in users (via `psutil.users()`)

### Network
- Throughput (bytes sent/received delta)
- Active connection count
- Suspicious port detection

### Processes
- New process creation (PID, name, PPID, executable path)
- Process termination

### File Activity
- File creation, modification, deletion, renaming in monitored directories
- Suspicious extension detection (`.exe`, `.dll`, `.bat`, etc.)
- SHA-256 hash of file content

## Authentication

The agent authenticates using the `X-Agent-Key` header. The key must match the `SENTINEL_AGENT_KEY` configured on the server.

## Retry and Buffering

When the backend is unreachable:
1. Events are buffered locally (bounded by `BUFFER_MAX`)
2. Retry uses exponential backoff: `base_delay * 2^attempt`, capped at `max_delay`
3. On successful connection, buffered events are drained first
4. If the buffer is full, the oldest events are evicted

## Heartbeat

The agent sends a heartbeat every `HEARTBEAT_INTERVAL` seconds via `POST /api/agents/heartbeat`. The heartbeat includes:
- Agent ID
- Hostname
- OS type
- Environment
- Current CPU, memory, process count

The server uses heartbeats to track agent health:
- **HEALTHY**: heartbeat within last 60 seconds
- **DEGRADED**: heartbeat within last 600 seconds
- **OFFLINE**: no heartbeat for over 600 seconds

## Event Ingestion

Events are sent via `POST /api/events/ingest/agent` with the `X-Agent-Key` header. Each event includes:
- `event_id` (UUID) for idempotent ingestion
- `event_type` (e.g., `telemetry.snapshot`, `process.created`, `net.connection`, `file.created`)
- Normalized schema matching the backend's canonical event model

## Graceful Shutdown

The agent handles `SIGINT` and `SIGTERM` signals:
1. Sets a shutdown flag
2. Waits for the current collection cycle to finish
3. Flushes any remaining buffered events to the backend
4. Exits cleanly

## Dependencies

Only stdlib + `psutil` (no FastAPI or other backend dependencies). This allows the agent to run on machines that don't have the full backend installed.

## Security

- The agent key is never logged
- Bounded buffer prevents memory exhaustion
- Idempotent ingestion prevents duplicate events on retry
- No TLS enforcement in the agent itself; use a reverse proxy or `https://` server URL for production
