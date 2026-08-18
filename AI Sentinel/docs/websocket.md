# AI Sentinel — WebSocket / Event Stream Reference

## Connection

```
GET /ws/events?token=<JWT>
```

Authentication is required. The token must be a valid signed AI Sentinel token
(same scheme as the REST API). Invalid/missing tokens are rejected with close
code `4401`.

- Dev via Vite proxy: `ws://localhost:5173/ws/events?token=…`
- Direct: `ws://localhost:8000/ws/events?token=…`
- Prod (single container): same-origin `wss://<host>/ws/events?token=…`

## Message types

All messages are JSON: `{"type": <string>, "payload": {…}}`.

### `hello` — sent once on connect
```json
{"type":"hello","payload":{"user":"admin"}}
```

### `stats` — pipeline metrics (throttled ≤ every 2 s)
```json
{"type":"stats","payload":{
  "eps":0.3,"processed":210,"queue_depth":0,"ws_connections":1,"detections_today":3}}
```

### `event` — new normalized event
```json
{"type":"event","payload":{
  "event_id":"evt_…","ts":"…","source":"agent","host":"srv-01",
  "event_type":"auth.failed_login","category":"auth","severity":"high",
  "source_ip":"203.0.113.50","username":"bob","details":{…}}}
```

### `detection` — rule / ML / TI detection that produced an alert
```json
{"type":"detection","payload":{
  "alert_id":"alt_…","incident_id":"inc_…",
  "title":"Brute force: excessive failed logins from one source",
  "description":"…","severity":"high","risk_score":60,"risk_level":"high",
  "rule":"Brute force: excessive failed logins from one source",
  "category":"credential-attack","mitre":["T1110","T1110.001","T1110.003"],
  "event":{"event_id":"evt_…","type":"auth.failed_login","time":"…",
           "host":"","source_ip":"203.0.113.50","dest_ip":"","username":"u0"},
  "ml":false,"ai_explanation":""}}
```

`ml:true` indicates the detection came from the ML anomaly layer; when present,
`ai_explanation` carries the grounded explanation derived from the learned
baseline (observed value vs baseline mean), never fabricated.

### `alert` — new alert (created after dedup check)
```json
{"type":"alert","payload":{"alert_id":"alt_…","title":"…","severity":"high",
  "risk_score":60,"status":"NEW","source":"brute_force_velocity","event_ids":["evt_…"]}}
```

### `incident` — new or updated incident
```json
{"type":"incident","payload":{"incident_id":"inc_…","title":"…",
  "severity":"high","status":"NEW","risk_score":60,"category":"credential-attack",
  "affected_user":"u0","source_ip":"203.0.113.50","mitre":["T1110"]}}
```

## Notes

- Client must echo/heartbeat: the server keeps the socket open and only reads
  `receive_text()`. A ping/pong at the client is enough to detect dropped links.
- Broadcasts are thread-safe: workers schedule pushes on the main event loop
  via `asyncio.run_coroutine_threadsafe` (fixed the prior dead-loop bug).
- Disconnected clients are pruned on each broadcast.
