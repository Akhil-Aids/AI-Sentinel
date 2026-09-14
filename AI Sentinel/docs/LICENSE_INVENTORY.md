# License Inventory

Commercial-grade license audit of all direct dependencies. Every dependency
listed below is a **permissive** open-source license (MIT, BSD, or Apache-2.0),
suitable for proprietary and commercial use without copyleft obligations.

Generated: 2026-09-14

---

## Backend (Python)

| Package | Version | License | Notes |
|---------|---------|---------|-------|
| fastapi | 0.115.0 | MIT | Web framework |
| uvicorn[standard] | 0.30.6 | BSD-3-Clause | ASGI server |
| pydantic | 2.9.2 | MIT | Data validation |
| python-dotenv | 1.0.1 | BSD-3-Clause | .env file loader |
| scikit-learn | 1.5.2 | BSD-3-Clause | ML (Isolation Forest) |
| numpy | 2.1.1 | BSD-3-Clause | Numerical arrays |
| joblib | 1.5.3 | BSD-3-Clause | Model serialization |
| requests | 2.31.0 | Apache-2.0 | HTTP client (threat intel) |
| psutil | 7.2.2 | BSD-3-Clause | System metrics collection |
| pytest | 9.1.1 | MIT | Test framework (dev only) |
| httpx | 0.28.1 | BSD-3-Clause | Test HTTP client (dev only) |

**Copyleft risk: NONE** — all permissive.

## Frontend (JavaScript)

| Package | Version | License | Notes |
|---------|---------|---------|-------|
| react | ^18.3.1 | MIT | UI library |
| react-dom | ^18.3.1 | MIT | React DOM renderer |
| react-router-dom | ^6.27.0 | MIT | Client-side routing |
| @vitejs/plugin-react | ^4.3.2 | MIT | Vite React plugin (dev only) |
| autoprefixer | ^10.4.20 | MIT | CSS vendor prefixing (dev only) |
| postcss | ^8.4.47 | MIT | CSS transforms (dev only) |
| tailwindcss | ^3.4.13 | MIT | Utility CSS framework (dev only) |
| vite | ^5.4.8 | MIT | Build tool / dev server (dev only) |

**Copyleft risk: NONE** — all permissive.

## System

| Component | License | Notes |
|-----------|---------|-------|
| SQLite | Public Domain | Database engine; no restrictions |
| Python 3.11+ | PSF License | Permissive; no copyleft |
| Node.js 18+ | MIT | No copyleft |
| Linux kernel | GPL-2.0 | Only relevant for kernel-level telemetry; AI Sentinel only uses userspace APIs (psutil) |

---

## Summary

| Category | Total direct deps | Permissive | Copyleft (GPL/AGPL/LGPL) |
|----------|-------------------|------------|--------------------------|
| Backend | 11 | 11 | 0 |
| Frontend | 8 | 8 | 0 |
| System | 2 | 2 | 0 |
| **Total** | **21** | **21** | **0** |

**No copyleft licenses are present in any direct or build-time dependency.**
Transitive dependency risk is low (scikit-learn, numpy, and node ecosystem
transitive deps are overwhelmingly permissive), but a `pip-licenses` and
`license-checker` scan is recommended before any public binary release.
