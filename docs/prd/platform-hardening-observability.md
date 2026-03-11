# Product Requirements Document: Platform Hardening & Observability

**Document Version**: 1.0  
**Last Updated**: March 2026  
**Product**: KubeDash  
**Feature Area**: Platform Hardening & Observability  
**Status**: Draft  

---

## Table of Contents

1. [Implementation Status](#implementation-status)
2. [Executive Summary](#1-executive-summary)
3. [Rate Limiting](#2-rate-limiting)
4. [Redis Cluster Support](#3-redis-cluster-support)
5. [Structured Logging](#4-structured-logging)
6. [Internationalization (i18n)](#5-internationalization-i18n)
7. [Audit Logging](#6-audit-logging)
8. [Prometheus Pull Metrics (Optional)](#7-prometheus-pull-metrics-optional)
9. [Success Metrics](#8-success-metrics)
10. [Related PRDs](#9-related-prds)

---

## Implementation Status

> **Overall Progress: 0% — Not Started**

This PRD captures gaps and recommendations from security and platform reviews. Implementation status will be updated as work proceeds.

### Feature Implementation Matrix

| Feature Area | Status | Completion | Notes |
|--------------|--------|------------|-------|
| **Rate Limiting** | ❌ Not Started | 0% | No rate limiting on authentication endpoints |
| **Redis Cluster Support** | ⚠️ Config Only | 0% | `cluster_enabled` in config; no implementation |
| **Structured Logging** | ❌ Not Started | 0% | Custom color logger only; no JSON option |
| **Internationalization (i18n)** | ❌ Not Started | 0% | No multi-language support |
| **Audit Logging** | ❌ Not Started | 0% | No audit trail for user actions |
| **Prometheus Pull Metrics** | ❌ Not Started | 0% | Optional; move metrics to pull model |

### Technical Debt & Rationale

| Gap | Current State | Recommendation |
|-----|---------------|-----------------|
| **Rate limiting** | Authentication endpoints (login, OIDC callback) have no rate limiting | Add flask-limiter for brute-force protection |
| **Redis cluster** | Config exposes `cluster_enabled` but no cluster-mode implementation | Complete implementation or remove option to avoid confusion |
| **Structured logging** | Custom color logger; not suitable for log aggregation | Add JSON logging option for production (ELK/Loki compatibility) |
| **i18n** | No internationalization | Add Flask-Babel for multi-language support |
| **Audit logging** | No audit trail for sensitive user actions | Add audit log plugin for compliance |
| **Metrics** | Push or on-demand metrics today | Optional: expose Prometheus pull metrics |

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines requirements for platform hardening and observability improvements in KubeDash. It addresses security gaps (rate limiting, audit logging), operational clarity (Redis cluster support or removal, structured logging), and optional enhancements (internationalization, Prometheus pull metrics).

### 1.2 Background

Security and platform reviews identified missing controls and observability features that are expected in enterprise Kubernetes dashboards. This document consolidates those findings into a single PRD for prioritization and implementation.

### 1.3 Goals

1. **Security**: Reduce brute-force and abuse risk on auth endpoints; provide audit trail for compliance.
2. **Operational clarity**: Align configuration with implementation (Redis); improve log consumption in production.
3. **Usability (optional)**: Support multiple languages and standard metrics ingestion where needed.

---

## 2. Rate Limiting

### 2.1 Problem

Authentication endpoints (e.g. login, OIDC callback) have no rate limiting. This increases exposure to brute-force and credential-stuffing attacks.

### 2.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| RL-001 | Apply rate limiting to login (local auth) endpoint | P0 |
| RL-002 | Apply rate limiting to OIDC/SSO callback endpoint | P0 |
| RL-003 | Make limits configurable (e.g. requests per minute per IP) | P1 |
| RL-004 | Return HTTP 429 when limit exceeded, with Retry-After where appropriate | P0 |
| RL-005 | Optionally exempt or use higher limits for trusted IPs/CIDRs | P2 |

### 2.3 User Stories

#### US-RL-001: Brute-Force Protection on Login
**As a** platform administrator  
**I want** login attempts to be rate-limited per client  
**So that** brute-force attacks against local or SSO login are mitigated  

**Acceptance Criteria**:
- After N failed attempts per IP (configurable), further attempts are rejected with 429 for a cooldown period.
- Successful login resets or does not count against the limit.
- Limit applies to both local login and OIDC callback (where applicable).

**Priority**: P0

### 2.4 Recommendation

- Use **Flask-Limiter** (or equivalent) with in-memory or Redis-backed storage.
- Default: e.g. 5 login attempts per minute per IP; configurable via `kubedash.ini` or environment.

---

## 3. Redis Cluster Support

### 3.1 Problem

Configuration exposes a `cluster_enabled` (or similar) option for Redis, but no cluster-mode implementation is visible. This can mislead operators and cause support confusion.

### 3.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| RC-001 | Either implement Redis Cluster support (connection, routing) or remove cluster-related config | P0 |
| RC-002 | If removed: delete `cluster_enabled` and any cluster-only options; document standalone Redis only | P1 |
| RC-003 | If implemented: support cluster topology discovery and use cluster-aware client (e.g. redis-py cluster) | P0 |

### 3.3 User Stories

#### US-RC-001: Config Matches Behavior
**As an** operator  
**I want** Redis configuration options to reflect actual behavior  
**So that** I do not enable “cluster” mode expecting high availability when it is not implemented  

**Acceptance Criteria**:
- No configuration option implies Redis Cluster support unless it is implemented.
- Documentation states clearly whether standalone only or cluster is supported.

**Priority**: P0

### 3.4 Recommendation

- **Option A**: Remove `cluster_enabled` and cluster-only options; document that only standalone Redis is supported.
- **Option B**: Complete Redis Cluster implementation using a cluster-capable client and document topology requirements.

---

## 4. Structured Logging

### 4.1 Problem

Logging uses a custom color logger. Production log pipelines (ELK, Loki, Splunk) expect structured (e.g. JSON) logs for parsing, filtering, and correlation.

### 4.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| SL-001 | Support a structured logging format (e.g. JSON) in addition to current human-readable format | P0 |
| SL-002 | Make format selectable via config (e.g. `logging_format = json` vs `text`) | P1 |
| SL-003 | JSON logs include: timestamp, level, logger name, message, and optional fields (e.g. correlation_id, request_id, user) | P0 |
| SL-004 | Preserve existing behavior when structured format is disabled | P1 |

### 4.3 User Stories

#### US-SL-001: JSON Logs for Production
**As an** operator  
**I want** KubeDash to emit JSON logs when configured for production  
**So that** I can ship logs to ELK, Loki, or similar without custom parsing  

**Acceptance Criteria**:
- Config option (e.g. in `[logging]`) selects format: `text` (current) or `json`.
- JSON lines include timestamp, level, message, and common context (e.g. correlation_id when in request context).
- Default remains text for backward compatibility.

**Priority**: P0

### 4.4 Recommendation

- Add a JSON logging option (e.g. `python-json-logger` or stdlib JSON formatter).
- Use same log level and handler configuration; only formatter changes.

---

## 5. Internationalization (i18n)

### 5.1 Problem

No internationalization support is visible. Users in non-English environments cannot use the UI in their preferred language.

### 5.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| I18N-001 | Support multiple UI languages via Flask-Babel (or equivalent) | P2 |
| I18N-002 | Extract translatable strings from templates and Python (messages) | P2 |
| I18N-003 | Allow language selection via user preference or browser/session | P2 |
| I18N-004 | Document how to add and update translations (e.g. .po/.mo workflow) | P2 |

### 5.3 User Stories

#### US-I18N-001: Use UI in Preferred Language
**As a** user  
**I want** to choose the dashboard language  
**So that** I can use KubeDash in my preferred language  

**Acceptance Criteria**:
- At least English as default; one additional language (e.g. one locale) as proof of concept.
- Language can be selected in settings or via Accept-Language/session.
- Template and key messages use translation functions.

**Priority**: P2

### 5.4 Recommendation

- Add **Flask-Babel** (or Flask-BabelEx) for message extraction and runtime translation.
- Start with a small set of pages and expand; document translation contribution process.

---

## 6. Audit Logging

### 6.1 Problem

There is no audit trail for user actions (login, resource changes, settings changes). Compliance and security investigations require a record of who did what and when.

### 6.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| AL-001 | Record authentication events (login success/failure, logout, SSO) with user, timestamp, IP, outcome | P0 |
| AL-002 | Record high-risk actions (e.g. delete user, change role, cluster/namespace delete) with user, resource, timestamp | P0 |
| AL-003 | Store audit records in a durable backend (e.g. database table or configurable sink) | P0 |
| AL-004 | Provide a way to query or export audit logs (API or UI) for compliance | P1 |
| AL-005 | Optionally integrate with OpenTelemetry or external SIEM (e.g. as events/spans) | P2 |

### 6.3 User Stories

#### US-AL-001: Audit Trail for Sensitive Actions
**As a** security or compliance officer  
**I want** an audit log of who logged in and what sensitive actions they performed  
**So that** I can investigate incidents and meet compliance requirements  

**Acceptance Criteria**:
- Login (success/failure), logout, and SSO events are logged with user identity (or anonymous), IP, timestamp.
- Destructive or high-privilege actions (e.g. user delete, role change) are logged with resource and outcome.
- Logs are stored in DB or configurable sink and retained according to policy.
- Optional: filterable/exportable view or API for audit log.

**Priority**: P0

### 6.4 Recommendation

- Add an **audit log plugin** or core module that writes to a dedicated table (or external sink).
- Define a small event schema (event_type, user, resource, timestamp, metadata).
- Consider emitting critical events to OpenTelemetry for correlation with traces.

---

## 7. Prometheus Pull Metrics (Optional)

### 7.1 Problem

Metrics are currently collected on-demand or via push. Some environments standardize on Prometheus pull for scraping application metrics.

### 7.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| PM-001 | Expose a Prometheus-compatible metrics endpoint (e.g. `/metrics`) with standard format | P2 |
| PM-002 | Include basic app metrics (e.g. request count, latency, error count, active sessions) | P2 |
| PM-003 | Document Prometheus scrape config and any recommended ServiceMonitor | P2 |

### 7.3 User Stories

#### US-PM-001: Scrape KubeDash with Prometheus
**As an** operator  
**I want** Prometheus to scrape KubeDash metrics via pull  
**So that** I can use the same monitoring stack as the rest of the cluster  

**Acceptance Criteria**:
- `GET /metrics` (or configured path) returns Prometheus text exposition format.
- Metrics include at least request counts and basic health indicators.
- Documentation includes example Prometheus scrape config and, if applicable, ServiceMonitor.

**Priority**: P2 (Optional)

### 7.4 Recommendation

- Add **prometheus_client** (or Flask-Prometheus) to expose `/metrics`.
- Align with existing ServiceMonitor patterns in the Helm chart if present.

---

## 8. Success Metrics

| Goal | Metric |
|------|--------|
| Security | Rate limiting enabled on auth endpoints; no config implying unsupported Redis Cluster |
| Observability | JSON logging option available; audit events stored and queryable |
| Optional | At least one extra language available; Prometheus `/metrics` exposed and documented |

---

## 9. Related PRDs

- [Authentication & User Management](authentication-user-management.md) — Rate limiting and audit logging apply to auth flows.
- [Dashboard & Monitoring](dashboard-monitoring.md) — Prometheus pull metrics relate to monitoring strategy.
- [KubeDash Product Requirements](kubedash-product-requirements.md) — Master PRD; this document feeds into technical debt and roadmap.
