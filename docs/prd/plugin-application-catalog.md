# Product Requirements Document: Application Catalog Plugin

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Product**: KubeDash  
**Feature Area**: Application Catalog Plugin  
**Status**: Active  

---

## Implementation Status

> **Overall Progress: ~100% Complete**

This section tracks the current implementation status against the requirements defined in this PRD.

### Feature Implementation Matrix

| Feature Category | Status | Completion | Notes |
|-----------------|--------|------------|-------|
| **Application Management** | ✅ Implemented | 100% | CRUD operations via UI and API |
| **Configuration File Sync** | ✅ Implemented | 100% | Syncs from kubedash.ini on startup |
| **Embedded Applications** | ✅ Implemented | 100% | Iframe embedding with proxy |
| **Iframe Proxy** | ✅ Implemented | 100% | Full HTTP method support |
| **URL Rewriting** | ✅ Implemented | 100% | HTML and CSS URL rewriting |
| **CSP Management** | ✅ Implemented | 100% | Automatic CSP updates |
| **REST API** | ✅ Implemented | 100% | Full CRUD API endpoints |
| **Settings UI** | ✅ Implemented | 100% | Management interface |

### User Story Implementation Status

#### Application Management
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-APP-001: List Applications | ✅ Done | `plugins/application_catalog/api.py` |
| US-APP-002: Create Application | ✅ Done | `plugins/application_catalog/api.py` |
| US-APP-003: Update Application | ✅ Done | `plugins/application_catalog/api.py` |
| US-APP-004: Delete Application | ✅ Done | `plugins/application_catalog/api.py` |

#### Embedded Applications
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-APP-005: Embed Applications | ✅ Done | `plugins/application_catalog/__init__.py` |
| US-APP-006: Proxy Requests | ✅ Done | `plugins/iframe_proxy/__init__.py` |
| US-APP-007: Rewrite URLs | ✅ Done | `plugins/iframe_proxy/__init__.py` |

#### Configuration
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-APP-008: Config File Sync | ✅ Done | `plugins/application_catalog/helpers.py` |
| US-APP-009: CSP Updates | ✅ Done | `plugins/application_catalog/helpers.py` |

### Key Implementation Details

- **Data Storage**: PostgreSQL/SQLite database table `application_catalog`
- **Database Model**: `ApplicationCatalog` with fields: name, url, icon, enabled, embedded
- **Routes**: 
  - `/plugins/app-catalog/settings` - Settings UI
  - `/plugins/app-catalog/{app_name}` - Embedded app view
  - `/plugins/iframe-proxy/{app_name}/{path}` - Proxy endpoint
  - `/api/v1/application-catalog` - REST API
- **Templates**: `application_catalog/applications.html.j2`, `application_catalog/app_embed.html.j2`
- **Migration**: `ea51eddbcfb6_plugin_application_catalog.py`

### Technical Debt & Known Issues

1. **Icon Support**: Currently supports URL icons, base64 support could be enhanced
2. **Menu Integration**: Applications could be automatically added to main menu
3. **Application Health**: No health checking for application URLs
4. **Bulk Operations**: No bulk import/export functionality

### Next Steps

1. Add application health checking
2. Implement menu integration for quick access
3. Add bulk import/export functionality
4. Enhance icon support (base64, SVG, etc.)
5. Add application usage analytics

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for the KubeDash Application Catalog Plugin. The plugin enables users to manage and embed external applications within KubeDash, creating a unified dashboard experience for observability tools, development utilities, and other web applications.

### 1.2 Background

Organizations often use multiple tools for monitoring, tracing, and development alongside Kubernetes management. Switching between different UIs creates context switching overhead. The Application Catalog allows these tools to be integrated directly into KubeDash, providing a single pane of glass experience.

### 1.3 Goals

1. **Unified Dashboard**: Integrate external applications into KubeDash
2. **Application Management**: Easy addition, configuration, and removal of applications
3. **Secure Embedding**: Safely embed applications with proper security policies
4. **Flexible Access**: Support both embedded and direct link access modes
5. **Configuration Flexibility**: Support both file-based and database-driven configuration

---

## 2. User Personas

### 2.1 DevOps Engineer

- **Role**: Manages infrastructure and observability tools
- **Technical Level**: Advanced
- **Goals**: Integrate monitoring tools (Jaeger, Grafana, Prometheus) into KubeDash
- **Frustrations**: Switching between multiple dashboards and tools

### 2.2 Platform Administrator

- **Role**: Configures and maintains KubeDash
- **Technical Level**: Advanced
- **Goals**: Configure application catalog for team use
- **Frustrations**: Manual configuration management

### 2.3 Developer

- **Role**: Uses development and debugging tools
- **Technical Level**: Intermediate
- **Goals**: Quick access to development tools from KubeDash
- **Frustrations**: Remembering URLs and credentials for multiple tools

---

## 3. User Stories

### 3.1 Application Management

#### US-APP-001: List Applications
**As a** user  
**I want to** see all configured applications  
**So that** I can access them easily  

**Acceptance Criteria**:
- Display all applications in a list
- Show application name, URL, icon, enabled status
- Filter by enabled/disabled status
- Sort by name or creation date
- Display application count

**Priority**: P0 (Critical)

---

#### US-APP-002: Create Application
**As a** user  
**I want to** add a new application to the catalog  
**So that** I can access it from KubeDash  

**Acceptance Criteria**:
- Form to enter application details:
  - Name (required, unique)
  - URL (required, valid URL)
  - Icon (optional, URL or base64)
  - Enabled (checkbox, default: true)
  - Embedded (checkbox, default: false)
- Validate URL format
- Check for duplicate names/URLs
- Success message on creation
- Error handling for invalid inputs

**Priority**: P0 (Critical)

---

#### US-APP-003: Update Application
**As a** user  
**I want to** modify application settings  
**So that** I can keep applications up to date  

**Acceptance Criteria**:
- Edit all application fields
- Update URL, icon, enabled status, embedded mode
- Validate changes before saving
- Update CSP if embedding status changes
- Success message on update

**Priority**: P0 (Critical)

---

#### US-APP-004: Delete Application
**As a** user  
**I want to** remove applications from the catalog  
**So that** I can clean up unused entries  

**Acceptance Criteria**:
- Delete button with confirmation
- Remove from database
- Update CSP if embedded
- Success message on deletion
- Handle errors gracefully

**Priority**: P1 (High)

---

### 3.2 Embedded Applications

#### US-APP-005: Embed Applications
**As a** user  
**I want to** view applications embedded in KubeDash  
**So that** I don't need to switch tabs  

**Acceptance Criteria**:
- Applications with `embedded=true` shown in iframe
- Full-screen iframe experience
- Proper sizing and scrolling
- Loading indicator
- Error handling for unreachable applications

**Priority**: P0 (Critical)

---

#### US-APP-006: Proxy Requests
**As a** user  
**I want to** access HTTP applications from HTTPS KubeDash  
**So that** I can embed them securely  

**Acceptance Criteria**:
- Proxy all HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Forward request headers appropriately
- Handle CORS preflight requests
- Support query parameters
- Timeout handling (30 seconds)
- Error responses for connection failures

**Priority**: P0 (Critical)

---

#### US-APP-007: Rewrite URLs
**As a** user  
**I want to** embedded applications to work correctly  
**So that** all links and resources load properly  

**Acceptance Criteria**:
- Rewrite relative URLs in HTML attributes (href, src, action)
- Rewrite URLs in CSS (url() functions)
- Update `<base>` tags for proper resolution
- Handle absolute URLs correctly
- Prevent double-rewriting
- Support various URL formats

**Priority**: P1 (High)

---

### 3.3 Configuration

#### US-APP-008: Config File Sync
**As a** platform administrator  
**I want to** configure applications in kubedash.ini  
**So that** I can manage them via configuration management  

**Acceptance Criteria**:
- Read `[application_list]` section from config
- Parse application entries (app_1_name, app_1_url, etc.)
- Sync with database on startup
- Update existing applications
- Create new applications
- Handle missing or invalid entries gracefully

**Priority**: P1 (High)

---

#### US-APP-009: CSP Updates
**As a** platform administrator  
**I want to** CSP to be updated automatically  
**So that** embedded applications work without manual configuration  

**Acceptance Criteria**:
- Extract domains from embedded application URLs
- Add domains to CSP `frame-src` directive
- Update CSP on application add/update
- Remove domains on application delete
- Preserve existing CSP settings
- Handle invalid URLs gracefully

**Priority**: P0 (Critical)

---

## 4. Functional Requirements

### 4.1 Application Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-APP-01 | System shall store applications in database | P0 |
| FR-APP-02 | System shall provide CRUD operations for applications | P0 |
| FR-APP-03 | System shall validate application URLs | P0 |
| FR-APP-04 | System shall enforce unique application names | P0 |
| FR-APP-05 | System shall support enabling/disabling applications | P0 |
| FR-APP-06 | System shall support embedded and non-embedded modes | P0 |

### 4.2 Embedded Applications

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-APP-10 | System shall embed applications in iframes | P0 |
| FR-APP-11 | System shall proxy requests to embedded applications | P0 |
| FR-APP-12 | System shall rewrite URLs in embedded content | P1 |
| FR-APP-13 | System shall handle all HTTP methods | P0 |
| FR-APP-14 | System shall support CORS for embedded apps | P0 |

### 4.3 Configuration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-APP-20 | System shall sync config file with database | P1 |
| FR-APP-21 | System shall update CSP automatically | P0 |
| FR-APP-22 | System shall support both file and DB configuration | P1 |

### 4.4 API

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-APP-30 | System shall provide REST API for applications | P1 |
| FR-APP-31 | System shall require authentication for API | P0 |
| FR-APP-32 | System shall return JSON responses | P0 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Application list load time (50 apps) | < 1 second |
| NFR-PERF-02 | Proxy request latency | < 500ms overhead |
| NFR-PERF-03 | URL rewriting time | < 100ms per page |

### 5.2 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-USE-01 | Add new application | < 3 clicks |
| NFR-USE-02 | Access embedded application | < 2 clicks |
| NFR-USE-03 | Responsive design | Desktop + tablet |

### 5.3 Security

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-SEC-01 | Authenticate all operations | Required |
| NFR-SEC-02 | Validate application URLs | Required |
| NFR-SEC-03 | Update CSP for embedded apps | Required |
| NFR-SEC-04 | Prevent XSS in embedded content | Required |

---

## 6. Technical Considerations

### 6.1 Database Schema

```sql
CREATE TABLE application_catalog (
    id INTEGER PRIMARY KEY,
    application_name VARCHAR(100) UNIQUE NOT NULL,
    application_url VARCHAR(200) NOT NULL,
    application_icon VARCHAR(200),
    application_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    application_embedded BOOLEAN NOT NULL DEFAULT FALSE
);
```

### 6.2 Configuration File Format

```ini
[application_list]
app_1_name = Jaeger
app_1_url = http://jaeger:16686
app_1_icon = https://jaeger.io/icon.svg
app_1_embed = true
app_1_enable = true
```

### 6.3 Content Security Policy

The plugin updates the CSP `frame-src` directive to include domains from embedded applications:

```
frame-src 'self' http://jaeger:16686 https://grafana:3000
```

### 6.4 URL Rewriting

The proxy rewrites relative URLs in HTML:
- `href="/api/data"` → `href="/plugins/iframe-proxy/jaeger/api/data"`
- `src="/static/app.js"` → `src="/plugins/iframe-proxy/jaeger/static/app.js"`

### 6.5 RBAC Requirements

Users need authentication to:
- View applications
- Manage applications (Admin role)
- Access embedded applications

---

## 7. User Interface Guidelines

### 7.1 Application List View

```
+------------------------------------------+
| Application Catalog                      |
+------------------------------------------+
| [+ Add Application]                      |
+------------------------------------------+
| Name      | URL              | Status    |
|-----------|------------------|-----------|
| Jaeger    | http://jaeger... | ✅ Enabled |
| Grafana   | https://graf...  | ✅ Enabled |
| Prometheus| http://prom...    | ⚠️ Disabled|
+------------------------------------------+
```

### 7.2 Application Form

```
+------------------------------------------+
| Add/Edit Application                     |
+------------------------------------------+
| Name:        [________________]          |
| URL:         [________________]          |
| Icon:        [________________]          |
| ☑ Enabled                                |
| ☐ Embedded                               |
|                                          |
| [Cancel]  [Save]                         |
+------------------------------------------+
```

### 7.3 Embedded Application View

```
+------------------------------------------+
| ← Back to Applications    [Jaeger]       |
+------------------------------------------+
|                                          |
|  [Embedded Application Content]          |
|                                          |
+------------------------------------------+
```

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Authentication system (for access control)
- Database (SQLAlchemy)
- Plugin framework (registration)
- Security framework (Talisman for CSP)

### 8.2 External Dependencies

- `requests` library (for proxying)
- `urllib.parse` (for URL parsing)
- `re` (for URL rewriting)

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Embedded app doesn't support iframes | High | Medium | Clear error message, fallback to new tab |
| URL rewriting breaks app functionality | Medium | Medium | Comprehensive testing, allow disabling |
| CSP conflicts with app requirements | Medium | Low | Relaxed CSP for embedded apps |
| Proxy performance issues | Medium | Low | Timeout handling, connection pooling |
| Security vulnerabilities in embedded apps | High | Low | Only embed trusted apps, document risks |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Plugin adoption | 40% of installations | Feature analytics |
| Applications per installation | 3-5 apps | Usage statistics |
| Embedded vs non-embedded ratio | 60% embedded | Usage statistics |
| User satisfaction | NPS > 35 | Surveys |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Application Health Checks**: Monitor application availability
2. **Menu Integration**: Auto-add applications to main menu
3. **Bulk Import/Export**: Import/export application configurations
4. **Application Categories**: Organize applications by category
5. **Custom Icons**: Support for custom icon uploads
6. **Application Analytics**: Track application usage
7. **SSO Integration**: Single sign-on for embedded applications
8. **Application Templates**: Pre-configured templates for common tools

### 11.2 Out of Scope (This Version)

- Application authentication (SSO)
- Application health monitoring
- Application usage analytics
- Custom CSS for embedded apps
- Application permissions (per-user access)

---

## 12. Plugin Configuration

### 12.1 Enable/Disable

```ini
# kubedash.ini
[plugins]
application_catalog = true
iframe_proxy = true
```

### 12.2 Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `application_catalog` | `false` | Enable/disable Application Catalog plugin |
| `iframe_proxy` | `false` | Enable/disable iframe proxy (required for embedding) |

### 12.3 Application Configuration

```ini
[application_list]
app_1_name = Application Name
app_1_url = https://app.example.com
app_1_icon = https://app.example.com/icon.svg
app_1_embed = true
app_1_enable = true
```

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, DevOps, Platform Team*

