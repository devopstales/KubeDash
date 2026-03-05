# KubeDash documentation

This directory is the source for the [MkDocs](https://www.mkdocs.org/) site. The navigation is defined in the repo root in **`mkdocs.yml`**.

## Structure

| Folder / file | Purpose |
|---------------|--------|
| **index.md** | Main overview and quick links |
| **installation/** | How to install and configure KubeDash |
| **functions/** | User-facing feature docs (workloads, RBAC, storage, etc.) |
| **integrations/** | User guides for integrations and plugins (Extension API, Helm, Registry, Cert Manager, Application Catalog, etc.). One nav entry per topic. |
| **plugins/** | Plugin reference index (`README.md`) and per-plugin reference docs (structure, config, routes). In the nav: single entry “Plugin reference” → `plugins/README.md`; that page links to all plugin docs and to the corresponding Integration user guides. |
| **development/** | Architecture, developer guide, testing, API reference, security |
| **prd/** | Product requirements (PRDs) for features and plugins |
| **faq/** | FAQ content |
| **build/** | MkDocs build dependencies only (see `build/README.md`) |
| **assets/** | Static assets for the doc site (e.g. search) |
| **development/plugin-development.md**, **development/extension-api-reference.md**, **development/extension-api-examples.md** | Plugin and Extension API dev docs; linked from Development in the nav |

- **Integrations** (nav): “How to use” guides; hyphenated filenames (e.g. `extension-api.md`).
- **Plugins** (nav): Plugin reference; filenames match plugin dirs with underscores (e.g. `application_catalog.md`).

Image links like `../img/...` in doc files resolve to **docs/img/**; add screenshots there if needed.
