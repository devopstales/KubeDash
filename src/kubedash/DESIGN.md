# Design System of KubeDash (CoreUI Bootstrap 5)

## 1. Visual Theme & Atmosphere

KubeDash is an admin dashboard built on **CoreUI v5.2.0**, a free Bootstrap 5-based admin template by creativeLabs. The design language is **enterprise-clean**: a crisp white canvas with a distinctive indigo-violet primary accent that signals "infrastructure tool" without being cold. Every surface, component, and interaction follows CoreUI's component system extended with custom KubeDash styling.

The visual identity says **"operators' cockpit"** — information-dense but not cluttered, with clear visual hierarchy from sidebar to data tables. The dark theme is a deep navy-charcoal (`#212631`) that reduces eye strain during long on-call sessions, with all semantic colors adjusted for dark mode legibility.

Key design characteristics:
- Light mode: pure white (`#ffffff`) canvas with subtle blue-tinted grays
- Dark mode: deep navy (`#212631`) with warm-gray elevations
- Primary accent: indigo-violet (`#5856d6`) — modern, slightly purple, not the standard Bootstrap blue
- Dense tabular data with 1px borders, minimal padding, sortable headers
- Sidebar navigation with collapsible sections, active state highlighting
- Breadcrumb-based page context in the header
- Toast notifications for async feedback

## 2. Color Palette & Roles

### Primary
- **Indigo Primary** (`#5856d6`): The core brand color — an indigo-violet used for active nav states, primary buttons, links, focus rings, and sidebar highlights. RGB: `88, 86, 214`. Hover darkens to `#4645ab`.
- **Primary Light** (`#cfc7f3`): Subtle background tint for primary elements (badges, selected rows, alert backgrounds).
- **Primary Border** (`#9d92e6`): Border variant for primary-themed elements.
- **Primary Text** (`#3634a3`): Dark text for primary-colored headings and emphasized text.

### Secondary
- **Slate Secondary** (`#6b7785`): Secondary buttons, muted labels, de-emphasized metadata. RGB: `107, 119, 133`.

### Semantic Colors
- **Success** (`#1b9e3e`): Running pods, healthy nodes, successful operations. Light bg: `#cbedd6`, dark text: `#0f5722`, border: `#96dbad`.
- **Info** (`#3399ff`): Informational messages, pending states, links. Light bg: `#c0e6ff`, dark text: `#184c77`, border: `#80c6ff`.
- **Warning** (`#f9b115`): Degraded states, resource limits nearing capacity. Light bg: `#feecc5`, dark text: `#764705`, border: `#fcd88a`.
- **Danger** (`#e55353`): Errors, failed pods, critical alerts. Light bg: `#f9d4d4`, dark text: `#671414`, border: `#f2a9a9`.

### Surface & Background (Light Mode)
- **White** (`#ffffff`): Primary page background and card surfaces.
- **Gray 100** (`#f3f4f7`): Light surfaces, tertiary backgrounds, light mode header.
- **Gray 200** (`#e7eaee`): Secondary backgrounds, subtle surface separation.
- **Gray 300** (`#dbdfe6`): Default border color (`--cui-border-color`).
- **Gray 400** (`#cfd4de`): Disabled state borders, subtle dividers.
- **Gray 500** (`#aab3c5`): Inactive icons, placeholder text.

### Surface & Background (Dark Mode)
- **Deep Navy** (`#212631`): Primary page background. RGB: `33, 38, 49`.
- **Dark Surface** (`#2a303d`): Tertiary surfaces, elevated containers in dark mode.
- **Dark Elevated** (`#323a49`): Secondary dark backgrounds, card surfaces.
- **Dark Border** (implied `#4a566d`-range borders adapted from gray-700).

### Neutral Text Colors (Light Mode)
- **Black** (`#080a0c`): Maximum emphasis text, headings.
- **Body Color** (`rgba(37, 43, 54, 0.95)`): Primary body text — a very dark blue-tinted charcoal.
- **Secondary Text** (`rgba(37, 43, 54, 0.681`): Muted body text, timestamps, metadata.
- **Tertiary Text** (`rgba(37, 43, 54, 0.38)`): Disabled state text, placeholders.
- **Gray 700** (`#4a566d`): Dark-enough for body use, muted headings.
- **Gray 800** (`#323a49`): Near-black for high-contrast needs.

### Shadow System
- **Base Shadow** (`0 0.5rem 1rem rgba(8, 10, 12, 0.15)`): Card and dropdown elevation.
- **Small Shadow** (`0 0.125rem 0.25rem rgba(8, 10, 12, 0.075)`): Subtle element elevation.
- **Large Shadow** (`0 1rem 3rem rgba(8, 10, 12, 0.175)`): Modal overlays, popovers.
- **Inset Shadow** (`inset 0 1px 2px rgba(8, 10, 12, 0.075)`): Form input inner depth.

### Focus Ring
- **Primary Focus** (`rgba(88, 86, 214, 0.25)` at `0.25rem` width): Indigo-tinted focus ring matching the primary brand color.

## 3. Typography Rules

### Font Families
- **Sans-Serif (Primary)**: `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", "Noto Sans", "Liberation Sans", Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji"` — full system font stack for native performance.
- **Monospace (Code)**: `SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace` — terminal output, YAML, log lines.

### Hierarchy

| Role | Font | Size | Weight | Line Height | Notes |
|------|------|------|--------|-------------|-------|
| H1 / Page Title | Sans-serif | 1.875rem (30px) | 500 | 1.2 | Main page headings |
| H2 / Section | Sans-serif | 1.5rem (24px) | 500 | 1.2 | Section headings |
| H3 / Subsection | Sans-serif | 1.25rem (20px) | 500 | 1.2 | Subsection headings |
| H4 | Sans-serif | 1.125rem (18px) | 500 | 1.2 | Card titles |
| H5 | Sans-serif | 1rem (16px) | 500 | 1.2 | Small section headings |
| H6 | Sans-serif | 0.875rem (14px) | 500 | 1.2 | Minimal heading |
| Body Standard | Sans-serif | 1rem (16px) | 400 | 1.5 | Default body text |
| Body Small | Sans-serif | 0.875rem (14px) | 400 | 1.5 | Table cell text, sidebar |
| Caption | Sans-serif | 0.75rem (12px) | 400 | 1.5 | Badges, labels, metrics |
| Code / Terminal | Monospace | 0.875em | 400 | 1.5 | Inline code, YAML blocks |
| Pre / Terminal Block | Monospace | 0.875em | 400 | 1.5 | xterm.js output, logs |
| Button Text | Sans-serif | 0.875rem (14px) | 400 | 1.5 | All button labels |
| Nav / Sidebar | Sans-serif | 0.875rem (14px) | 400 | 1.5 | Sidebar menu items |

### Principles
- **Consistent heading weights**: All headings use weight 500 — no bold variation between levels. Size alone drives hierarchy.
- **1.5 default line-height**: Generous body text line-height for readability in dense dashboards.
- **Monospace isolation**: Code and terminal output always uses the monospace stack — critical for log readability, YAML alignment, and terminal sessions.
- **System font stack**: Uses native fonts on every platform — no web font downloads, instant render, zero FOIT/FOUT.
- **Compact table text**: DataTables and list views default to 0.875rem for information density.

## 4. Component Stylings

### Buttons

**Primary**
- Background: `#5856d6`
- Text: `#ffffff`
- Border: `1px solid #5856d6`
- Radius: `0.375rem` (6px)
- Padding: `0.375rem 0.75rem`
- Hover: `#4645ab` background
- Focus: `0.25rem` indigo ring at 25% opacity
- Box-shadow: `0 0 0 0.25rem rgba(88, 86, 214, 0.25)`

**Secondary (Outline)**
- Background: transparent
- Text: `#6b7785`
- Border: `1px solid #6b7785`
- Hover: `#6b7785` background, `#ffffff` text
- Radius: `0.375rem`

**Success**
- Background: `#1b9e3e`, Text: `#ffffff`
- Hover: darker green

**Danger**
- Background: `#e55353`, Text: `#ffffff`
- Button text on dark surfaces: white
- Hover: darker red

**Ghost Variants** (CoreUI extension)
- Background: transparent, colored text matching semantic color
- Hover: light tint background with darker color
- Used for toolbar actions where prominence isn't needed

### Cards & Containers
- Background: `#ffffff` (light), `#323a49` (dark)
- Border: `1px solid #dbdfe6` (light), `1px solid #323a49` (dark)
- Radius: `0.375rem` (6px) — subtle, professional, not playful
- Header: `#f3f4f7` background, `1px solid #dbdfe6` bottom border
- Shadow: none by default, `0 0.5rem 1rem rgba(8, 10, 12, 0.15)` for elevated cards
- Footer: `1px solid #dbdfe6` top border, `#f3f4f7` background
- Body padding: `1rem` standard

### Tables & DataViews
- Header: `#f3f4f7` (light gray), weight 500, 0.875rem text
- Rows: white (odd), no alternating colors — relies on hover states instead
- Hover row: `#f3f4f7` background
- Striped rows: `#f3f4f7` background on even rows (optional via Bootstrap `.table-striped`)
- Borders: `1px solid #dbdfe6` between rows and columns
- Header borders: none between columns, `1px solid #dbdfe6` below header
- Sort icons: small chevrons in header cells
- Cell padding: `0.5rem 0.75rem` — compact for density
- Status badges: colored pills with semantic color background and white text
- Row click highlighting: subtle background change on selected row

### Sidebar Navigation
- Width: `256px` expanded, `64px` collapsed (icon-only)
- Background: `#212631` (dark navy — always dark regardless of page theme)
- Text: `rgba(255, 255, 255, 0.6)` inactive, `rgba(255, 255, 255, 0.87)` active
- Active item: `#5856d6` background highlight, white text
- Hover: `rgba(255, 255, 255, 0.05)` background tint
- Item height: `40px` per navigation item
- Icon size: `1.25rem` with CoreUI icon font (`cil-*` class prefix)
- Section headers: `0.65rem`, uppercase, `0.8px` letter-spacing, `rgba(255, 255, 255, 0.38)`
- Sub-menu: indented `1rem` with collapsible animation
- Sidebar border: `1px solid rgba(255, 255, 255, 0.1)` on right edge

### Header / TopBar
- Height: `64px` (standard CoreUI header)
- Background: `#ffffff` (light mode), `#212631` or `#323a49` (dark mode)
- Border-bottom: `1px solid #dbdfe6` (light), `1px solid #4a566d` (dark)
- Shadow: appears on scroll (added dynamically via JS)
- Breadcrumb: inline in header, `0.8rem` text, gray separators
- Namespace selector: dropdown with session persistence
- User menu: avatar/circle with dropdown for settings and logout
- Toggle sidebar button: hamburger or icon toggle
- Theme toggle: sun/moon icon button

### Forms & Inputs
- Background: `#ffffff`
- Border: `1px solid #cfd4de` (gray-400)
- Focus border: `1px solid #5856d6` with `0.25rem` indigo focus ring
- Radius: `0.375rem` (6px)
- Text: `#080a0c` (near black)
- Placeholder: `rgba(37, 43, 54, 0.38)` (tertiary emphasis)
- Height: `2.375rem` (38px) standard, `3rem` (48px) for `.form-control-lg`
- Select dropdown: caret icon on right, native browser picker
- Checkbox/Radio: `1rem` size, indigo active state
- Validation: green border/focus (`#1b9e3e`) for valid, red border/focus (`#e55353`) for invalid

### Modals & Dialogs
- Backdrop: `rgba(8, 10, 12, 0.5)` — 50% black overlay
- Modal background: `#ffffff`
- Border: `1px solid rgba(8, 10, 12, 0.2)`, `0.5rem` border-radius
- Shadow: `0 1rem 3rem rgba(8, 10, 12, 0.175)` (large shadow)
- Header: `border-bottom: 1px solid #dbdfe6`, padding `1rem 1rem 0.5rem`
- Footer: `border-top: 1px solid #dbdfe6`, padding `0.75rem 1rem`
- Close button: `×` icon, top-right corner
- Small modal: `300px` max-width, Medium: `500px`, Large: `800px`, XL: `1140px`

### Badges & Status Indicators
- Shape: pill (fully rounded corners with `border-radius: 50rem`)
- Padding: `0.35em 0.65em`
- Font-size: `0.75em` of parent, weight 500
- Colors matching semantic palette:
  - Success: `#1b9e3e` bg, white text
  - Warning: `#f9b115` bg, dark text (`#080a0c`)
  - Danger: `#e55353` bg, white text
  - Info: `#3399ff` bg, white text
  - Secondary: `#6b7785` bg, white text
- Outlined variant: transparent bg, colored border and text

### Alerts
- Border-left: `4px` solid semantic color
- Background: `#f3f4f7` base with tinted bg
- Icon: matching semantic color, left of heading
- Radius: `0.375rem`
- Padding: `1rem 1.25rem`
- Dismissible: close button on right

### Toasts
- Position: top-right corner (`position-fixed top-0 end-0 p-3`)
- Background: colored (`bg-success`, `bg-danger`, etc.) with white text
- Auto-hide: `5000ms`
- Stack: vertical stacking with overlap
- Radius: `0.375rem`
- Max-width: `350px`

### Tabs
- Active tab text: `#5856d6` with `border-bottom: 2px solid #5856d6`
- Inactive tab text: `#6d7d9c` (gray-600)
- Hover tab: `#5856d6` text with `border-bottom: 2px solid #5856d6`
- Tab padding: `0.5rem 1rem`
- Font-weight: 500 active, 400 inactive

### Progress Bars
- Background: `#e7eaee` (gray-200)
- Fill: semantic colors (success `#1b9e3e`, warning `#f9b115`, danger `#e55353`)
- Radius: `0.375rem`
- Height: `0.5rem` (8px) standard, `0.25rem` for thin variants
- Striped/animated animation available for loading states

### Terminal / xterm.js Components
- Background: `#000000` (pure black terminal surface)
- Text: white/light gray by default, xterm.js palette
- Border: `1px solid #dbdfe6` card border wrapping terminal
- Font: `SFMono-Regular, Menlo, Monaco, Consolas, monospace`
- Cursor: block, blinking
- Scrollback: 10,000 lines
- Terminal padding: card-body padding (1rem) around xterm container
- Addons loaded: FitAddon, WebLinksAddon, SearchAddon (v4.11.0)

## 5. Layout Structure

### Page Layout (Standard Admin)
```
┌─────────────────────────────────────────────────────────┐
│  Sidebar (256px)    │  Header (64px)                     │
│  ┌──────┐           │  ┌─────────────────────────────┐  │
│  │ Logo  │          │  │ Breadcrumb | NS | User Menu │  │
│  ├──────┤          │  └─────────────────────────────┘  │
│  │ Nav   │          │  ┌─────────────────────────────┐  │
│  │ Items │          │  │ Main Content Area            │  │
│  │       │          │  │                              │  │
│  │       │          │  │  Cards, Tables, Forms, etc.  │  │
│  │       │          │  │                              │  │
│  │       │          │  └─────────────────────────────┘  │
│  │       │          │                                   │
│  │       │          │  ┌──────┐                        │
│  └──────┘          │  │Footer│                        │
│                    │  └──────┘                        │
└─────────────────────────────────────────────────────────┘
```

### Content Area Pattern
- Page title at top (H1, `margin-bottom: 1rem`)
- Breadcrumb in header (auto-generated from route)
- Cards as primary content containers
- DataTables for list views (with server-side pagination, sorting, filtering)
- Form cards with header (title) + body (fields) + footer (actions)
- Two-column forms with label on left, input on right (at lg breakpoint)
- Charts in cards with header (title + actions) + body (chart canvas)
- Tabbed interfaces for multi-view resource pages

### Responsive Behavior
- Sidebar: collapses to icon-only (`64px`) on medium screens, overlay on mobile
- Tables: horizontal scroll on small screens (responsive table wrapper)
- Cards: stack vertically on mobile
- Forms: single-column on mobile, two-column on desktop
- Modals: full-width on mobile with top margin
- Charts: resize on window change (Chart.js responsive)

## 6. Iconography

### CoreUI Icons
- Font library: CoreUI Icons (`cil-*` class prefix)
- Size: `1.25rem` for sidebar navigation, `1rem` for inline use
- Color: inherits from parent text color
- Sidebar: icon + label layout, icons on left
- Action buttons: icon-only with tooltip on hover
- Status icons: colored dots (green/amber/red circles) for health indicators

### Status Dot Pattern
```html
<span class="bg-success" style="width: 10px; height: 10px; border-radius: 50%; display: inline-block;"></span>
```
- Green (`bg-success`): Running, Healthy, Ready
- Yellow (`bg-warning`): Pending, Warning, Degraded
- Red (`bg-danger`): Error, Failed, Critical
- Gray (`bg-secondary`): Unknown, Terminated, Stopped

## 7. Animation & Interaction

### Transitions
- Default transition: `0.3s ease` for color, background, border changes
- Sidebar toggle: `0.35s` slide animation
- Dropdown: `0.15s` fade-in
- Modal: `0.3s` fade-in with backdrop
- Toast: Bootstrap slide-in from right
- Button hover: instant color change (no transition)
- Card hover: no animation by default (static surfaces)

### Hover States
- Nav items: `rgba(255, 255, 255, 0.05)` background on dark sidebar
- Table rows: `#f3f4f7` background tint
- Links: underline + color shift to `#4645ab`
- Action buttons: darker shade of semantic color
- Card actions: opacity change on icon buttons

### Loading States
- Spinner: CoreUI spinner component with primary color
- Skeleton: not yet implemented — use spinner + "Loading..." text
- DataTable: server-side shows spinner in table body during AJAX calls
- Page transitions: full page reload, no SPA transitions

## 8. Dark Mode Implementation

### Theme System
- Mechanism: `data-coreui-theme` attribute on `<html>` element (`"light"` or `"dark"`)
- Persisted to: `localStorage` key `coreui-theme`
- Fallback: `light` if no localStorage value
- Flash prevention: inline `<script>` in `<head>` sets theme before body renders, uses `body { opacity: 0 !important; }` temporarily
- Toggle: handled by `js/color-modes.js` script

### Dark Mode Color Overrides
All semantic colors are overridden when `[data-coreui-theme="dark"]`:
- Primary: `#6261cc` (slightly lighter than light mode's `#5856d6`)
- Body text: `rgba(255, 255, 255, 0.87)` with `rgba(255, 255, 255, 0.6)` secondary
- Surface: `#212631` (bg) → `#323a49` (secondary) → `#2a303d` (tertiary)
- Success: `#249542` (brighter green for dark legibility)
- Info: `#3d99f5` (brighter blue)
- Warning: `#edad21` (brighter amber)
- Danger: `#db5d5d` (brighter red)
- Emphasis classes: `.dark\:text-*` variants for conditional rendering

## 9. Spacing & Sizing System

### Spacing Scale (CoreUI/Bootstrap)
Based on `0.25rem` (4px) unit:
- `0`: `0`
- `1`: `0.25rem` (4px)
- `2`: `0.5rem` (8px)
- `3`: `1rem` (16px)
- `4`: `1.5rem` (24px)
- `5`: `3rem` (48px)

### Common Layout Values
- Card body padding: `1rem` (16px)
- Card header/footer padding: `0.75rem 1rem`
- Section gap: `1.5rem` (24px) between cards
- Form field gap: `1rem` (16px) between groups
- Table cell padding: `0.5rem 0.75rem`
- Button gap: `0.5rem` between adjacent buttons

### Grid System
- Container max-width: `1320px` at `xxl` breakpoint (`1400px+`)
- Columns: 12-column flexbox grid
- Gutters: `1.5rem` (24px) horizontal
- Breakpoints: `sm(576px)`, `md(768px)`, `lg(992px)`, `xl(1200px)`, `xxl(1400px)`

## 10. Z-Index Layering

Standard CoreUI z-index scale:
- DataTables: `1`
- Dropdowns: `1000`
- Sticky header: `1020`
- Fixed-top: `1030`
- Toasts: `1080` (via inline `style="z-index: 11"`)
- Modal backdrop: `1040`
- Modal: `1050`
- Popovers: `1070`
- Tooltips: `1080`

## 11. Custom CSS Additions (kubedash)

Beyond CoreUI, KubeDash adds:
- `static/css/style.css` — CoreUI v5.2.0 customized build
- `static/vendor/custom/custom.css` — KubeDash-specific overrides and extensions
- Status badge extensions for Kubernetes-specific states
- Terminal container styling (card wrapper around xterm.js)
- DataTable customization (column reorder, export buttons)
- Resource usage bar visualization (CPU/memory inline progress bars)
- Node health indicators (colored dot patterns)
- Namespace dropdown styling in header
- Form POST handling for inline forms with CSRF tokens
- CSP nonce handling for inline scripts (`{{ csp_nonce }}`)
- Traceparent propagation for OpenTelemetry distributed tracing

## 12. Accessibility (a11y)

- ARIA labels on form controls and navigation
- `aria-live` regions for dynamic content (toasts)
- Keyboard navigation support (tab order follows DOM)
- Focus: 0.25rem indigo ring visible on all interactive elements
- Color contrast: WCAG AA compliant with adjusted dark mode palettes
- Screen reader: form labels associated via `for`/`id`, `aria-label` on icon-only buttons
- Skip to content: not yet implemented
- Reduced motion: respects `prefers-reduced-motion` for transitions