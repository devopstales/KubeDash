# UI style guide

Build a KubeDash screen with the pieces below.
The product intent is in [DESIGN.md](../DESIGN.md).
The same pieces are rendered in [style-guide.html](style-guide.html).
Open that file from this directory so it loads the local CoreUI stylesheet.

## Quick path

1. Put the breadcrumb and the page action in `TopMenu`.
2. Put the data in one `CCard` with `shadow mb-4`.
3. Use `KubeDataTable` for a list and `CTable` for one object's fields.
4. Use an icon for a header create action and for every row action.
5. Keep loading, empty, and error text inside the card body.

## Shell

The app is a full-height column: sidebar, two-row header, body, footer.

The first header row is shared.
It holds the sidebar toggle, namespace selector, docs links, notifications, theme, and account.
Do not add a page action there.

The second header row is the page.
`TopMenu` portals its children into that row.
Give the row `aria-label="breadcrumb"` on the breadcrumb.

```tsx
<TopMenu>
  <CBreadcrumb className="my-0" aria-label="breadcrumb">
    <CBreadcrumbItem>Cluster</CBreadcrumbItem>
    <CBreadcrumbItem active>Namespaces</CBreadcrumbItem>
  </CBreadcrumb>
  <CButton
    color="link"
    className="header-toggler ms-auto"
    type="button"
    aria-label="Add Namespace"
    title="Add Namespace"
    onClick={open}
  >
    <CIcon icon={cilPlus} size="lg" />
  </CButton>
</TopMenu>
```

Back and reload already sit at the right of that row.
Do not add another pair.

On an object page, earlier crumbs are links and the last crumb is the object name.

## Cards

```tsx
<CCard className="shadow mb-4">
  <CCardHeader className="py-3">
    <CCardTitle className="m-0 fw-bold text-primary fs-6">Namespace List</CCardTitle>
  </CCardHeader>
  <CCardBody>{/* states, then content */}</CCardBody>
</CCard>
```

User Management insets the card with `mx-4` and uses an `h6` title (`m-0 fw-bold text-primary`).
New cluster and security pages use the `CCardTitle` form above, without `mx-4`.

One card per page.
A second card is a different task, not a section of the same list.

## Lists

Render lists through `KubeDataTable`.
Do not mount a second DataTables skin or a hand-rolled pager.

| Setting | Value |
| --- | --- |
| Component | `frontend/src/components/KubeDataTable.tsx` |
| Skin | `datatables.net-bs5` |
| Class | `table table-bordered` |
| Page length | 25 |
| Responsive | on |

Column order is status, name, the resource-specific fields, created, then Action.
The name links to the object page.
The link text is the object name.

```tsx
<Column title="Namespace" data="name">
  {(namespace: string) => (
    <Link to={`/cluster/namespace/data?name=${encodeURIComponent(namespace)}`}>
      {namespace}
    </Link>
  )}
</Column>
```

An external URL is an `<a>` only when the scheme is `http:` or `https:`.
Anything else renders an em dash.

Object pages use `CTable` with `bordered`.
Key/value blocks add `small` and `mb-0`.
Long values use `text-break`.

## Buttons

| Place | Look | Label |
| --- | --- | --- |
| Header create | `color="link"`, `header-toggler ms-auto`, icon `size="lg"` | `aria-label` and `title` are the action, such as "Add Namespace" |
| Row delete | `color="danger"` `size="sm"`, `cilTrash` | `title="Delete"`, `aria-label={`Delete ${name}`}` |
| Row edit | `color="success"` `size="sm"`, `cilPencil` | `title="Edit"`, `aria-label={`Edit ${name}`}` |
| Row navigate | `btn btn-secondary btn-sm`, one icon | `title` is the verb, `aria-label` includes the name |
| Dialog dismiss | `color="secondary"`, text "Close" | visible text |
| Dialog submit | `color="primary"`, text is the action | visible text, disabled until the form is valid |
| Card-header command | `color="secondary"` `size="sm"`, icon plus words | visible text, for example "Sync from SSO" |

Several row actions sit in `d-flex flex-row gap-1`.
One row action does not need the wrapper.

A header action is icon-only.
Do not put a primary text button such as "Add Namespace" in the header.
The same words belong on the dialog submit button.

Hide an action the user cannot perform.
Do not render it disabled.

Set `type="button"` on every button that is not a form submit.

## Icons

Import icons from `@coreui/icons` and render them with `CIcon`.
Do not use an icon font, an emoji, or an inline image.

| Intent | Icon |
| --- | --- |
| Add | `cilPlus` |
| Add a user | `cilUserPlus` |
| Delete | `cilTrash` |
| Edit | `cilPencil` |
| Privileges | `cilBadge` |
| Refresh a data set | `cilSync` |

## Status and feedback

| State | Markup |
| --- | --- |
| Healthy | `<CBadge color="success">` |
| Other phase | `<CBadge color="secondary">`, or `danger` on an object page when the phase is not Active |
| Loading | `Loading namespaces...` inside the card body |
| Empty | `text-center text-muted`, "No namespaces found" |
| Error | `text-danger`, include the server message |
| Missing selection | Plain text, "No cluster selected." |

Do not use `window.alert`.
A destructive row action may use `window.confirm` with the object name in the question.

Mutation errors render under the table as `text-danger mt-3`.
They stay on the page after the dialog closes.

## Dialogs

```tsx
<CModal visible={open} alignment="center" onClose={close} aria-labelledby="add-namespace-title">
  <CForm onSubmit={submit}>
    <CModalHeader>
      <CModalTitle id="add-namespace-title">New Namespace</CModalTitle>
    </CModalHeader>
    <CModalBody>{/* fields */}</CModalBody>
    <CModalFooter>
      <CButton type="button" color="secondary" onClick={close}>
        Close
      </CButton>
      <CButton type="submit" color="primary" disabled={!valid || pending}>
        {pending ? 'Saving…' : 'Add Namespace'}
      </CButton>
    </CModalFooter>
  </CForm>
</CModal>
```

One column of fields.
Each label sits above its control.
Invalid input uses the CoreUI `invalid` state.
Helper text is `small text-muted`.

## Color and type

Use CoreUI theme tokens (`--cui-*`, `text-primary`, `text-danger`, `text-muted`).
Do not set a one-off hex color on a product screen.
The snippet block `.kd-snippet` is the exception for a code sample.

Card titles use `fw-bold text-primary`.
Body copy stays the CoreUI default.
Do not load a webfont.

## Checklist

- [ ] Breadcrumb and header action are in `TopMenu`, not the first header row.
- [ ] The create control is an icon button with `aria-label` and `title`.
- [ ] The list uses `KubeDataTable` inside one shadowed card.
- [ ] The name column links to the object page.
- [ ] Row actions are icons with a verb tooltip and an object-specific accessible name.
- [ ] Loading, empty, and error states are inside the card.
- [ ] The dialog submit button uses words. Close is secondary.
- [ ] No Tailwind, no CDN URL, no new color.
