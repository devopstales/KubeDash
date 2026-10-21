# KubeDash UI

KubeDash is a dense operator console on the CoreUI shell.
New screens follow that shell and [frontend/STYLEGUIDE.md](frontend/STYLEGUIDE.md).
They do not introduce a second visual system.

## Decisions

| Topic | Rule |
| --- | --- |
| Shell | CoreUI React. Sidebar, header, cards, buttons, and modals stay CoreUI. |
| Lists | `KubeDataTable`: DataTables React with the Bootstrap 5 skin. |
| Styling | CoreUI SCSS and utility classes. No Tailwind. |
| Assets | Bundled in the image. No CDN fonts, scripts, or stylesheets. |
| Reference | 4.1 screens are the visual reference. React views are the implementation. |
| Theme | Light, dark, and auto come from CoreUI color modes. |
| Catalog | `frontend/style-guide.html` renders the live specimens with the installed CoreUI CSS. |

The locked records are ADR-0005 (CoreUI), ADR-0020 (air gap), and ADR-0023 (DataTables).

## Principles

1. Operators scan tables.
   Chrome stays quiet so status, name, and actions stay easy to find.
2. Create is an icon in the page header.
   The dialog that confirms the create action uses words.
3. A row action is an icon.
   The accessible name includes the object.
   The tooltip is the verb.
4. One page has one card and one title.
5. Status is a badge.
   Errors and empty results are inline text on the page.
6. Color comes from CoreUI.
   Do not add a second accent, a custom font, or a marketing layout.

## Page types

**List.**
Breadcrumb and header action in the second header row.
One shadowed card.
A short title, then the table.

**Object.**
The same card.
The breadcrumb adds the object name and links back to the list.
Fields sit in a bordered table.
There is no second create button.

**Dialog.**
Centered modal for a short create or edit form.
Close is secondary.
The submit button repeats the action in words.

## Out of scope

Landing pages, illustrations, and new component libraries.
The CoreUI example views under `frontend/src/views/components/` are template leftovers.
Product screens live in feature folders such as `views/Cluster/` and `views/AdminPermissions/`.
