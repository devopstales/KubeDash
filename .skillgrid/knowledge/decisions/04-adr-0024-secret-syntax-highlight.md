# Secret values: react-syntax-highlighter with the an-old-hope theme

---
status: "accepted"
date: 2026-10-21
supersedes: none
---

**Decision-makers.** paladm (project owner)
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash 4.1 renders a revealed secret value through highlight.js
(`segments/components/highlight_snippet.html.j2`, theme `an-old-hope`).
Language comes from the key and the decoded text: json, yaml, xml,
javascript, or plaintext for keys, certs, and PEM (`-----BEGIN`).
The React secret page showed the decoded text in an unstyled `<code>`
element. highlight.js is a script-tag library. The secret page needs a
React component, bundled for air-gap (ADR-0020), with the same theme and
the same language choice.

`monaco-editor` is already a dependency, for diffs. An editor chrome
around a secret value is the wrong control.

#### Decision Drivers

- Revealed secret values should look like the 4.1 highlight.js block
- The component must be React, and the grammars and theme must ship in the bundle
- Only the languages 4.1 actually selected: json, yaml, xml, javascript
- PEM and other plaintext stay one color on that theme, as 4.1 did
- The value stays out of the DOM until the reveal button is pressed

#### Considered Options

- `react-syntax-highlighter` light build, highlight.js grammars, `an-old-hope`
- `prism-react-renderer`
- highlight.js called from a `useEffect`
- `monaco-editor` read-only

#### Decision Outcome

Chosen option: "`react-syntax-highlighter` light build with the highlight.js
grammars and the `an-old-hope` theme", because it is a React component, it
is the theme 4.1 loaded, and the light build registers four languages
instead of the full grammar set.

`SecretData` calls `secretLanguage` with the same rules as 4.1
`detectLanguage`. A hit passes that language. A miss renders plaintext on
the same theme. The hidden placeholder is not passed through the highlighter.

##### Consequences

- Good, because a revealed certificate, JSON blob, or manifest gets the
  4.1 dark block, and json, yaml, xml, and javascript are colored
- Good, because styles are inline objects. No CDN stylesheet (ADR-0020)
- Bad, because `react-syntax-highlighter` and
  `@types/react-syntax-highlighter` are new dependencies
- Neutral, because the export page keeps its plain `.kd-snippet` block.
  This ADR covers secret values only

##### Confirmation

- `frontend/package.json` depends on `react-syntax-highlighter`
- A revealed secret renders a `pre` with the an-old-hope background
- `secretLanguage('ca.crt', '-----BEGIN CERTIFICATE-----…')` is plaintext
- The hidden value is still the placeholder, not the decoded secret

#### Pros and Cons of the Options

##### `react-syntax-highlighter` light + an-old-hope (chosen)

- Good, because the theme and the grammars are the ones 4.1 used
- Good, because the light build does not bundle every language
- Bad, because it is a new dependency

##### `prism-react-renderer`

- Good, because it is a small React renderer
- Bad, because Prism has no an-old-hope theme, so the block would not match 4.1

##### highlight.js from a `useEffect`

- Good, because it is the same library 4.1 called
- Bad, because it highlights by mutating the DOM, which fights React

##### `monaco-editor` read-only

- Good, because the dependency is already present
- Bad, because it mounts an editor, not the 4.1 code block

#### More Information

- 4.1 include: branch `4.1`,
  `src/kubedash/templates/segments/components/highlight_snippet.html.j2`
  and `detectLanguage` in `security/secret-data.html.j2`
- Theme file: `react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope`
