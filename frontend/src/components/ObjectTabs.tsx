import React, { useState } from 'react'

export type ObjectTab = { key: string; label: string }

/**
 * Button-based object-type tab bar for the /network/* list pages — the
 * CoreUI Bootstrap navs-tabs button pattern
 * (coreui.io/bootstrap/docs/components/navs-tabs/), the same markup 4.1
 * uses in /workload/pods/data and the ELB plugin page (a `nav nav-tabs`
 * list of `button.nav-link` toggles over a `tab-content` of panes).
 *
 * Replaces CoreUI React's CTabs on these pages: @coreui/react 5.13
 * renders the newer `div.tabs` markup, which the @coreui/coreui 5.9
 * stylesheet does not style — the labels render as a stacked column of
 * plain text. The classic `nav nav-tabs` markup is styled by the bundled
 * stylesheet and renders as the 4.1-style horizontal button bar.
 *
 * Like CTabPanel, every panel stays mounted (the fetch-on-mount contract
 * the view tests assert on).
 */
const ObjectTabs = ({
  tabs,
  children,
  activeKey,
  defaultActiveKey,
  onChange,
}: {
  tabs: ObjectTab[]
  /** One ReactNode per tab, in `tabs` order; all panels stay mounted. */
  children: React.ReactNode[]
  /** Controlled: the currently active key (overrides the internal state). */
  activeKey?: string
  /** Uncontrolled: the initially active key (defaults to the first tab). */
  defaultActiveKey?: string
  /** Called when a tab button is clicked (controlled and uncontrolled). */
  onChange?: (key: string) => void
}) => {
  const [internalKey, setInternalKey] = useState(defaultActiveKey ?? tabs[0]?.key)
  const active = activeKey ?? internalKey

  const select = (key: string) => {
    if (activeKey === undefined) setInternalKey(key)
    onChange?.(key)
  }

  return (
    <>
      <ul className="nav nav-tabs" role="tablist">
        {tabs.map((tab) => (
          <li className="nav-item" role="presentation" key={tab.key}>
            <button
              type="button"
              role="tab"
              id={`${tab.key}-tab`}
              className={active === tab.key ? 'nav-link active' : 'nav-link'}
              aria-selected={active === tab.key}
              aria-controls={`${tab.key}-tabpanel`}
              onClick={() => select(tab.key)}
            >
              {tab.label}
            </button>
          </li>
        ))}
      </ul>
      <div className="tab-content">
        {tabs.map((tab, i) => (
          <div
            key={tab.key}
            role="tabpanel"
            id={`${tab.key}-tabpanel`}
            aria-labelledby={`${tab.key}-tab`}
            className={active === tab.key ? 'tab-pane active show' : 'tab-pane'}
          >
            {children[i]}
          </div>
        ))}
      </div>
    </>
  )
}

export default ObjectTabs
