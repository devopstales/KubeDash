import React from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, test, vi } from 'vitest'
import TopMenu, { TopMenuNav } from '../../src/components/TopMenu'
import { useTopMenuStore } from '../../src/store/topmenu'

describe('TopMenu', () => {
  afterEach(() => {
    useTopMenuStore.setState({ slot: null })
    vi.unstubAllGlobals()
  })

  test('page-content-renders-into-the-header-slot', () => {
    const slot = document.createElement('div')
    document.body.appendChild(slot)
    useTopMenuStore.setState({ slot })
    render(<TopMenu>Users crumb</TopMenu>)
    expect(slot.textContent).toContain('Users crumb')
    slot.remove()
  })

  test('back-goes-to-the-previous-page', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/clusters', '/admin/permissions']} initialIndex={1}>
        <TopMenuNav />
        <Routes>
          <Route path="/clusters" element={<div>Clusters page</div>} />
          <Route path="/admin/permissions" element={<div>Users page</div>} />
        </Routes>
      </MemoryRouter>,
    )
    await user.click(screen.getByRole('link', { name: 'Back' }))
    expect(await screen.findByText('Clusters page')).toBeTruthy()
  })

  test('a-separator-precedes-back-and-reload', () => {
    const { container } = render(
      <MemoryRouter>
        <TopMenuNav />
      </MemoryRouter>,
    )
    const nav = container.querySelector('.header-nav')
    const rule = nav?.querySelector('.header-nav-separator')
    expect(rule).toBeTruthy()
    expect(nav?.firstElementChild).toBe(rule)
    expect((rule as HTMLElement).style.height).toBe('1.25rem')
  })

  test('reload-reloads-the-page', async () => {
    const user = userEvent.setup()
    const reload = vi.fn()
    vi.stubGlobal('location', { ...window.location, reload })
    render(
      <MemoryRouter>
        <TopMenuNav />
      </MemoryRouter>,
    )
    await user.click(screen.getByRole('button', { name: /reload page/i }))
    expect(reload).toHaveBeenCalled()
  })
})
