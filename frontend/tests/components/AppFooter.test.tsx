import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import AppFooter from '../../src/components/AppFooter'

test('footer-shows-4-1-labels', () => {
  render(<AppFooter />)
  expect(screen.getByText('DevOpsTales - KubeDash Copyright © 2021-2026')).toBeTruthy()
  expect(screen.getByText('Powered by CoreUI UI Components')).toBeTruthy()
})

test('footer-has-no-outbound-link', () => {
  const { container } = render(<AppFooter />)
  expect(container.querySelectorAll('a')).toHaveLength(0)
})
