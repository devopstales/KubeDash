import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import AppFooter from '../../src/components/AppFooter'

test('footer-shows-4-1-links', () => {
  render(<AppFooter />)
  expect(screen.getByRole('link', { name: 'DevOpsTales' }).getAttribute('href')).toBe(
    'https://devopstales.github.io',
  )
  expect(screen.getByRole('link', { name: 'KubeDash' }).getAttribute('href')).toBe(
    'https://devopstales.github.io/KubeDash/latest/',
  )
  expect(screen.getByRole('link', { name: 'CoreUI UI Components' }).getAttribute('href')).toBe(
    'https://coreui.io/docs/',
  )
  expect(screen.getByText(/Copyright © 2021-2026/)).toBeTruthy()
})
