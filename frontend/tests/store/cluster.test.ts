import { beforeEach, describe, expect, test, vi } from 'vitest'

const STORAGE_KEY = 'kd-cluster-scope'

// zustand persist v5 wraps the partialized state: {"state": {...}, "version": 0}.
// Read the wrapper; assert on `state` so tests don't couple to the wrapper.
const readStored = (): { state: Record<string, unknown>; version: number } | null => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (raw == null) return null
  return JSON.parse(raw)
}

// The "new tab / reload" path: seed localStorage, then import the store with a
// fresh module registry so it rehydrates from storage at module init.
const freshImport = async (query: string) => {
  vi.resetModules()
  const mod = await import(`../../src/store/cluster${query}`)
  return mod.useClusterStore.getState()
}

describe('useClusterStore persistence', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.resetModules()
  })

  test('persists selectedCluster + selectedNamespace to localStorage', async () => {
    const { useClusterStore } = await import('../../src/store/cluster')
    useClusterStore.getState().setSelectedCluster({ id: 1, name: 'kind' })
    useClusterStore.getState().setSelectedNamespace('team-a')

    const stored = readStored()
    expect(stored?.state).toEqual({
      selectedCluster: { id: 1, name: 'kind' },
      selectedNamespace: 'team-a',
    })
  })

  test('partialize: actions are not persisted', async () => {
    const { useClusterStore } = await import('../../src/store/cluster')
    useClusterStore.getState().setSelectedCluster({ id: 1, name: 'kind' })

    const stored = readStored()
    expect(stored?.state).not.toHaveProperty('setSelectedCluster')
    expect(stored?.state).not.toHaveProperty('setSelectedNamespace')
  })

  test('rehydrates into a fresh module instance from localStorage', async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        state: { selectedCluster: { id: 2, name: 'prod' }, selectedNamespace: 'kube-system' },
        version: 0,
      }),
    )

    const s = await freshImport('?reload')
    expect(s.selectedCluster).toEqual({ id: 2, name: 'prod' })
    expect(s.selectedNamespace).toBe('kube-system')
  })

  test('corrupted localStorage entry yields the empty initial state', async () => {
    localStorage.setItem(STORAGE_KEY, 'not-json')

    const s = await freshImport('?corrupt')
    expect(s.selectedCluster).toBeNull()
    expect(s.selectedNamespace).toBeNull()
  })

  test('selectedNamespace: null round-trips as null (Namespaces delete path)', async () => {
    const { useClusterStore } = await import('../../src/store/cluster')
    useClusterStore.getState().setSelectedCluster({ id: 1, name: 'kind' })
    useClusterStore.getState().setSelectedNamespace('team-a')
    useClusterStore.getState().setSelectedNamespace(null)

    const stored = readStored()
    expect(stored).not.toBeNull()
    expect(stored?.state.selectedNamespace).toBeNull()
  })
})
