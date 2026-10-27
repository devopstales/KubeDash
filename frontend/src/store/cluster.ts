import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'

/**
 * Selection store: which cluster the user is currently viewing.
 * `useCluster()` populates it from `/api/v1/clusters` on mount; the
 * Header cluster switcher and the Cluster view both read from it.
 *
 * Persistence (4.1 `session['ns_select']` parity): `selectedCluster` +
 * `selectedNamespace` survive a page reload via `localStorage`
 * (key `kd-cluster-scope`, synchronous JSON storage). The store persists
 * the raw values — it has no namespace list — so the header's
 * `preferredNamespace` fallback chain (`selectedNamespace` → `default` →
 * first entry) re-validates a stale ns on boot. The per-cluster scope is
 * deliberate: the persisted namespace is only meaningful relative to the
 * cluster it was selected on.
 */
export interface SelectedCluster {
  id: number
  name: string
}

interface ClusterStore {
  selectedCluster: SelectedCluster | null
  setSelectedCluster: (c: SelectedCluster | null) => void
  /** Header scope, matching 4.1's session `ns_select`. */
  selectedNamespace: string | null
  setSelectedNamespace: (namespace: string | null) => void
}

export const useClusterStore = create<ClusterStore>()(
  persist(
    (set) => ({
      selectedCluster: null,
      setSelectedCluster: (selectedCluster) => set({ selectedCluster }),
      selectedNamespace: null,
      setSelectedNamespace: (selectedNamespace) => set({ selectedNamespace }),
    }),
    {
      name: 'kd-cluster-scope',
      storage: createJSONStorage(() => localStorage),
      partialize: (s) => ({
        selectedCluster: s.selectedCluster,
        selectedNamespace: s.selectedNamespace,
      }),
    },
  ),
)
