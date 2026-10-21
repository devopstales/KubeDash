import { create } from 'zustand'

/**
 * Selection store: which cluster the user is currently viewing.
 * `useCluster()` populates it from `/api/v1/clusters` on mount; the
 * Header cluster switcher and the Cluster view both read from it.
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

export const useClusterStore = create<ClusterStore>()((set) => ({
  selectedCluster: null,
  setSelectedCluster: (selectedCluster) => set({ selectedCluster }),
  selectedNamespace: null,
  setSelectedNamespace: (selectedNamespace) => set({ selectedNamespace }),
}))
