import { create } from 'zustand'

type SidebarStore = {
  visible: boolean
  toggle: () => void
  setVisible: (visible: boolean) => void
}

export const useSidebarStore = create<SidebarStore>()((set) => ({
  visible: true,
  toggle: () => set((state) => ({ visible: !state.visible })),
  setVisible: (visible) => set({ visible }),
}))
