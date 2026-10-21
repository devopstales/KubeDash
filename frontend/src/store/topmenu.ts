import { create } from 'zustand'

type TopMenuStore = {
  slot: HTMLElement | null
  setSlot: (slot: HTMLElement | null) => void
}

export const useTopMenuStore = create<TopMenuStore>()((set) => ({
  slot: null,
  setSlot: (slot) => set({ slot }),
}))
