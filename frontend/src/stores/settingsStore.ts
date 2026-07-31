import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

export interface SettingsState {
  verboseLogging: boolean;
  toggleVerboseLogging: () => void;
  maxNodes: number;
  setMaxNodes: (n: number) => void;
  maxConnectionsPerNode: number;
  setMaxConnectionsPerNode: (n: number) => void;
}

const defaultSettings = {
  verboseLogging: false,
  maxNodes: 150,
  maxConnectionsPerNode: 10,
};

const SETTINGS_VERSION = 6;

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      ...defaultSettings,
      toggleVerboseLogging: () => set((state) => ({ verboseLogging: !state.verboseLogging })),
      setMaxNodes: (n) => set({ maxNodes: n }),
      setMaxConnectionsPerNode: (n) => set({ maxConnectionsPerNode: Math.max(1, Math.min(150, n)) }),
    }),
    {
      name: 'display-settings-storage',
      version: SETTINGS_VERSION,
      storage: createJSONStorage(() => localStorage),
      migrate: (persistedState: any, version: number) => {
        if (version < SETTINGS_VERSION) {
          return { ...defaultSettings };
        }
        return {
          ...defaultSettings,
          ...persistedState,
          maxConnectionsPerNode: Math.max(1, Math.min(150, persistedState?.maxConnectionsPerNode ?? 10)),
        };
      },
    }
  )
);
