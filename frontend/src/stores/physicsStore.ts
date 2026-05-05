import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

export interface PhysicsSettings {
  connectionPullStrength: number;
  collisionRepulsion: number;
  damping: number;
  connectionLifetime: number;
  nodeLifetime: number;
  nodeSpacing: number;
  driftAwayStrength: number;
  centerPullStrength: number;
  springRestLength: number;
  setConnectionPullStrength: (v: number) => void;
  setCollisionRepulsion: (v: number) => void;
  setDamping: (v: number) => void;
  setConnectionLifetime: (v: number) => void;
  setNodeLifetime: (v: number) => void;
  setNodeSpacing: (v: number) => void;
  setDriftAwayStrength: (v: number) => void;
  setCenterPullStrength: (v: number) => void;
  setSpringRestLength: (v: number) => void;
  resetPhysicsDefaults: () => void;
}

const defaultPhysics = {
  connectionPullStrength: 1.80, // strong pull so connected nodes cluster tight
  collisionRepulsion: 0.08,
  damping: 0.8,
  connectionLifetime: 5000,
  nodeLifetime: 15000,
  nodeSpacing: 75,              // minDist = 10+10+75 = 95px — readable node separation
  driftAwayStrength: 2.4,       // quiet nodes reach the edge before their 15s fade expires
  centerPullStrength: 0.0030,   // keeps active topology clustered in the center
  springRestLength: 55,         // short lines — connected nodes sit close together
}

// Increment to force-reset localStorage when defaults change
const PHYSICS_VERSION = 18;

export const usePhysicsStore = create<PhysicsSettings>()(
  persist(
    (set) => ({
      ...defaultPhysics,
      setConnectionPullStrength: (v) => set({ connectionPullStrength: v }),
      setCollisionRepulsion: (v) => set({ collisionRepulsion: v }),
      setDamping: (v) => set({ damping: v }),
      setConnectionLifetime: (v) => set({ connectionLifetime: v }),
      setNodeLifetime: (v) => set({ nodeLifetime: v }),
      setNodeSpacing: (v) => set({ nodeSpacing: v }),
      setDriftAwayStrength: (v) => set({ driftAwayStrength: v }),
      setCenterPullStrength: (v) => set({ centerPullStrength: v }),
      setSpringRestLength: (v) => set({ springRestLength: v }),
      resetPhysicsDefaults: () => set({ ...defaultPhysics }),
    }),
    {
      name: 'physics-settings-storage',
      version: PHYSICS_VERSION,
      storage: createJSONStorage(() => localStorage),
      migrate: (persistedState: any, version: number) => {
        if (version < PHYSICS_VERSION) {
          return { ...defaultPhysics };
        }
        return persistedState;
      },
    }
  )
)
