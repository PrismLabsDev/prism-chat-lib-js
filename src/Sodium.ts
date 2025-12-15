import _sodium from "libsodium-wrappers-sumo";

export type Sodium = typeof _sodium;

let instance: Sodium | null = null;

// Top-level async initialization
export const sodiumReady: Promise<typeof _sodium> = (async (): Promise<typeof _sodium> => {
  await _sodium.ready;   // wait for WASM to load
  instance = _sodium;
  return instance;
})();

// Optional synchronous getter after initialization
export function getSodium(): typeof _sodium {
  if (!instance) throw new Error("Sodium not initialized yet. Await sodiumReady first.");
  return instance;
}
