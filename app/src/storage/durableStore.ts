/**
 * Durable, restart-safe persistence for receipts and merchant identity.
 *
 * The requirement is the original one: receipt history and verification state
 * must survive a process restart (delegation plan gate 9), so the app binds the
 * `KeyValueStore` port to the platform's own storage rather than to memory.
 *
 * The backing store is resolved in this order:
 *
 *   1. a storage adapter injected by the host (tests, or a different backend);
 *   2. `@react-native-async-storage/async-storage`, the established React Native
 *      key-value store, when it is installed;
 *   3. nothing, and then this module FAILS LOUDLY.
 *
 * There is deliberately no silent fallback to an in-memory store: a receipt that
 * appears saved but vanishes on restart is worse than a visible failure, because
 * it misrepresents the one property (durability) the user cannot verify by
 * looking at the screen. `MemoryKeyValueStore` still exists for tests, but the
 * app never selects it on its own.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import type {KeyValueStore} from './receiptStore';

/** The AsyncStorage surface this module uses (structural, so no hard dependency). */
interface AsyncStorageLike {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

let injected: KeyValueStore | null = null;

/** Install a store from the host. Tests use this; the app does not. */
export function setDurableStore(store: KeyValueStore | null): void {
  injected = store;
}

/**
 * AsyncStorage is a COMMITTED dependency, so it is imported statically. A
 * `require()` guarded by try/catch would be worse than useless: Metro resolves
 * static requires at bundle time, so the guard would either fail the build or be
 * untestable dead code. The real failure mode worth reporting is the NATIVE
 * module missing from a build that installed the JS package — that is what the
 * capability probe below catches, at runtime, once.
 */
function resolveAsyncStorage(): AsyncStorageLike | null {
  const candidate: unknown = AsyncStorage;
  if (
    typeof candidate === 'object' &&
    candidate !== null &&
    typeof (candidate as AsyncStorageLike).getItem === 'function' &&
    typeof (candidate as AsyncStorageLike).setItem === 'function' &&
    typeof (candidate as AsyncStorageLike).removeItem === 'function'
  ) {
    return candidate as AsyncStorageLike;
  }
  return null;
}

/** True when a durable backend is available. */
export function hasDurableStore(): boolean {
  return injected !== null || resolveAsyncStorage() !== null;
}

/**
 * The name of the resolved backend, for the UI to report honestly. `unavailable`
 * means the JS package is present but the native module is not — the state a
 * build that skipped its pod install / Gradle sync lands in.
 */
export function durableStoreName(): string {
  if (injected !== null) {
    return 'injected';
  }
  return resolveAsyncStorage() !== null ? 'async-storage' : 'unavailable';
}

class AsyncStorageKeyValueStore implements KeyValueStore {
  constructor(private readonly storage: AsyncStorageLike) {}

  async get(key: string): Promise<string | null> {
    return this.storage.getItem(key);
  }

  async set(key: string, value: string): Promise<void> {
    await this.storage.setItem(key, value);
  }

  async remove(key: string): Promise<void> {
    await this.storage.removeItem(key);
  }
}

/**
 * The app's store. Throws when no durable backend exists rather than degrading
 * to memory, so a misconfigured build is reported instead of pretending.
 */
export function resolveDurableStore(): KeyValueStore {
  if (injected !== null) {
    return injected;
  }
  const storage = resolveAsyncStorage();
  if (storage === null) {
    throw new Error(
      'no durable storage backend: install @react-native-async-storage/async-storage (receipt history must survive restart)',
    );
  }
  return new AsyncStorageKeyValueStore(storage);
}
