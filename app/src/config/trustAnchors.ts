/**
 * The pinned trust anchor set the app ships.
 *
 * This is the PoC's single trust root and it is PUBLIC material: the anchor id
 * and the Ed25519 public key, no private half (trust.md §3). The value is
 * copied from `protocol/vectors/fixtures/trust-anchors-v1.json` so a reader can
 * diff it against the frozen vector without running anything.
 *
 * The repository is public and the root is an explicitly-labelled TEST root.
 * Its private half exists only in `protocol/vectors/keys/test-keys.json` for the
 * harness; a production build MUST NOT trust it, and MUST NOT bundle any test
 * private key (conformance B9, docs/protocol/trust.md §3).
 *
 * Replacing this with a production root is a provisioning change, not a code
 * change: the anchor set is data handed to the adapter.
 */

import type {TrustAnchor} from '../native/DeceiptNative';

export const TEST_ROOT_ANCHOR_ID_HEX = '0decea00000000000000000000000001';
export const TEST_ROOT_PUBLIC_KEY_HEX = 'bd65615aed2e3adf4f91e8fccfd7b54d44e532456399115b33456d72668a87cb';

/** Public anchors only. `publicKeyB64` is the same key, base64-encoded. */
export const TRUST_ANCHORS: TrustAnchor[] = [
  {
    anchorIdHex: TEST_ROOT_ANCHOR_ID_HEX,
    publicKeyB64: 'vWVhWu0uOt9Pkej8z9e1TUTlMkVjmRFbM0VtcmaKh8s=',
    label: 'Deceipt PoC Test Root 1',
  },
];
