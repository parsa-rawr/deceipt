/**
 * Dev-only merchant provisioning.
 *
 * Without this, a freshly installed app has no signing key: `merchantKeyStatus`
 * reports `provisioned: false`, `assertMerchantReady` fails, and merchant mode
 * can never render a checkout code. That is correct for a production build and
 * fatal for the PoC demo, so the demo needs an explicit bootstrap.
 *
 * The guards are the point of this module:
 *
 *  * it runs ONLY when the adapter itself reports `testProvisioningEnabled`,
 *    which a production build must report `false` (docs/protocol/trust.md §3,
 *    conformance B9);
 *  * the key material is the PUBLISHED, LABELLED test seed and the frozen test
 *    credential. They are public by construction and worthless outside the
 *    vector set; nothing here is, or derives from, a production trust root;
 *  * it never invents a key. If the published material is not what the build
 *    carries, the bootstrap reports that instead of substituting something.
 *
 * A production build replaces this with real enrollment (out of PoC scope).
 */

import type {DeceiptNative, MerchantKeyStatus} from '../native/DeceiptNative';
import {base64Encode, hexDecode} from '../protocol/bytes';
import {
  TEST_MERCHANT_CREDENTIAL_HEX,
  TEST_MERCHANT_DEVICE_KEY_ID_HEX,
  TEST_MERCHANT_DEVICE_SEED_HEX,
} from './testMerchantMaterial';

export interface ProvisionOutcome {
  ok: boolean;
  /** `true` when the adapter already had a key; nothing was imported. */
  alreadyProvisioned: boolean;
  /** Why the bootstrap did not run, when it did not. */
  reason?: string;
  status?: MerchantKeyStatus;
}

/**
 * Import the published test merchant key and credential, if the adapter allows
 * it. Idempotent: an adapter that is already provisioned is left untouched.
 */
export async function ensureDemoMerchant(native: DeceiptNative): Promise<ProvisionOutcome> {
  let capabilities;
  try {
    capabilities = await native.capabilities();
  } catch (error) {
    return {ok: false, alreadyProvisioned: false, reason: `capabilities unavailable: ${describe(error)}`};
  }
  if (!capabilities.testProvisioningEnabled) {
    return {
      ok: false,
      alreadyProvisioned: false,
      reason: 'this adapter does not allow test provisioning (production build)',
    };
  }
  if (!capabilities.ed25519) {
    return {ok: false, alreadyProvisioned: false, reason: 'the adapter cannot sign (no Ed25519)'};
  }
  const existing = await native.merchantKeyStatus();
  if (existing.provisioned) {
    return {ok: true, alreadyProvisioned: true, status: existing};
  }

  const provisioned = await provisionTestMerchant(native);
  return provisioned;
}

/**
 * Call the gated `testProvisioning` entry point when the adapter exposes it.
 * The contract keeps it off the main interface on purpose, so it is reached by a
 * narrow structural check rather than by widening `DeceiptNative`.
 */
async function provisionTestMerchant(native: DeceiptNative): Promise<ProvisionOutcome> {
  const candidate: unknown = native;
  if (typeof candidate !== 'object' || candidate === null) {
    return {ok: false, alreadyProvisioned: false, reason: 'the adapter exposes no test provisioning'};
  }
  const provisioning: unknown = (candidate as {testProvisioning?: unknown}).testProvisioning;
  if (typeof provisioning !== 'object' || provisioning === null) {
    return {ok: false, alreadyProvisioned: false, reason: 'the adapter exposes no test provisioning'};
  }
  const provision = (provisioning as {provisionTestMerchant?: unknown}).provisionTestMerchant;
  if (typeof provision !== 'function') {
    return {ok: false, alreadyProvisioned: false, reason: 'the adapter exposes no provisionTestMerchant'};
  }
  try {
    const status = (await (provision as (request: unknown) => Promise<MerchantKeyStatus>).call(provisioning, {
      deviceSeedB64: base64Encode(hexDecode(TEST_MERCHANT_DEVICE_SEED_HEX)),
      deviceKeyIdHex: TEST_MERCHANT_DEVICE_KEY_ID_HEX,
      credentialB64: base64Encode(hexDecode(TEST_MERCHANT_CREDENTIAL_HEX)),
    })) as MerchantKeyStatus;
    return {ok: status.provisioned, alreadyProvisioned: false, status};
  } catch (error) {
    return {ok: false, alreadyProvisioned: false, reason: describe(error)};
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown failure';
}
