/**
 * The published, test-only merchant material the dev bootstrap imports.
 *
 * These values are PUBLIC BY CONSTRUCTION: the seed is derived from the fixed
 * ASCII label `deceipt-testkey:ed25519:merchant-test-1` and the credential is
 * signed by the labelled PoC test root. They are transcribed from
 * `protocol/vectors/keys/test-keys.json` and
 * `protocol/vectors/fixtures/valid-credential.cbor` at revision
 * `deceipt-proto-r4` so this build can be diffed against the frozen vectors.
 *
 * The repository is public and these are test vectors: they protect nothing, are
 * trusted only by the PoC test anchor, and MUST NEVER be used to protect real
 * value. A production build ships no private material of any kind
 * (docs/protocol/trust.md §3, conformance B9), and the adapter reports
 * `testProvisioningEnabled: false` so this bootstrap is unreachable there.
 */

/** `device_key_id` of the pre-provisioned test merchant (16 bytes). */
export const TEST_MERCHANT_DEVICE_KEY_ID_HEX = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';

/** 32-byte Ed25519 seed of the test merchant device key. TEST ONLY. */
export const TEST_MERCHANT_DEVICE_SEED_HEX = '3955055e519690782aa3b61aa6820bd1a61123820c779f2ec6788f3270b152d3';

/** The exact COSE_Sign1 credential bytes (288 B) issued to that key. TEST ONLY. */
export const TEST_MERCHANT_CREDENTIAL_HEX = '84583ba301270378236170706c69636174696f6e2f646563656970742d63726564656e7469616c2b63626f7204500decea00000000000000000000000001a0589dab010102500decea000000000000000000000000010350a1b2c3d4e5f60718293a4b5c6d7e8f9004500f1e2d3c4b5a69788796a5b4c3d2e1f005582061d36a1033982810583469d18733d5810bcc8f06db10d11d391e3945d51c58ed061a692e2c00071a6b36ec8008181f09776d65726368616e742e706f632e746573742d616c7068610a714d61706c6520262056696e6520436166650b1a692e2c005840448b4fa5a34278c7b5d170077cf3f3aa1785a2d40c3b55502c592e8ea030223e45b379ef0b268ee7877dcf8fbe2ceb243780b134674d2db3c6f0f6328fe9b603';
