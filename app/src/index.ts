/**
 * Deceipt shared app — public surface.
 *
 * The one typed adapter contract lives in `./native/DeceiptNative`; A4 and A5
 * implement it identically. `modules/deceipt-native/index.ts` re-exports this
 * file for consumers that import the module by path.
 */

export * from './native/DeceiptNative';
export {DeceiptBridgeError} from './native/bridgeError';
export {
  InMemoryDeceiptNative,
  linkMockPeers,
  type MockMerchantProvision,
  type MockNativeOptions,
  type MockRadio,
} from './native/mock/InMemoryDeceiptNative';
export {
  buildReceiptOfferFromReceipt,
  computeBindingValues,
  offerHashFromOfferMetadata,
  type BindingValues,
  type OfferIdentity,
} from './native/offer';

export {
  CBOR_LIMITS,
  RECEIPT_LIMITS,
  CREDENTIAL_LIMITS,
  CAPABILITIES,
  WIRE_LIMITS,
  HANDSHAKE_LIMITS,
  TIMEOUTS_MS,
  MESSAGE_TYPES,
  ENVELOPE_TAGS,
  GATT,
  CURRENCY_MINOR_UNIT_EXPONENT,
  PROTOCOL_VERSION,
  SUITE_ID,
  CLOCK_SKEW_MAX_S,
  attPayloadMax,
  maxFramePayloadForMtu,
} from './protocol/constants';
export {
  PROTOCOL_ERRORS,
  OUTCOMES,
  ProtocolError,
  asProtocolError,
  type ErrorCategory,
  type ErrorDescriptor,
  type OutcomeName,
  type PolicyOutcome,
  type ProtocolErrorName,
} from './protocol/errors';
export {CborMap, decodeCbor, encodeCbor, checkCanonical, type CborValue} from './protocol/cbor';
export {
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  bytesEqual,
  concatBytes,
  hexDecode,
  hexEncode,
  isValidUtf8,
  utf8Decode,
  utf8Encode,
} from './protocol/bytes';
export {randomBytes, sha256, hmacSha256, verifyHmacSha256, ed25519Verify} from './protocol/crypto';
export {
  assertQrFresh,
  bindingProofMessage,
  computeBindingTupleDigest,
  computeOfferHash,
  encodeBindingTuple,
  encodeBindingQr,
  offerHashPreimage,
  parseBindingQr,
  QR_PREFIX,
  type BindingQrPayload,
  type BindingTupleFields,
  type OfferFields,
} from './protocol/binding';
export {
  buildTranscript,
  checkProtectedHeader,
  parseCoseSign1,
  sigStructure,
  transcriptHash,
  verifyCredential,
  verifyTranscriptSignature,
  COSE_ALG_EDDSA,
  CREDENTIAL_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  type CredentialBody,
  type CredentialCheck,
  type CoseSign1,
  type TranscriptInputs,
} from './protocol/handshake';
export {
  computeLineAmountMinor,
  computeRateAmountMinor,
  parseReceiptPayload,
  parseReceiptMap,
  recomputeTotals,
  receiptToCbor,
  roundHalfAwayFromZero,
  serializeReceipt,
  type DecodedReceipt,
  type Receipt,
  type ReceiptKind,
  type ReceiptLine,
  type Quantity,
} from './protocol/receipt';
export {
  verifyReceipt,
  checkIssuedAtPolicy,
  receiptMatchesOffer,
  toStoredVerification,
  trustLabel,
  REVOCATION_UNSUPPORTED_REASON,
  type VerificationContext,
  type VerificationResult,
  type VerificationSubStates,
  type StoredVerification,
} from './protocol/verification';
export {
  encodeDataFrame,
  decodeDataFrame,
  encodeControlMessage,
  decodeControlMessage,
  encodeAeadEnvelope,
  encodePlaintextEnvelope,
  parseAeadEnvelope,
  segmentLpdu,
  reassembleLpdu,
  LpduReceiver,
  FrameReceiver,
  aeadNonce,
  aeadAdditionalData,
  frameCountFor,
  splitIntoFrames,
  assertFrameSize,
  assertFramePayloadLength,
  validateEphemeralPoint,
  decodeBindingTuple,
  messageDirection,
  type DataFrame,
  type ControlMessage,
  type ClientHello,
  type ServerHello,
  type ReceiptOffer,
  type TransferBegin,
  type TransferComplete,
  type AckMessage,
  type ReceiptAckMessage,
  type CancelMessage,
  type RetryMessage,
  type ErrorMessage,
  type LpduFragment,
} from './protocol/wire';

export {
  assertSessionAuthenticated,
  assertSessionMayTransfer,
  isAuthenticatedSession,
  isTransferableSession,
  isUnverifiedPeerSession,
} from './native/session';
export {
  MemoryKeyValueStore,
  ReceiptStore,
  MerchantIdentityCache,
  receiptDisplayBytes,
  type ImportKind,
  type ImportOutcome,
  type KeyValueStore,
  type StoredMerchantIdentity,
  type StoredReceipt,
  type StoredTrustLabel,
} from './storage/receiptStore';

export {
  INITIAL_CHECKOUT,
  candidatesForScannedSession,
  failureMessageFor,
  isEligible,
  orderCandidates,
  recoveryActionFor,
  reduce,
  type Candidate,
  type CandidateDiagnostics,
  type CheckoutEvent,
  type CheckoutModel,
  type CheckoutState,
  type SavedReceiptView,
  type Selection,
} from './checkout/machine';
export {CheckoutController, type CheckoutControllerOptions, type CheckoutResult} from './checkout/controller';
export {
  assertMerchantReady,
  buildSyntheticSale,
  prepareMerchantOffer,
  startMerchantServing,
  type PreparedMerchantOffer,
  type SyntheticReceiptOptions,
} from './checkout/merchantFlow';
export {TRUST_ANCHORS} from './config/trustAnchors';
