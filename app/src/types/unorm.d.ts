/**
 * Minimal ambient declaration for `unorm`, which ships no types.
 *
 * Only the NFC entry point is declared: that is the sole function this codebase
 * calls, and declaring the rest would promise an API surface nobody exercises.
 * Verify against the package's own README if more is ever needed.
 */
declare module 'unorm' {
  /** NFC normalization, UAX #15. */
  export function nfc(value: string): string;
  export function nfd(value: string): string;
  export function nfkc(value: string): string;
  export function nfkd(value: string): string;
  const unorm: {
    nfc(value: string): string;
    nfd(value: string): string;
    nfkc(value: string): string;
    nfkd(value: string): string;
  };
  export default unorm;
}
