/// A snapshot of the current enumeration, not a durable display identity.
export interface DisplayMetadata {
  index: number;
  name: string;
  x: number;
  y: number;
  width: number;
  height: number;
  online: boolean;
  primary: boolean;
}
export interface CapturedFrame {
  width: number;
  height: number;
  strides: number[];
  format: 'bgra' | 'rgba' | 'rgb565le' | 'i420' | 'nv12' | 'i444';
  /** Owned native-layout bytes, potentially including padding. */
  data: Buffer;
}
export function listDisplays(): Promise<DisplayMetadata[]>;
/** timeoutMs is a backend hint, not a hard deadline. May reject with WouldBlock. */
export function captureDisplay(displayIndex: number, timeoutMs: number): Promise<CapturedFrame>;
