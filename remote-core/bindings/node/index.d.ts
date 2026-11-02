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
export interface EncodeOptions {
  width: number;
  height: number;
  stride: number;
  codec: 'vp8' | 'vp9' | 'av1';
  pixelFormat: 'bgra' | 'rgba';
  quality: number;
  ptsMs: number;
}
export interface EncodedPacket { data: Buffer; key: boolean; ptsMs: number }
export interface EncodedFrame { codec: 'vp8' | 'vp9' | 'av1'; packets: EncodedPacket[] }
/** One independent frame/encoder invocation; not a persistent video stream. */
export function encodeFrame(data: Buffer, options: EncodeOptions): Promise<EncodedFrame>;

/** Decimal unsigned 64-bit RustDesk cursor ID, never a JS number. */
export interface CursorMetadata { id: string; hotx: number; hoty: number; width: number; height: number }
export interface DecodedCursorShape extends CursorMetadata { rgba: Buffer }
/** Wire conversion only, not a cursor capturer or session. */
export function encodeCursorShape(rgba: Buffer, metadata: CursorMetadata): Promise<Buffer>;
export function decodeCursorShape(wire: Buffer): Promise<DecodedCursorShape>;
export function encodeCursorPosition(x: number, y: number): Buffer;
export function encodeCursorId(id: string): Buffer;

/** Experimental, unaudited direct TCP viewer. Address must be literal IP:port. */
export interface ViewerOptions {
  address: string; expectedHostId: string; hostSigningKey: Buffer;
  viewerId: string; viewerName: string; wireSessionId: string; version: string;
  password: string; timeoutMs: number; maxMessageBytes: number;
}
export interface ViewerDisplayInfo {
  x: number; y: number; width: number; height: number; name: string;
  online: boolean; cursorEmbedded: boolean; scale: number;
}
export interface ViewerPeerInfo {
  username: string; hostname: string; platform: string; version: string;
  currentDisplay: number; displays: ViewerDisplayInfo[];
}
export interface ViewerMessage {
  kind: 'video' | 'cursorShape' | 'cursorId' | 'cursorPosition' | 'testDelay' | 'peerInfo' | 'other';
  data?: Buffer; display?: number; codec?: string; cursorId?: string;
  x?: number; y?: number; hotx?: number; hoty?: number; width?: number; height?: number;
  peer?: ViewerPeerInfo;
}
export class Viewer {
  peerInfo(): ViewerPeerInfo;
  sendMouse(mask: number, x: number, y: number, timeoutMs: number): Promise<void>;
  /** Timeout closes the connection. Calls on one Viewer cannot overlap. */
  receive(timeoutMs: number): Promise<ViewerMessage>;
  close(): void;
}
/** Source v1 host key pinning; this is untested, not a production security guarantee. */
export function connectViewer(options: ViewerOptions): Promise<Viewer>;
