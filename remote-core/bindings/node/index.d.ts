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
  kind: 'video' | 'cursorShape' | 'cursorId' | 'cursorPosition' | 'testDelay' | 'peerInfo' | 'permission' | 'other';
  data?: Buffer; display?: number; codec?: string; cursorId?: string;
  x?: number; y?: number; hotx?: number; hoty?: number; width?: number; height?: number;
  peer?: ViewerPeerInfo; permission?: number; enabled?: boolean;
}
export interface ViewerDecodingOptions {
  vp8: boolean; vp9: boolean; av1: boolean; h264: boolean; h265: boolean;
  preference: 'auto' | 'vp8' | 'vp9' | 'av1' | 'h264' | 'h265';
}
export class Viewer {
  peerInfo(): ViewerPeerInfo;
  sendMouse(mask: number, x: number, y: number, timeoutMs: number): Promise<void>;
  /** Uses RustDesk ControlKey numeric values, not Windows VK codes. */
  sendControlKey(controlKey: number, down: boolean, press: boolean, modifiers: number[], timeoutMs: number): Promise<void>;
  sendText(text: string, timeoutMs: number): Promise<void>;
  /** Source Map-mode Windows physical scan code; host must authorize and enable it. */
  sendWindowsScanCode(code: number, down: boolean, timeoutMs: number): Promise<void>;
  sendMouseWithModifiers(mask: number, x: number, y: number, modifiers: number[], timeoutMs: number): Promise<void>;
  /** These are requests/notifications only; they do not refresh or decode video locally. */
  advertiseDecoding(options: ViewerDecodingOptions, timeoutMs: number): Promise<void>;
  requestCursorShape(id: string, timeoutMs: number): Promise<void>;
  requestRefreshAll(timeoutMs: number): Promise<void>;
  requestRefreshDisplay(display: number, timeoutMs: number): Promise<void>;
  notifyVideoReceived(timeoutMs: number): Promise<void>;
  /** Timeout closes the connection. Calls on one Viewer cannot overlap. */
  receive(timeoutMs: number): Promise<ViewerMessage>;
  close(): void;
}
/** Source v1 host key pinning; this is untested, not a production security guarantee. */
export function connectViewer(options: ViewerOptions): Promise<Viewer>;
/** WSS endpoint policy does not prevent SSRF; use only trusted endpoints. */
export interface WssViewerOptions extends Omit<ViewerOptions, 'address'> { endpoint: string }
/** TLS validates the relay/server, while the host key is independently pinned. */
export function connectWssViewer(options: WssViewerOptions): Promise<Viewer>;

/** Loopback-only, view-only prototype. The host pin is ephemeral per listener. */
export interface LocalHostOptions { hostId: string; password: string; timeoutMs: number }
/** All claims are supplied by the peer, not a verified identity. */
export interface LocalLoginClaims { username: string; peerId: string; peerName: string; wireSessionId: string; version: string }
export class LocalHost {
  address(): string;
  signingPublicKey(): Buffer;
  /** Returns an unapproved session; one session at a time. */
  accept(timeoutMs: number): Promise<LocalHostSession>;
  /** Existing sessions must be closed separately. Cannot overlap accept(). */
  close(): void;
}
export interface LocalHostEvent {
  kind: 'input' | 'heartbeat' | 'refreshAll' | 'refreshDisplay' | 'frameReceived' | 'cursorShapeRequest' | 'decodingAdvertisement';
  display?: number; cursorId?: string; data?: Buffer; vp8?: number; vp9?: number; av1?: number;
  h264?: number; h265?: number; preference?: number;
}
export class LocalHostSession {
  claims(): LocalLoginClaims;
  /** Requires a separate trusted local consent decision; grants view only. */
  approveView(confirmLocalConsent: boolean, timeoutMs: number): Promise<void>;
  /** One independently encoded frame; not continuous video or a codec negotiation. */
  sendOneVp9Frame(displayIndex: number, confirmViewerVp9: boolean, captureTimeoutMs: number, sendTimeoutMs: number): Promise<void>;
  /** One paced VP9 stream burst, at most 5 seconds and 120 frames. No concurrent host operations. */
  sendVp9Burst(displayIndex: number, confirmViewerVp9: boolean, fps: number, maxFrames: number,
    maxDurationMs: number, captureTimeoutMs: number, sendTimeoutMs: number): Promise<number>;
  /** Cooperative stop; cannot interrupt a native call or an in-flight send. */
  requestStopBurst(): void;
  /** Timeout closes the session; requests are untrusted and are not executed automatically. */
  receiveEvent(timeoutMs: number): Promise<LocalHostEvent>;
  sampleWindowsCursor(timeoutMs: number): Promise<boolean>;
  resendCursorShape(id: string, timeoutMs: number): Promise<boolean>;
  close(): void;
}
/** Explicit loopback host, unbuilt/untested and not a production security boundary. */
export function listenLocalHost(options: LocalHostOptions): Promise<LocalHost>;
