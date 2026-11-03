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

/** Caller-measured local decoder/queue observations, not authenticated facts. */
/** receivedFps is the source UI-callback frame count normalized by elapsed time, not packets received or confirmed renders. */
export interface ViewerFpsSample { display: number; receivedFps: number; decodeFps?: number | null; queueLen: number; queueCapacity: number }
export interface ViewerFpsDecision { customFps?: number | null; refresh: number[]; minDecodeFps?: number | null }
/** Caller owns measurements, scheduling, reconnect/reset and send policy. */
export class ViewerFpsController {
  setDisplays(displays: number[]): void;
  reset(): void;
  noteManualFpsUpdate(): void;
  tick(direct: boolean, customFps: number | null | undefined, samples: ViewerFpsSample[]): ViewerFpsDecision;
}
export function createViewerFpsController(): ViewerFpsController;
/** Feed only locally measured successful displayed frames; no native timing. */
export class ViewerDecodeFps {
  record(formatChanged: boolean, elapsedMicros: number): number | null | undefined;
  estimate(): number | null | undefined;
  reset(): void;
}
export function createViewerDecodeFps(): ViewerDecodeFps;
/** Caller-counted UI callback frames, not network arrivals or confirmed renders. */
export class ViewerFrameRate {
  recordFrame(): void;
  sample(elapsedMs: number): number | null | undefined;
  reset(): void;
}
export function createViewerFrameRate(): ViewerFrameRate;

export interface VideoQueuePushResult { kind: 'queued' | 'keyframe' | 'awaitKeyframe' | 'needRefresh'; discarded: number }
export interface VideoQueueFrame { token: string; generation: string; keyframe: boolean; data: Buffer }
export interface VideoQueueStats { queued: number; accountedBytes: number; generation: string; synced: boolean }
/** Local compressed buffers only; never makes input safe for native decoders. */
export class ViewerVideoQueueHandle {
  push(data: Buffer): Promise<VideoQueuePushResult>;
  pop(): VideoQueueFrame | null | undefined;
  isCurrent(token: string): boolean;
  complete(token: string, succeeded: boolean): 'applied' | 'stale' | 'decodeFailed';
  reset(): number;
  stats(): VideoQueueStats;
}
export function createViewerVideoQueue(display: number, codec: 'vp8' | 'vp9' | 'av1' | 'h264' | 'h265', maxFrames: number, maxBytes: number, maxMessageBytes: number): ViewerVideoQueueHandle;

export interface TrustedStreamResult {
  kind: 'ok' | 'removed' | 'notFound' | 'awaitKeyframe' | 'noImage' | 'image';
  display?: number | null; width?: number | null; height?: number | null; stride?: number | null; data?: Buffer | null;
}
/** Trusted local input only. A malicious bitstream can allocate or exploit native codecs. */
export class TrustedVideoWorker {
  register(display: number, codec: 'vp8' | 'vp9' | 'av1'): Promise<TrustedStreamResult>;
  decode(data: Buffer): Promise<TrustedStreamResult>;
  reset(display: number): Promise<TrustedStreamResult>;
  /** Drop one or all decoders after loss; reset and fresh keyframe required. */
  invalidate(display: number): Promise<TrustedStreamResult>;
  invalidateAll(): Promise<TrustedStreamResult>;
  remove(display: number): Promise<TrustedStreamResult>;
  close(): void;
}
export function createTrustedVideoWorker(maxInputBytes: number, maxOutputBytes: number, acknowledgeLocalTrustedInput: boolean): TrustedVideoWorker;

/** Experimental, unaudited direct TCP viewer. Address must be literal IP:port. */
export interface ViewerOptions {
  address: string; expectedHostId: string; hostSigningKey: Buffer;
  viewerId: string; viewerName: string; wireSessionId: string; version: string;
  password: string; timeoutMs: number; maxMessageBytes: number;
  /** Opt-in: caller must notifyVideoReceived after processing each video message. */
  videoAckRequired?: boolean;
  /** Optional pre-obtained code. JS and N-API copies cannot be reliably erased.
   * The peer can request/relay it; verify the host pin and obtain local consent.
   * The login fails if the peer does not request a second factor. */
  twoFactorCode?: string;
  /** Must be true exactly when twoFactorCode is present; no trust enrollment. */
  acknowledgeTwoFactorDisclosure?: boolean;
}
export interface ViewerDisplayInfo {
  x: number; y: number; width: number; height: number; name: string;
  online: boolean; cursorEmbedded: boolean; scale: number;
}
/** Peer-provided claims, not proof that codecs or secure attention work. */
export interface ViewerEncodingCapabilities {
  vp8: boolean; av1: boolean; h264: boolean; h265: boolean;
  i444Vp8?: boolean; i444Vp9?: boolean; i444Av1?: boolean; i444H264?: boolean; i444H265?: boolean;
}
export interface ViewerPeerInfo {
  username: string; hostname: string; platform: string; version: string;
  currentDisplay: number; displays: ViewerDisplayInfo[];
  sasEnabled: boolean; encoding?: ViewerEncodingCapabilities;
}
/** Untrusted and potentially sensitive OS-session claims, not authorization. */
export interface ViewerWindowsSessions { currentSid: number; sessions: Array<{ sid: number; name: string }> }
export interface ViewerMessage {
  kind: 'video' | 'cursorShape' | 'cursorId' | 'cursorPosition' | 'testDelay' | 'peerInfo' | 'displayChanged' | 'followCurrentDisplay' | 'permission' | 'encodingCapabilities' | 'other';
  data?: Buffer; display?: number; codec?: string; cursorId?: string;
  x?: number; y?: number; hotx?: number; hoty?: number; width?: number; height?: number; cursorEmbedded?: boolean;
  peer?: ViewerPeerInfo; permission?: number; enabled?: boolean;
  encodingVp8?: boolean; encodingAv1?: boolean; encodingH264?: boolean; encodingH265?: boolean;
  i444Vp8?: boolean; i444Vp9?: boolean; i444Av1?: boolean; i444H264?: boolean; i444H265?: boolean;
  /** Untrusted TestDelay fields; signed i64 is represented as a decimal string. */
  probeTime?: string; probeFromClient?: boolean; probeLastDelay?: number; probeTargetBitrate?: number;
}
/** Untrusted peer claims; these do not grant permission to change a mode. */
export interface WireResolution { width: number; height: number }
export interface DisplayChangeMetadata {
  display: number; x: number; y: number; width: number; height: number; cursorEmbedded: boolean;
  supportedModes?: WireResolution[]; original?: WireResolution;
}
/** Inspect a displayChanged event's data buffer; maximum 128 KiB. */
export function inspectDisplayChange(wire: Buffer): Promise<DisplayChangeMetadata>;
export interface ViewerDecodingOptions {
  vp8: boolean; vp9: boolean; av1: boolean; h264: boolean; h265: boolean;
  preference: 'auto' | 'vp8' | 'vp9' | 'av1' | 'h264' | 'h265';
}
/** Missing fields mean unchanged. Requests do not grant permission. */
export interface CursorPreferences { showRemoteCursor?: boolean; followRemoteCursor?: boolean; followRemoteWindow?: boolean; showMyCursor?: boolean }
/** A peer claim; present=false means the optional wire field was absent. */
export interface ViewerOriginalResolution { present: boolean; width?: number; height?: number }
export class Viewer {
  peerInfo(): ViewerPeerInfo;
  /** Latest untrusted login/update claims; null/undefined means unavailable or invalid. */
  originalResolutions(): Promise<ViewerOriginalResolution[] | null | undefined>;
  /** Latest untrusted current-display mode claims, or null/undefined when absent. */
  supportedModes(): Promise<{ display: number; modes: WireResolution[] } | null | undefined>;
  sendMouse(mask: number, x: number, y: number, timeoutMs: number): Promise<void>;
  /** Latest Windows session claims; absent/invalid is null/undefined. Does not switch sessions. */
  windowsSessions(): Promise<ViewerWindowsSessions | null | undefined>;
  /** Uses RustDesk ControlKey numeric values, not Windows VK codes. */
  sendControlKey(controlKey: number, down: boolean, press: boolean, modifiers: number[], timeoutMs: number): Promise<void>;
  sendText(text: string, timeoutMs: number): Promise<void>;
  /** Explicitly acknowledge source Windows effects. May release Shift or synthesize modifiers; non-BMP scalars are truncated. Peer consent/authorization is separate; delivery may be indeterminate. */
  sendWindowsTranslateText(text: string, acknowledgeSourceEffects: boolean, timeoutMs: number): Promise<void>;
  /** Source Map-mode Windows physical scan code; host must authorize and enable it. */
  sendWindowsScanCode(code: number, down: boolean, timeoutMs: number): Promise<void>;
  /** Source Translate-mode position code; host must authorize and enable it. */
  sendWindowsTranslateCode(code: number, down: boolean, timeoutMs: number): Promise<void>;
  /** Source Windows touch scale; zero ends gesture. Requires host opt-in. */
  sendTouchScale(scale: number, timeoutMs: number): Promise<void>;
  sendMouseWithModifiers(mask: number, x: number, y: number, modifiers: number[], timeoutMs: number): Promise<void>;
  /** These are requests/notifications only; they do not refresh or decode video locally. */
  advertiseDecoding(options: ViewerDecodingOptions, timeoutMs: number): Promise<void>;
  /** Source QoS values: 0 unchanged; 2 low, 3 balanced, 4 best; otherwise positive packed custom. FPS 0 or 1..120. */
  sendVideoPreferences(imageQuality: number, fps: number, timeoutMs: number): Promise<void>;
  requestCursorShape(id: string, timeoutMs: number): Promise<void>;
  sendCursorPreferences(preferences: CursorPreferences, timeoutMs: number): Promise<void>;
  /** A request only; false does not grant input. */
  sendDisableKeyboard(disabled: boolean, timeoutMs: number): Promise<void>;
  /** Does not change resolution. Host may deny or ignore it. */
  requestDisplay(display: number, timeoutMs: number): Promise<void>;
  queryDisplay(display: number, timeoutMs: number): Promise<void>;
  /** Peer may change its real OS display mode; explicit informed consent is required. */
  requestDisplayResolution(display: number, width: number, height: number, confirmRemoteResolutionChange: boolean, timeoutMs: number): Promise<void>;
  /** Empty lists can unsubscribe all displays; host may deny this request. */
  requestCaptureDisplays(add: number[], sub: number[], set: number[], timeoutMs: number): Promise<void>;
  /** Explicit caller-approved plan; success counts local sends, not peer receipt. */
  dispatchFpsDecision(decision: ViewerFpsDecision, perDisplayRefresh: boolean, timeoutMs: number): Promise<number>;
  requestRefreshAll(timeoutMs: number): Promise<void>;
  requestRefreshDisplay(display: number, timeoutMs: number): Promise<void>;
  notifyVideoReceived(timeoutMs: number): Promise<void>;
  /** Peer may ignore these untrusted QoS/recording claims; no recording is performed. */
  sendAutoAdjustFps(fps: number, timeoutMs: number): Promise<void>;
  reportRecording(recording: boolean, timeoutMs: number): Promise<void>;
  /** Timeout closes the connection. Calls on one Viewer cannot overlap. */
  receive(timeoutMs: number): Promise<ViewerMessage>;
  /** Best-effort notification then local close; peer receipt is not guaranteed. */
  sendCloseReason(reason: string, timeoutMs: number): Promise<void>;
  /** Terminal cooperative close; in-flight delivery may be indeterminate. Native work may not stop promptly. */
  requestClose(): void;
  /** Experimental direct TCP only; explicit opt-in after login. WSS rejects it. */
  enableDuplexReadAhead(acknowledgeExperimental: boolean): Promise<void>;
  /** Non-destructive local queue poll; null/undefined means no message. */
  tryReceive(sendTimeoutMs: number): Promise<ViewerMessage | null | undefined>;
  close(): void;
}
/** Source v1 host key pinning; this is untested, not a production security guarantee. */
export function connectViewer(options: ViewerOptions): Promise<Viewer>;
/** WSS endpoint policy does not prevent SSRF; use only trusted endpoints. */
export interface WssViewerOptions extends Omit<ViewerOptions, 'address'> { endpoint: string }
/** Single-use local cancellation handle for one connection attempt. */
export class ViewerConnectRequest {
  constructor();
  /** Sticky cancellation; already-disclosed credentials and delivery cannot be recalled. */
  cancel(): void;
  /** An attempted call consumes the handle even if validation fails. */
  connectTcp(options: ViewerOptions): Promise<Viewer>;
  connectWss(options: WssViewerOptions): Promise<Viewer>;
}
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
  /** Cancel an in-progress accept; await it, then close() to release the listener slot. */
  requestClose(): void;
  /** Existing sessions must be closed separately. Cannot overlap accept(). */
  close(): void;
}
export interface LocalHostEvent {
  kind: 'input' | 'inputSuppressed' | 'heartbeat' | 'refreshAll' | 'refreshDisplay' | 'frameReceived' | 'displaySwitch' | 'captureDisplays' | 'displayResolution' | 'displayQuery' | 'windowsSessionRequest' | 'cursorShapeRequest' | 'decodingAdvertisement' | 'videoPreferences' | 'autoAdjustFps' | 'clientRecording' | 'cursorPreferences' | 'inputPreference';
  /** Session requests are untrusted; the current view-only Node host does not grant the required gate or switch sessions. */
  display?: number; cursorId?: string; windowsSessionId?: number; data?: Buffer; vp8?: number; vp9?: number; av1?: number;
  h264?: number; h265?: number; preference?: number; imageQuality?: number; customFps?: number; recording?: boolean;
  showRemoteCursor?: boolean; followRemoteCursor?: boolean; followRemoteWindow?: boolean; showMyCursor?: boolean; disableKeyboard?: boolean;
  /** On heartbeat probe replies only; untrusted. Time is a signed decimal i64 string. */
  probeTime?: string; probeLastDelay?: number; probeTargetBitrate?: number;
}
export interface HostVideoPreferences { imageQuality?: number; customFps?: number }
/** ACKs are unsequenced/untrusted. A closed connection still requires session.close() for slot cleanup. */
export interface AckBurstResult { sent: number; reason: 'requested' | 'deadline' | 'frameLimit' | 'event' | 'eventWithAckOutstanding'; event?: LocalHostEvent | null; connectionClosed: boolean }
export class LocalHostSession {
  claims(): LocalLoginClaims;
  /** Untrusted login preferences, available only after approval; consumed once. */
  takeInitialVideoPreferences(): HostVideoPreferences | null;
  takeInitialCursorPreferences(): CursorPreferences | null;
  takeInitialDisableKeyboard(): boolean | null | undefined;
  /** Available only after view approval; not proof of rendering. */
  initialVideoAckRequired(): boolean;
  /** Requires a separate trusted local consent decision; grants view only. */
  approveView(confirmLocalConsent: boolean, timeoutMs: number): Promise<void>;
  /** One independently encoded frame; not continuous video or a codec negotiation. */
  sendOneVp9Frame(displayIndex: number, confirmViewerVp9: boolean, captureTimeoutMs: number, sendTimeoutMs: number): Promise<void>;
  /** Trusted non-decoding diagnostic sink only; does not establish viewer codec support. */
  sendOneVp9EnvelopeToTrustedSink(displayIndex: number, acknowledgeNoDecoder: boolean, captureTimeoutMs: number, sendTimeoutMs: number): Promise<void>;
  /** One paced VP9 burst, at most 5 seconds/120 frames. Rejects ACK-required sessions; no concurrent host operations. */
  sendVp9Burst(displayIndex: number, confirmViewerVp9: boolean, fps: number, maxFrames: number,
    maxDurationMs: number, captureTimeoutMs: number, sendTimeoutMs: number): Promise<number>;
  /** Explicit duplex/ACK opt-in; event or timeout may stop and close the session. */
  sendVp9AckBurst(displayIndex: number, confirmViewerVp9: boolean, acknowledgeUntrustedAck: boolean,
    fps: number, maxFrames: number, maxDurationMs: number, captureTimeoutMs: number, sendTimeoutMs: number): Promise<AckBurstResult>;
  /** Trusted diagnostic sink only: explicitly does not claim decoder capability. */
  sendVp9AckBurstToTrustedSink(displayIndex: number, acknowledgeNoDecoder: boolean, acknowledgeUntrustedAck: boolean,
    fps: number, maxFrames: number, maxDurationMs: number, captureTimeoutMs: number, sendTimeoutMs: number): Promise<AckBurstResult>;
  /** Cooperative stop; cannot interrupt a native call or an in-flight send. */
  requestStopBurst(): void;
  /** Caller-driven, untrusted probe. No timer or QoS integration; never retry uncertain sends. */
  sendDelayProbe(lastDelayMs: number, targetBitrateKbps: number, timeoutMs: number): Promise<void>;
  /** Timeout closes the session; requests are untrusted and are not executed automatically. */
  receiveEvent(timeoutMs: number): Promise<LocalHostEvent>;
  /** Experimental direct TCP read-ahead; only after view approval. */
  enableDuplexReadAhead(acknowledgeExperimental: boolean): Promise<void>;
  tryReceiveEvent(sendTimeoutMs: number): Promise<LocalHostEvent | null | undefined>;
  /** Caller-driven; no timer is started. Accepted minutes: 1..1440. */
  enableIdleTimeout(minutes: number): void;
  idleRemainingMs(): number | null | undefined;
  /** Close on expiry. Must be called regularly and cannot overlap host operations. */
  pollIdleTimeout(): boolean;
  /** Caller-driven 30-second receive watchdog; no timer or probes are started. */
  /** Restricted Windows input paths; consent is a caller assertion, not proof. */
  setWindowsScanModeEnabled(enabled: boolean, confirmLocalConsent: boolean): void;
  setWindowsTranslateModeEnabled(enabled: boolean, confirmLocalConsent: boolean): void;
  setWindowsKeyRepeatEnabled(enabled: boolean, confirmLocalConsent: boolean): void;
  enableReceiveWatchdog(): void;
  receiveWatchdogRemainingMs(): number | null | undefined;
  pollReceiveWatchdog(): boolean;
  /** Consent-sensitive Windows foreground hint. No background tracking or display switch. */
  sendWindowsFocusHint(confirmLocalConsent: boolean, followEnabled: boolean, timeoutMs: number): Promise<boolean>;
  resetWindowFocus(): void;
  /** Caller supplies volatile display index and multi-UI state; no automatic tracking. */
  sendWindowsCursorFollowHint(currentDisplay: number, multiUiSession: boolean, confirmLocalConsent: boolean, followEnabled: boolean, timeoutMs: number): Promise<boolean>;
  /** Always-shape mode; cannot mix with cursor announcements in one session. */
  sampleWindowsCursor(timeoutMs: number): Promise<boolean>;
  /** Opt into bounded source-style shape/ID announcements after view approval. */
  enableCursorAnnouncements(acknowledgePeerCacheMisses: boolean): void;
  /** Windows only; forceShape resends full pixels. No background service or hide event. */
  sampleWindowsCursorAnnouncement(forceShape: boolean, timeoutMs: number): Promise<boolean>;
  /** Explicitly answer a peer resend request from the selected session cache. */
  resendCursorShape(id: string, timeoutMs: number): Promise<boolean>;
  /** Best-effort notification then local close; call close() afterward to release the slot. */
  sendCloseReason(reason: string, timeoutMs: number): Promise<void>;
  /** Terminal close request; wait for active work, then call close() to release the session slot. */
  requestClose(): void;
  close(): void;
}
/** Explicit loopback host, unbuilt/untested and not a production security boundary. */
export function listenLocalHost(options: LocalHostOptions): Promise<LocalHost>;

/**
 * Controlled-network-only experimental listener. Exact observed IP is only a
 * filter, not identity. Password transcripts permit offline guessing; there is
 * no failure-rate policy, trusted consent UI or secure pin distribution.
 */
export interface NetworkHostOptions {
  address: string; allowedPeerIp: string; hostId: string; password: string;
  timeoutMs: number; acknowledgeNetworkExposure: boolean;
}
export class NetworkHost {
  address(): string;
  signingPublicKey(): Buffer;
  /** Same view-only session object as LocalHost; still needs explicit approval. */
  accept(timeoutMs: number): Promise<LocalHostSession>;
  /** Terminal listener request; existing delivered sessions remain caller-owned. */
  requestClose(): void;
  close(): void;
}
/** Do not expose this unaudited prototype to an untrusted/public network. */
export function listenNetworkHost(options: NetworkHostOptions): Promise<NetworkHost>;

/** Source libyuv ARGB byte convention, not a guaranteed canvas RGBA layout. */
export interface TrustedDecodedImage { inputIndex: number; display: number; width: number; height: number; stride: number; data: Buffer }
/**
 * Local, trusted input only. Native codec decoding is not hardened: malicious
 * bitstreams may allocate unbounded native memory or compromise the process.
 * Batches are independent and must start with a keyframe; no network/rendering.
 */
export function decodeTrustedVideoBatch(messages: Buffer[], acknowledgeTrustedInputOnly: boolean): Promise<TrustedDecodedImage[]>;

/** Read-only Windows OS mode snapshot. Names/indices can become stale immediately. */
export interface WindowsDisplayMode { width: number; height: number; bitsPerPixel: number; refreshHz: number }
export interface WindowsModeSnapshot { displayIndex: number; deviceName: string; current: WindowsDisplayMode; modes: WindowsDisplayMode[]; truncated: boolean }
/** Requires local consent; never changes resolution. Unsupported outside Windows. */
export function inspectWindowsDisplayModes(displayIndex: number, confirmLocalConsent: boolean): Promise<WindowsModeSnapshot>;

/** Caller-driven, per-peer cursor cache. No drawing or requests are automatic. */
export class ViewerCursorHandle {
  /** CursorData normally selects; delayed resend replies have no correlation. */
  observeShape(metadata: CursorMetadata, rgba: Buffer, select: boolean): void;
  /** Select peer ID and return false for a cache miss. */
  select(id: string): boolean;
  /** A new buffer copy; JS-retained copies are outside cache accounting. */
  selectedShape(): DecodedCursorShape | null | undefined;
  observePosition(x: number, y: number): void;
  position(): { x: number; y: number } | null | undefined;
  stats(): { selectedId?: string | null; cached: number; retainedBytes: number };
  clear(): void;
}
export function createViewerCursor(maxItems: number, maxBytes: number): ViewerCursorHandle;
