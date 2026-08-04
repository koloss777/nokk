export interface LaunchOptions {
  /** Address to bind (default "127.0.0.1"). */
  host?: string;
  /** TCP port; 0 (default) picks a free one. */
  port?: number;
  /** Isolate worker threads. */
  workers?: number;
  /** Cap on concurrent live contexts before backpressure. */
  maxContexts?: number;
  /** Upstream proxy, e.g. "socks5://host:1080" or "http://user:pass@host:port". */
  proxy?: string;
  /** Directory for persistent named-session cookie jars. */
  sessionStore?: string;
  /** Give each browser context its own coherent fingerprint. */
  rotateFingerprint?: boolean;
  /** Derive each context's timezone/locale from its proxy's exit IP. */
  geoipTimezone?: boolean;
  /** Load ad/analytics/tracker subresources (blocked by default). */
  allowTrackers?: boolean;
  /** Chrome major version to emulate (TLS + JS together), e.g. 148. */
  chromeVersion?: number;
  /** Extra raw CLI arguments passed to the binary. */
  args?: string[];
  /** Extra environment variables for the server process. */
  env?: Record<string, string>;
  /** stdio option for the child process (default "inherit"). */
  stdio?: any;
  /** Milliseconds to wait for the server to become ready (default 30000). */
  timeout?: number;
}

export declare class NokkServer {
  readonly host: string;
  readonly port: number;
  /** browserWSEndpoint for puppeteer.connect / chromium.connectOverCDP. */
  readonly wsEndpoint: string;
  readonly httpEndpoint: string;
  readonly pid: number;
  /** Stop the server. Idempotent. */
  close(): Promise<void>;
}

/** Start a nokk CDP server and resolve to a NokkServer. */
export declare function launch(options?: LaunchOptions): Promise<NokkServer>;

/** Absolute path to the bundled `nokk` binary (override with NOKK_BINARY). */
export declare function binaryPath(): string;
