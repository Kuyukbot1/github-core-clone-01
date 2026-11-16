// main.ts — the entrypoint of the github-core-clone-01 forge.
//
// This file only runs the service lifecycle: it starts the forge from
// ./app.ts on an ephemeral port, tells the trial environment where to find
// it, and stays alive until the environment reports the run is over.
// Everything the forge itself does lives in app.ts.

import { createApp } from './app.ts';

// How long one request to the environment may take before it is abandoned.
const REQUEST_TIMEOUT_MS = 30_000;
// The first pause between two attempts, doubling after every attempt.
const FIRST_RETRY_DELAY_MS = 250;
// The longest pause between two attempts.
const MAX_RETRY_DELAY_MS = 2_000;

function die(message: string): never {
  console.error(`[forge] ${message}`);
  process.exit(1);
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

// The pause before attempt `attempt` (0-based): 250ms, 500ms, 1000ms, then
// 2000ms for every later attempt.
function retryDelayMs(attempt: number): number {
  const step = Number.isFinite(attempt) ? Math.max(0, Math.trunc(attempt)) : 0;
  return Math.min(MAX_RETRY_DELAY_MS, Math.round(FIRST_RETRY_DELAY_MS * 2 ** step));
}

function joinUrl(origin: string, path: string): string {
  const base = origin.replace(/\/+$/, '');
  const suffix = path.startsWith('/') ? path : `/${path}`;
  return `${base}${suffix}`;
}

interface HttpResult {
  readonly status: number;
  readonly body: unknown;
}

// One JSON request with a hard timeout. A timeout or a transport failure
// throws, so the caller can retry; a response is returned whatever its
// status, so the caller can decide what the status means.
async function requestJson(url: string, method: string, payload?: unknown): Promise<HttpResult> {
  const init: RequestInit = {
    method,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  };
  if (payload !== undefined) {
    init.headers = { 'content-type': 'application/json' };
    init.body = JSON.stringify(payload);
  }
  const response = await fetch(url, init);
  let body: unknown = null;
  try {
    body = (await response.json()) as unknown;
  } catch {
    body = null;
  }
  return { status: response.status, body };
}

class FatalRegisterError extends Error {
  constructor(status: number) {
    super(`the environment refused registration with HTTP ${status}`);
    this.name = 'FatalRegisterError';
  }
}

// Announce the forge's port to the environment. A 200 or a 409 both mean the
// environment knows where the forge is; a 400 or 405 means the request
// itself is wrong and retrying cannot help; anything else is worth another
// attempt after the backoff.
async function register(envUrl: string, port: number): Promise<void> {
  const url = joinUrl(envUrl, '/register');
  let attempt = 0;
  for (;;) {
    let result: HttpResult | null = null;
    try {
      result = await requestJson(url, 'POST', { port });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.error(`[forge] register attempt ${attempt} failed: ${reason}`);
    }
    if (result !== null) {
      if (result.status === 200 || result.status === 409) return;
      if (result.status === 400 || result.status === 405) throw new FatalRegisterError(result.status);
      console.error(`[forge] register answered HTTP ${result.status}; retrying`);
    }
    await sleep(retryDelayMs(attempt));
    attempt += 1;
  }
}

// Ask the environment whether the run is over, until it says it is. Every
// answer that is not a 200 with {"done": true} — a failure, another status,
// or {"done": false} — just means "not yet", so wait out the backoff and ask
// again.
async function waitForDone(envUrl: string): Promise<void> {
  const url = joinUrl(envUrl, '/done');
  let attempt = 0;
  for (;;) {
    let finished = false;
    try {
      const result = await requestJson(url, 'GET');
      finished =
        result.status === 200 &&
        typeof result.body === 'object' &&
        result.body !== null &&
        (result.body as { readonly done?: unknown }).done === true;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.error(`[forge] done poll attempt ${attempt} failed: ${reason}`);
    }
    if (finished) return;
    await sleep(retryDelayMs(attempt));
    attempt += 1;
  }
}

async function main(): Promise<void> {
  const envUrl = process.env.MAKEFUN_ENV_URL;
  if (envUrl === undefined || envUrl === '') die('MAKEFUN_ENV_URL is not set');
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') die('the forge is not listening on a TCP port');
  const port = address.port;
  console.log(`[forge] listening on port ${port}`);
  try {
    await register(envUrl, port);
    await waitForDone(envUrl);
  } catch (error) {
    if (server.listening) server.close();
    throw error;
  }
  server.closeAllConnections();
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

main()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    const reason = error instanceof Error ? error.message : String(error);
    console.error(`[forge] fatal: ${reason}`);
    process.exit(1);
  });
