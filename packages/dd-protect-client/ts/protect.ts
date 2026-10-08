// protect.ts: @datadeft/protect-client
//
// One function for proof-of-work admission. No UI code, no hardcoded routes.
//
// Usage:
//   import { protect, ProtectError } from "@datadeft/protect-client";
//
//   try {
//     await protect({
//       workerUrl: "/pow-worker.js", // your app builds and serves this
//       createUrl: "/api/v1/session/pow/create",
//       validateUrl: "/api/v1/session/pow/validate",
//     });
//   } catch (e) {
//     if (e instanceof ProtectError) {
//       switch (e.code) {
//         case "network": /* offline, DNS, or CORS failure */
//         case "timeout": /* request or solve took too long */
//         case "server":  /* non-2xx from the admission API */
//         case "solve":   /* worker crash or nonce exhaustion */
//       }
//     }
//   }

/**
 * Failure category for {@link ProtectError}.
 *
 * - `"network"`: Fetch failed (offline, DNS, CORS).
 * - `"timeout"`: Request or proof-of-work solve exceeded its time limit.
 * - `"server"`: Admission API returned non-2xx. Read `.status` for the code.
 * - `"solve"`: Worker crashed, CSP blocked the worker, or the nonce space ran out.
 */
export type ProtectErrorCode = "network" | "timeout" | "server" | "solve";

/**
 * Typed error thrown by {@link protect}. Use `e.code` for the failure category
 * and `e.status` for the HTTP status when `code === "server"`.
 */
export class ProtectError extends Error {
    /** Failure category. */
    readonly code: ProtectErrorCode;
    /** HTTP status code. Set only when `code === "server"`. */
    readonly status?: number;

    constructor(code: ProtectErrorCode, message: string, status?: number) {
        super(message);
        this.name = "ProtectError";
        this.code = code;
        this.status = status;
    }
}

/** Settings for one admission attempt. */
export interface ProtectConfig {
    /**
     * URL of the ESM worker script the app serves. Pass a string path or a
     * URL resolved by the consuming application's bundler.
     */
    workerUrl: string | URL;
    /** POST endpoint that mints a challenge (`pow/create`). */
    createUrl: string;
    /** POST endpoint that verifies a solution and sets the proof cookie (`pow/validate`). */
    validateUrl: string;
    /**
     * Parallel workers to spawn, clamped to `1..=8` (fractions round down).
     * Default: `navigator.hardwareConcurrency` (or 4), clamped the same way.
     */
    workerCount?: number;
    /** Maximum time for the whole solve. Default: 30000 ms. */
    solveTimeoutMs?: number;
    /** Maximum time per HTTP request. Default: 10000 ms. */
    fetchTimeoutMs?: number;
}

interface Challenge {
    chg: string;
    dif: number;
    tim: string;
    tag: string;
}

interface Solution {
    chg: string;
    sol: string;
    non: string;
    tim: string;
    tag: string;
}

interface WorkerMessage {
    type: "solution" | "error";
    nonce?: number;
    hash?: string;
    message?: string;
}

/** Worker count bounds; more workers than this only add browser overhead. */
const MIN_WORKER_COUNT = 1;
const MAX_WORKER_COUNT = 8;

/** Clamp a worker count into `MIN..=MAX`; a non-finite value yields `fallback`. */
function clampWorkerCount(value: number, fallback: number): number {
    if (!Number.isFinite(value)) {
        return fallback;
    }
    return Math.min(MAX_WORKER_COUNT, Math.max(MIN_WORKER_COUNT, Math.floor(value)));
}

const DEFAULT_WORKER_COUNT = clampWorkerCount(
    typeof navigator !== "undefined" ? navigator.hardwareConcurrency || 4 : 4,
    4,
);
/** Generous ceiling for challenge string fields (the server sends far less). */
const MAX_CHALLENGE_FIELD_LENGTH = 256;
/** Difficulty range the server accepts: leading zero hex digits of SHA-256. */
const MAX_DIFFICULTY = 64;
const DEFAULT_SOLVE_TIMEOUT_MS = 30_000;
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

function wrapFetchError(err: unknown, context: string): ProtectError {
    if (err instanceof DOMException && err.name === "TimeoutError") {
        return new ProtectError("timeout", `${context}: timed out`);
    }
    if (err instanceof TypeError) {
        return new ProtectError("network", `${context}: ${err.message}`);
    }
    const message = err instanceof Error ? err.message : String(err);
    return new ProtectError("network", `${context}: ${message}`);
}

/** True for a non-empty string within the challenge field length limit. */
function isChallengeField(value: unknown): value is string {
    return (
        typeof value === "string" &&
        value.length > 0 &&
        value.length <= MAX_CHALLENGE_FIELD_LENGTH
    );
}

/**
 * Check the parsed challenge's shape before any worker starts. TypeScript's
 * `as` is only an annotation; a hostile or misconfigured server can send
 * anything, and a missing `dif` would otherwise "solve" instantly.
 */
function parseChallenge(value: unknown): Challenge | null {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return null;
    }
    const { chg, dif, tim, tag } = value as Record<string, unknown>;
    if (
        !isChallengeField(chg) ||
        !isChallengeField(tim) ||
        !isChallengeField(tag) ||
        typeof dif !== "number" ||
        !Number.isInteger(dif) ||
        dif < 1 ||
        dif > MAX_DIFFICULTY
    ) {
        return null;
    }
    return { chg, dif, tim, tag };
}

function solve(
    challenge: Challenge,
    workerUrl: string | URL,
    workerCount: number,
    solveTimeoutMs: number,
): Promise<Solution> {
    return new Promise((resolve, reject) => {
        const workers: Worker[] = [];
        let solved = false;

        const cleanup = () => {
            workers.forEach((worker) => worker.terminate());
            workers.length = 0;
        };

        const timer = setTimeout(() => {
            if (!solved) {
                solved = true;
                cleanup();
                reject(
                    new ProtectError("timeout", `proof-of-work solve timed out after ${solveTimeoutMs}ms`),
                );
            }
        }, solveTimeoutMs);

        const done = (fn: () => void) => {
            clearTimeout(timer);
            fn();
        };

        for (let i = 0; i < workerCount; i++) {
            try {
                const worker = new Worker(workerUrl, { type: "module" });
                workers.push(worker);

                worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
                    if (solved) return;
                    const { type, nonce, hash, message } = event.data;

                    if (type === "solution" && nonce !== undefined && hash) {
                        solved = true;
                        cleanup();
                        done(() =>
                            resolve({
                                chg: challenge.chg,
                                sol: hash,
                                non: nonce.toString(),
                                tim: challenge.tim,
                                tag: challenge.tag,
                            }),
                        );
                    } else if (type === "error") {
                        solved = true;
                        cleanup();
                        done(() => reject(new ProtectError("solve", message || "worker error")));
                    }
                };

                worker.onerror = (error) => {
                    if (!solved) {
                        solved = true;
                        cleanup();
                        done(() => reject(new ProtectError("solve", `worker error: ${error.message}`)));
                    }
                };

                worker.postMessage({
                    challenge: challenge.chg,
                    difficulty: challenge.dif,
                    startNonce: i,
                    step: workerCount,
                });
            } catch (err) {
                cleanup();
                const message = err instanceof Error ? err.message : String(err);
                done(() => reject(new ProtectError("solve", `worker failed to start: ${message}`)));
                return;
            }
        }
    });
}

/**
 * Run the full proof-of-work admission flow: mint a challenge, solve it with
 * Web Workers, and post the solution. On success the server sets the `dd_pow`
 * proof cookie. The challenge is short-lived (about 120 s), so the solve starts
 * immediately after the challenge arrives.
 *
 * @throws {ProtectError} with `code` set to the failure category.
 */
export async function protect(config: ProtectConfig): Promise<void> {
    // Clamped so a bad value can neither start zero workers (a hang until the
    // solve timeout) nor fractional nonce strides.
    const workerCount = clampWorkerCount(
        config.workerCount ?? DEFAULT_WORKER_COUNT,
        DEFAULT_WORKER_COUNT,
    );
    const solveTimeoutMs = config.solveTimeoutMs ?? DEFAULT_SOLVE_TIMEOUT_MS;
    const fetchTimeoutMs = config.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;

    let createResp: Response;
    try {
        createResp = await fetch(config.createUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            credentials: "same-origin",
            cache: "no-store",
            body: "{}",
            signal: AbortSignal.timeout(fetchTimeoutMs),
        });
    } catch (err) {
        throw wrapFetchError(err, "challenge request failed");
    }
    if (!createResp.ok) {
        // The body is not echoed: proxies and portals return HTML pages that do
        // not belong in error messages, UIs, or logs. `status` carries the code.
        throw new ProtectError("server", "challenge creation failed", createResp.status);
    }
    let parsed: unknown;
    try {
        parsed = await createResp.json();
    } catch (err) {
        // The body read shares the request timeout.
        if (err instanceof DOMException && err.name === "TimeoutError") {
            throw new ProtectError("timeout", "challenge request failed: timed out");
        }
        // HTTP 200 with a non-JSON body: captive portals, proxy or WAF block
        // pages, CDN error pages, empty responses.
        throw new ProtectError(
            "server",
            "challenge response was not valid JSON",
            createResp.status,
        );
    }
    const challenge = parseChallenge(parsed);
    if (challenge === null) {
        throw new ProtectError("server", "invalid challenge", createResp.status);
    }

    const solution = await solve(challenge, config.workerUrl, workerCount, solveTimeoutMs);

    let validateResp: Response;
    try {
        validateResp = await fetch(config.validateUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            credentials: "same-origin",
            cache: "no-store",
            body: JSON.stringify(solution),
            signal: AbortSignal.timeout(fetchTimeoutMs),
        });
    } catch (err) {
        throw wrapFetchError(err, "validation request failed");
    }
    if (!validateResp.ok) {
        throw new ProtectError("server", "solution validation failed", validateResp.status);
    }
}
