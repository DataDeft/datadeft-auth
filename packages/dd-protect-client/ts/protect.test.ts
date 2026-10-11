import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import {
    backoffDelayMs,
    protect,
    protectedFetch,
    ProtectError,
    type ProtectConfig,
} from "./protect";

// -- Helpers ------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}

function textResponse(body: string, status: number): Response {
    return new Response(body, { status });
}

const CHALLENGE = { chg: "abc123", dif: 1, tim: "1700000000", tag: "t1" };

const CREATE_URL = "/api/v1/session/pow/create";
const VALIDATE_URL = "/api/v1/session/pow/validate";

/** Call `protect` with the standard test config, overriding fields as needed. */
function callProtect(overrides: Partial<ProtectConfig> = {}): Promise<void> {
    return protect({
        workerUrl: "./worker.js",
        createUrl: CREATE_URL,
        validateUrl: VALIDATE_URL,
        ...overrides,
    });
}

// -- Mock Worker --------------------------------------------------------------

type OnMessage = ((event: MessageEvent) => void) | null;
type OnError = ((event: ErrorEvent) => void) | null;

class MockWorker {
    onmessage: OnMessage = null;
    onerror: OnError = null;
    terminated = false;

    // Subclasses override to control behavior.
    handlePostMessage(_data: unknown): void {}

    postMessage(data: unknown) {
        // Defer so the onmessage handler is attached first.
        setTimeout(() => this.handlePostMessage(data), 0);
    }

    terminate() {
        this.terminated = true;
    }
}

class SolvingMockWorker extends MockWorker {
    handlePostMessage(_data: unknown) {
        this.onmessage?.({
            data: { type: "solution", nonce: 42, hash: "0".repeat(64) },
        } as MessageEvent);
    }
}

class ErrorMockWorker extends MockWorker {
    handlePostMessage(_data: unknown) {
        this.onmessage?.({
            data: { type: "error", message: "sha256 failed" },
        } as MessageEvent);
    }
}

class CrashMockWorker extends MockWorker {
    handlePostMessage(_data: unknown) {
        this.onerror?.({ message: "script load failed" } as ErrorEvent);
    }
}

// -- Test setup ---------------------------------------------------------------

let originalFetch: typeof globalThis.fetch;
let originalWorker: typeof globalThis.Worker;

beforeEach(() => {
    originalFetch = globalThis.fetch;
    originalWorker = globalThis.Worker;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    globalThis.Worker = originalWorker;
});

function mockFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
        const url =
            typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        return Promise.resolve(handler(url, init));
    }) as unknown as typeof globalThis.fetch;
}

function installWorker(WorkerClass: new (url: string | URL) => MockWorker) {
    globalThis.Worker = WorkerClass as unknown as typeof Worker;
}

// -- Unit tests: protect() ----------------------------------------------------

describe("protect", () => {
    test("starts the distributed ESM worker as a module", async () => {
        let workerOptions: WorkerOptions | undefined;
        class ModuleWorker extends SolvingMockWorker {
            constructor(_url: string | URL, options?: WorkerOptions) {
                super();
                workerOptions = options;
            }
        }
        installWorker(ModuleWorker);
        mockFetch((url) => url === CREATE_URL ? jsonResponse(CHALLENGE) : jsonResponse({ status: "ok" }));

        await callProtect({ workerCount: 1 });

        expect(workerOptions?.type).toBe("module");
    });

    describe("challenge creation", () => {
        test("sends {} with JSON content type and same-origin credentials", async () => {
            let createInit: RequestInit | undefined;
            mockFetch((url, init) => {
                if (url === CREATE_URL) {
                    createInit = init;
                    return jsonResponse(CHALLENGE);
                }
                if (url === VALIDATE_URL) return jsonResponse({ status: "ok" }, 200);
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(SolvingMockWorker);

            await callProtect();

            expect(createInit?.method).toBe("POST");
            expect(createInit?.body).toBe("{}");
            expect(createInit?.credentials).toBe("same-origin");
            const headers = createInit?.headers as Record<string, string>;
            expect(headers["Content-Type"]).toBe("application/json");
        });

        test("throws ProtectError('timeout') when reading the challenge body times out", async () => {
            mockFetch((url) => {
                if (url !== CREATE_URL) throw new Error(`unexpected fetch: ${url}`);
                const response = jsonResponse(CHALLENGE);
                response.json = () =>
                    Promise.reject(new DOMException("body read timed out", "TimeoutError"));
                return response;
            });

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                expect((e as ProtectError).code).toBe("timeout");
            }
        });

        for (const [name, body] of [
            ["an HTML page", "<!doctype html><title>Wi-Fi login</title>"],
            ["an empty body", ""],
            ["truncated JSON", '{"chg":'],
        ] as const) {
            test(`throws ProtectError('server') when a 200 response is ${name}`, async () => {
                mockFetch((url) => {
                    if (url === CREATE_URL) return textResponse(body, 200);
                    throw new Error(`unexpected fetch: ${url}`);
                });

                try {
                    await callProtect();
                    expect.unreachable("should have thrown");
                } catch (e) {
                    expect(e).toBeInstanceOf(ProtectError);
                    const pe = e as ProtectError;
                    expect(pe.code).toBe("server");
                    expect(pe.status).toBe(200);
                    expect(pe.message).not.toContain("<");
                }
            });
        }

        test("throws ProtectError('server') on non-2xx", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) return textResponse("rate limited", 429);
                throw new Error(`unexpected fetch: ${url}`);
            });

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                const pe = e as ProtectError;
                expect(pe.code).toBe("server");
                expect(pe.status).toBe(429);
                // The response body is never echoed into the message.
                expect(pe.message).not.toContain("rate limited");
            }
        });

        test("throws ProtectError('network') on fetch TypeError", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) throw new TypeError("failed to fetch");
                throw new Error(`unexpected fetch: ${url}`);
            });

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                expect((e as ProtectError).code).toBe("network");
            }
        });

        test("throws ProtectError('timeout') on AbortSignal timeout", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) {
                    throw new DOMException("signal timed out", "TimeoutError");
                }
                throw new Error(`unexpected fetch: ${url}`);
            });

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                expect((e as ProtectError).code).toBe("timeout");
            }
        });
    });

    describe("solve", () => {
        test("throws ProtectError('solve') when the worker reports an error", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(ErrorMockWorker);

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                const pe = e as ProtectError;
                expect(pe.code).toBe("solve");
                expect(pe.message).toContain("sha256 failed");
            }
        });

        test("throws ProtectError('solve') when the worker crashes", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(CrashMockWorker);

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                const pe = e as ProtectError;
                expect(pe.code).toBe("solve");
                expect(pe.message).toContain("script load failed");
            }
        });

        test("throws ProtectError('solve') when the Worker constructor throws", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                throw new Error(`unexpected fetch: ${url}`);
            });
            globalThis.Worker = class {
                constructor() {
                    throw new Error("CSP violation");
                }
            } as unknown as typeof Worker;

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                const pe = e as ProtectError;
                expect(pe.code).toBe("solve");
                expect(pe.message).toContain("CSP violation");
            }
        });
    });

    describe("validation", () => {
        test("throws ProtectError('server') on non-2xx", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                if (url === VALIDATE_URL) return textResponse("", 403);
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(SolvingMockWorker);

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                const pe = e as ProtectError;
                expect(pe.code).toBe("server");
                expect(pe.status).toBe(403);
            }
        });

        test("throws ProtectError('network') on fetch failure", async () => {
            mockFetch((url) => {
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                if (url === VALIDATE_URL) throw new TypeError("connection reset");
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(SolvingMockWorker);

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                expect((e as ProtectError).code).toBe("network");
            }
        });

        test("sends only solution fields to the validate endpoint (no dif)", async () => {
            let validateBody: string | undefined;
            mockFetch((url, init) => {
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                if (url === VALIDATE_URL) {
                    validateBody = init?.body as string;
                    return jsonResponse({}, 200);
                }
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(SolvingMockWorker);

            await callProtect();

            const parsed = JSON.parse(validateBody!);
            expect(parsed.chg).toBe(CHALLENGE.chg);
            expect(parsed.sol).toBe("0".repeat(64));
            expect(parsed.non).toBe("42");
            expect(parsed.tim).toBe(CHALLENGE.tim);
            expect(parsed.tag).toBe(CHALLENGE.tag);
            // The client never sends `dif`; the server fills it from policy.
            expect(parsed.dif).toBeUndefined();
        });
    });

    describe("configuration", () => {
        test("uses the configured create and validate endpoints", async () => {
            const urls: string[] = [];
            const createUrl = "https://api.example.test/pow/create";
            const validateUrl = "https://api.example.test/pow/validate";
            mockFetch((url) => {
                urls.push(url);
                if (url === createUrl) return jsonResponse(CHALLENGE);
                if (url === validateUrl) return jsonResponse({}, 200);
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(SolvingMockWorker);

            await callProtect({ createUrl, validateUrl });

            expect(urls).toEqual([createUrl, validateUrl]);
        });
    });

    describe("happy path", () => {
        test("create → solve → validate completes without error", async () => {
            const urls: string[] = [];
            mockFetch((url) => {
                urls.push(url);
                if (url === CREATE_URL) return jsonResponse(CHALLENGE);
                if (url === VALIDATE_URL) return jsonResponse({}, 200);
                throw new Error(`unexpected fetch: ${url}`);
            });
            installWorker(SolvingMockWorker);

            await callProtect();

            expect(urls).toEqual([CREATE_URL, VALIDATE_URL]);
        });
    });
});

// -- Unit tests: ProtectError -------------------------------------------------

describe("input validation", () => {
    for (const [requested, expected] of [
        [0, 1],
        [-5, 1],
        [2.5, 2],
        [100, 8],
        [8, 8],
        [1, 1],
    ] as const) {
        test(`clamps workerCount ${requested} to ${expected}`, async () => {
            let started = 0;
            const strides: number[] = [];
            class CountingWorker extends SolvingMockWorker {
                constructor() {
                    super();
                    started += 1;
                }
                postMessage(data: unknown) {
                    strides.push((data as { step: number }).step);
                    super.postMessage(data);
                }
            }
            installWorker(CountingWorker);
            mockFetch(() => jsonResponse(CHALLENGE));

            await callProtect({ workerCount: requested });
            expect(started).toBe(expected);
            // Every worker strides by the clamped integer count.
            expect(strides.every((step) => step === expected)).toBe(true);
        });
    }

    test("falls back to the default for a non-finite workerCount", async () => {
        let started = 0;
        class CountingWorker extends SolvingMockWorker {
            constructor() {
                super();
                started += 1;
            }
        }
        installWorker(CountingWorker);
        mockFetch(() => jsonResponse(CHALLENGE));

        await callProtect({ workerCount: Number.NaN });
        expect(started).toBeGreaterThanOrEqual(1);
        expect(started).toBeLessThanOrEqual(8);
    });

    const longField = "a".repeat(257);
    const invalidChallenges: [string, unknown][] = [
        ["null", null],
        ["an array", [CHALLENGE]],
        ["an empty object", {}],
        ["a missing dif", { chg: "abc", tim: "t", tag: "g" }],
        ["dif 0", { ...CHALLENGE, dif: 0 }],
        ["dif 65", { ...CHALLENGE, dif: 65 }],
        ["a fractional dif", { ...CHALLENGE, dif: 2.5 }],
        ["a string dif", { ...CHALLENGE, dif: "1" }],
        ["a numeric chg", { ...CHALLENGE, chg: 123 }],
        ["an empty tag", { ...CHALLENGE, tag: "" }],
        ["a missing tim", { chg: "abc", dif: 1, tag: "g" }],
        ["an oversized chg", { ...CHALLENGE, chg: longField }],
    ];
    for (const [name, body] of invalidChallenges) {
        test(`rejects a challenge with ${name} without starting workers`, async () => {
            let workersStarted = 0;
            class CountingWorker extends SolvingMockWorker {
                constructor() {
                    super();
                    workersStarted += 1;
                }
            }
            installWorker(CountingWorker);
            mockFetch((url) => {
                if (url === CREATE_URL) return jsonResponse(body);
                throw new Error(`unexpected fetch: ${url}`);
            });

            try {
                await callProtect();
                expect.unreachable("should have thrown");
            } catch (e) {
                expect(e).toBeInstanceOf(ProtectError);
                const pe = e as ProtectError;
                expect(pe.code).toBe("server");
                expect(pe.status).toBe(200);
            }
            expect(workersStarted).toBe(0);
        });
    }
});

describe("ProtectError", () => {
    test("has the correct name, code, message, and status", () => {
        const e = new ProtectError("server", "bad request", 400);
        expect(e.name).toBe("ProtectError");
        expect(e.code).toBe("server");
        expect(e.message).toBe("bad request");
        expect(e.status).toBe(400);
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(ProtectError);
    });

    test("status is undefined for non-server errors", () => {
        const e = new ProtectError("network", "offline");
        expect(e.status).toBeUndefined();
    });
});

// -- protectedFetch -----------------------------------------------------------

describe("protectedFetch", () => {
    const API = "/api/v1/magic-link/request";
    const config: ProtectConfig = {
        workerUrl: "./worker.js",
        createUrl: CREATE_URL,
        validateUrl: VALIDATE_URL,
        workerCount: 1,
    };
    const powRequired = () =>
        new Response("{}", { status: 401, headers: { "WWW-Authenticate": "DD-PoW" } });
    const unavailable = () => new Response("{}", { status: 503 });

    test("solves once on 401 DD-PoW and retries the request once", async () => {
        installWorker(SolvingMockWorker);
        const calls: string[] = [];
        let apiCalls = 0;
        mockFetch((url) => {
            calls.push(url);
            if (url === CREATE_URL) return jsonResponse(CHALLENGE);
            if (url === VALIDATE_URL) return new Response(null, { status: 204 });
            apiCalls += 1;
            return apiCalls === 1 ? powRequired() : jsonResponse({ status: "ok" });
        });

        const response = await protectedFetch(API, { method: "POST", body: "{}" }, config);

        expect(response.status).toBe(200);
        expect(calls).toEqual([API, CREATE_URL, VALIDATE_URL, API]);
    });

    test("matches the DD-PoW scheme case-insensitively", async () => {
        installWorker(SolvingMockWorker);
        const calls: string[] = [];
        let apiCalls = 0;
        mockFetch((url) => {
            calls.push(url);
            if (url === CREATE_URL) return jsonResponse(CHALLENGE);
            if (url === VALIDATE_URL) return new Response(null, { status: 204 });
            apiCalls += 1;
            return apiCalls === 1
                ? new Response("{}", { status: 401, headers: { "WWW-Authenticate": "dd-pow" } })
                : jsonResponse({ status: "ok" });
        });

        const response = await protectedFetch(API, { method: "POST", body: "{}" }, config);

        expect(response.status).toBe(200);
        expect(calls).toEqual([API, CREATE_URL, VALIDATE_URL, API]);
    });

    test("solves at most once: a second DD-PoW challenge is returned", async () => {
        installWorker(SolvingMockWorker);
        let solves = 0;
        mockFetch((url) => {
            if (url === CREATE_URL) {
                solves += 1;
                return jsonResponse(CHALLENGE);
            }
            if (url === VALIDATE_URL) return new Response(null, { status: 204 });
            return powRequired();
        });

        const response = await protectedFetch(API, { method: "POST", body: "{}" }, config);

        expect(response.status).toBe(401);
        expect(solves).toBe(1);
    });

    test("passes the app's own 401 and 403 through untouched", async () => {
        for (const status of [401, 403]) {
            let calls = 0;
            mockFetch(() => {
                calls += 1;
                return new Response("{}", { status });
            });
            const response = await protectedFetch(API, undefined, config);
            expect(response.status).toBe(status);
            expect(calls).toBe(1);
        }
    });

    test("backs off with equal jitter on 503 for a repeatable request", async () => {
        const waits: number[] = [];
        let calls = 0;
        mockFetch(() => {
            calls += 1;
            return calls < 3 ? unavailable() : jsonResponse({ status: "ok" });
        });

        const response = await protectedFetch(API, undefined, config, {
            sleep: (ms) => {
                waits.push(ms);
                return Promise.resolve();
            },
            random: () => 0,
        });

        expect(response.status).toBe(200);
        expect(waits).toEqual([500, 1_000]);
    });

    test("gives up after the configured retries and returns the 503", async () => {
        const waits: number[] = [];
        mockFetch(() => unavailable());

        const response = await protectedFetch(API, { method: "GET" }, config, {
            unavailableRetries: 2,
            sleep: (ms) => {
                waits.push(ms);
                return Promise.resolve();
            },
            random: () => 0.999_999,
        });

        expect(response.status).toBe(503);
        expect(waits.length).toBe(2);
    });

    test("does not repeat a POST after 503 unless told it is repeatable", async () => {
        let calls = 0;
        mockFetch(() => {
            calls += 1;
            return unavailable();
        });
        const noWait = () => Promise.resolve();

        await protectedFetch(API, { method: "POST", body: "{}" }, config, { sleep: noWait });
        expect(calls).toBe(1);

        calls = 0;
        await protectedFetch(API, { method: "POST", body: "{}" }, config, {
            repeatable: true,
            sleep: noWait,
        });
        expect(calls).toBe(4);
    });
});

describe("protectedFetch retry accounting", () => {
    const API = "/api/v1/magic-link/request";
    const config: ProtectConfig = {
        workerUrl: "./worker.js",
        createUrl: CREATE_URL,
        validateUrl: VALIDATE_URL,
        workerCount: 1,
    };

    test("a non-finite retry count falls back to the default instead of looping", async () => {
        let calls = 0;
        mockFetch(() => {
            calls += 1;
            return new Response("{}", { status: 503 });
        });
        const response = await protectedFetch(API, undefined, config, {
            unavailableRetries: Number.NaN,
            sleep: () => Promise.resolve(),
        });
        expect(response.status).toBe(503);
        expect(calls).toBe(4);
    });

    test("a solve does not use up a 503 retry, and backoff starts at the first step", async () => {
        installWorker(SolvingMockWorker);
        const waits: number[] = [];
        let apiCalls = 0;
        mockFetch((url) => {
            if (url === CREATE_URL) return jsonResponse(CHALLENGE);
            if (url === VALIDATE_URL) return new Response(null, { status: 204 });
            apiCalls += 1;
            if (apiCalls === 1) {
                return new Response("{}", {
                    status: 401,
                    headers: { "WWW-Authenticate": "DD-PoW" },
                });
            }
            return new Response("{}", { status: 503 });
        });
        await protectedFetch(API, undefined, config, {
            sleep: (ms) => {
                waits.push(ms);
                return Promise.resolve();
            },
            random: () => 0,
        });
        expect(waits).toEqual([500, 1_000, 2_000]);
        expect(apiCalls).toBe(5);
    });
});

describe("backoffDelayMs", () => {
    test("equal jitter: at least half of the doubling step, capped at 30 s", () => {
        expect([1, 2, 3, 4].map((retry) => backoffDelayMs(retry, () => 0))).toEqual([
            500, 1_000, 2_000, 4_000,
        ]);
        expect([1, 2, 3, 4].map((retry) => backoffDelayMs(retry, () => 0.999_999))).toEqual([
            999, 1_999, 3_999, 7_999,
        ]);
        expect(backoffDelayMs(20, () => 0)).toBe(15_000);
        expect(backoffDelayMs(20, () => 0.999_999)).toBe(29_999);
    });
});
