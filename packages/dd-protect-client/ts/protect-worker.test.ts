import { describe, test, expect } from "bun:test";
import { resolve } from "node:path";

// -- Helpers ------------------------------------------------------------------

const WORKER_PATH = resolve(import.meta.dir, "protect-worker.ts");

interface WorkerResult {
    type: "solution" | "error";
    nonce?: number;
    hash?: string;
    message?: string;
}

function runWorker(data: {
    challenge: string;
    difficulty: number;
    startNonce: number;
    step: number;
}): Promise<WorkerResult> {
    return new Promise((resolve, reject) => {
        const worker = new Worker(WORKER_PATH);
        const timeout = setTimeout(() => {
            worker.terminate();
            reject(new Error("worker timed out after 10s"));
        }, 10_000);

        worker.onmessage = (event: MessageEvent<WorkerResult>) => {
            clearTimeout(timeout);
            worker.terminate();
            resolve(event.data);
        };

        worker.onerror = (error) => {
            clearTimeout(timeout);
            worker.terminate();
            reject(new Error(error.message));
        };

        worker.postMessage(data);
    });
}

function hasLeadingZeroNibbles(hex: string, count: number): boolean {
    for (let i = 0; i < count; i++) {
        // eslint-disable-next-line security/detect-object-injection -- fixed numeric index
        if (hex[i] !== "0") return false;
    }
    return true;
}

async function sha256hex(text: string): Promise<string> {
    const encoded = new TextEncoder().encode(text);
    const buffer = await crypto.subtle.digest("SHA-256", encoded);
    const arr = new Uint8Array(buffer);
    return Array.from(arr, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// -- Integration tests: worker solves real challenges -------------------------

describe("protect-worker", () => {
    test("solves difficulty 1 challenge", async () => {
        const result = await runWorker({
            challenge: "test-challenge-d1",
            difficulty: 1,
            startNonce: 0,
            step: 1,
        });

        expect(result.type).toBe("solution");
        expect(result.nonce).toBeDefined();
        expect(result.hash).toBeDefined();
        expect(hasLeadingZeroNibbles(result.hash!, 1)).toBe(true);
    });

    test("solves difficulty 2 challenge", async () => {
        const result = await runWorker({
            challenge: "test-challenge-d2",
            difficulty: 2,
            startNonce: 0,
            step: 1,
        });

        expect(result.type).toBe("solution");
        expect(hasLeadingZeroNibbles(result.hash!, 2)).toBe(true);
    });

    test("solves difficulty 3 challenge", async () => {
        const result = await runWorker({
            challenge: "test-challenge-d3",
            difficulty: 3,
            startNonce: 0,
            step: 1,
        });

        expect(result.type).toBe("solution");
        expect(hasLeadingZeroNibbles(result.hash!, 3)).toBe(true);
    });

    test("solution hash matches SHA-256(challenge + nonce)", async () => {
        const challenge = "verify-hash-test";
        const result = await runWorker({
            challenge,
            difficulty: 1,
            startNonce: 0,
            step: 1,
        });

        expect(result.type).toBe("solution");
        const expected = await sha256hex(challenge + result.nonce);
        expect(result.hash).toBe(expected);
    });

    test("stride partitioning: worker with startNonce=2 step=4 finds solution", async () => {
        const result = await runWorker({
            challenge: "stride-test",
            difficulty: 1,
            startNonce: 2,
            step: 4,
        });

        expect(result.type).toBe("solution");
        // Nonce must be in the worker's partition: 2, 6, 10, 14, ...
        expect(result.nonce! % 4).toBe(2);
        expect(hasLeadingZeroNibbles(result.hash!, 1)).toBe(true);
    });

    test("multiple workers find solutions in disjoint nonce ranges", async () => {
        const workerCount = 4;
        const challenge = "parallel-test";
        const results = await Promise.all(
            Array.from({ length: workerCount }, (_, i) =>
                runWorker({
                    challenge,
                    difficulty: 1,
                    startNonce: i,
                    step: workerCount,
                }),
            ),
        );

        for (let i = 0; i < workerCount; i++) {
            // eslint-disable-next-line security/detect-object-injection -- fixed numeric index
            const result = results[i]!;
            expect(result.type).toBe("solution");
            expect(result.nonce! % workerCount).toBe(i);
        }
    });

    test("difficulty 0 accepts any hash (nonce 0)", async () => {
        const result = await runWorker({
            challenge: "trivial",
            difficulty: 0,
            startNonce: 0,
            step: 1,
        });

        expect(result.type).toBe("solution");
        expect(result.nonce).toBe(0);
    });
});
