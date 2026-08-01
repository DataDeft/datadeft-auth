// protect-worker.ts — proof-of-work solver Web Worker.
//
// Matches the dd-pow-core wire contract: SHA-256(challenge + nonce), lowercase
// hex, with `difficulty` leading zero hex characters (checked nibble by nibble).
// The nonce is reported as a decimal string.

interface WorkerIncomingData {
    challenge: string;
    difficulty: number;
    startNonce: number;
    step: number;
}

interface WorkerOutgoingMessage {
    type: "solution" | "error";
    nonce?: number;
    hash?: string;
    message?: string;
}

const ctx = self as DedicatedWorkerGlobalScope;

async function sha256(text: string): Promise<ArrayBuffer> {
    const encoded = new TextEncoder().encode(text);
    return crypto.subtle.digest("SHA-256", encoded);
}

function uint8ToHex(arr: Uint8Array): string {
    return Array.from(arr, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

ctx.onmessage = async (event: MessageEvent<WorkerIncomingData>) => {
    const { challenge, difficulty, startNonce, step } = event.data;
    let nonce = startNonce;

    try {
        while (true) {
            const input = challenge + nonce;
            const hashBuffer = await sha256(input);
            const hashArray = new Uint8Array(hashBuffer);

            let isValid = true;
            for (let i = 0; i < difficulty; i++) {
                const byteIndex = Math.floor(i / 2);
                // eslint-disable-next-line security/detect-object-injection -- fixed numeric index
                const currentByte = hashArray[byteIndex]!;
                const halfByteValue = i % 2 === 0 ? (currentByte >> 4) & 0x0f : currentByte & 0x0f;

                if (halfByteValue !== 0) {
                    isValid = false;
                    break;
                }
            }

            if (isValid) {
                const solutionMessage: WorkerOutgoingMessage = {
                    type: "solution",
                    nonce,
                    hash: uint8ToHex(hashArray),
                };
                ctx.postMessage(solutionMessage);
                break;
            }

            nonce += step;
            if (nonce > Number.MAX_SAFE_INTEGER - step) {
                throw new Error("nonce space exhausted");
            }
        }
    } catch (error) {
        const errorMessage: WorkerOutgoingMessage = {
            type: "error",
            message: error instanceof Error ? error.message : String(error),
        };
        ctx.postMessage(errorMessage);
    }
};

ctx.onerror = (event: ErrorEvent) => {
    const errorMessage: WorkerOutgoingMessage = {
        type: "error",
        message: `unhandled worker error: ${event.message}`,
    };
    ctx.postMessage(errorMessage);
};

export {};
