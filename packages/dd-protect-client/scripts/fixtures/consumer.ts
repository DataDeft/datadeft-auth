import { protect, ProtectError, type ProtectConfig, type ProtectErrorCode } from "@datadeft/protect-client";
import "@datadeft/protect-client/worker";

const config: ProtectConfig = {
    workerUrl: "/pow-worker.js",
    createUrl: "/pow/create",
    validateUrl: "/pow/validate",
};
const flow: Promise<void> = protect(config);
const code: ProtectErrorCode = new ProtectError("solve", "example").code;
void flow;
void code;
