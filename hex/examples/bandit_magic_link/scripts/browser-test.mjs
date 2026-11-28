import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { createServer } from "node:net";
import { createInterface } from "node:readline";
import { chromium } from "playwright";

const confirmPage = "/auth/magic-link/confirm";
const consume = "/auth/magic-link/consume";
const complete = "/auth/magic-link/complete";

class CheckFailed extends Error {}

function check(condition, message) {
  if (!condition) throw new CheckFailed(message);
}

async function unusedPort() {
  const socket = createServer();
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", resolve);
  });
  const { port } = socket.address();
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

function waitForMailbox(child) {
  const lines = createInterface({ input: child.stdout });
  const prefix = "Private mailbox: ";
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("startup timeout")), 45_000);
    child.once("error", reject);
    child.once("exit", () => reject(new Error("example exited")));
    lines.on("line", (line) => {
      if (line.startsWith(prefix)) {
        clearTimeout(timer);
        resolve(line.slice(prefix.length));
      }
    });
    child.once("close", () => clearTimeout(timer));
  });
}

function stop(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

// Playwright fulfills the foreign origin locally. The browser's form request
// to the example is real and carries browser-computed Origin and Fetch Metadata.
async function foreignForm(context, foreign, target, fields = {}) {
  const attacker = await context.newPage();
  try {
    await attacker.route(foreign + "/form", (route) =>
      route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Foreign origin</title>" }),
    );
    await attacker.goto(foreign + "/form");
    const [response] = await Promise.all([
      attacker.waitForResponse((r) => r.url() === target),
      attacker.evaluate(
        ({ target, fields }) => {
          const form = document.createElement("form");
          form.setAttribute("method", "post");
          form.setAttribute("action", target);
          for (const [name, value] of Object.entries(fields)) {
            const input = document.createElement("input");
            input.setAttribute("type", "hidden");
            input.setAttribute("name", name);
            input.value = value;
            form.append(input);
          }
          document.body.append(form);
          form.submit();
        },
        { target, fields },
      ),
    ]);
    check(response.status() === 400, "a foreign-origin form was not refused");
    check((await response.headerValue("set-cookie")) === null, "a foreign form cleared state");
  } finally {
    await attacker.close();
  }
}

let phase = "start the demo";
let child;
let browser;
try {
  const port = await unusedPort();
  const base = `http://127.0.0.1:${port}`;
  const foreign = `http://127.0.0.1:${await unusedPort()}`;
  child = spawn("mix", ["run", "--no-halt"], {
    detached: true,
    stdio: ["ignore", "pipe", "ignore"],
    env: { ...process.env, PORT: String(port) },
  });
  const mailbox = await waitForMailbox(child);
  phase = "launch Chromium";
  browser = await chromium.launch();
  const human = await browser.newContext();
  const scanner = await browser.newContext();
  const page = await human.newPage();
  const scannerPage = await scanner.newPage();

  phase = "request a link in the browser";
  await page.goto(base);
  await page.getByLabel("Accept the demo terms").check();
  await page.getByLabel("Accept the demo privacy policy").check();
  await page.getByRole("button", { name: "Request sign-in link" }).click();
  await page.getByText("Request accepted.", { exact: false }).waitFor();
  check(((await stat(mailbox)).mode & 0o777) === 0o600, "mailbox is not private");
  const link = (await readFile(mailbox, "utf8")).trim();
  const parsed = new URL(link);
  const token = parsed.searchParams.get("token");
  check(parsed.origin === base && Boolean(token), "mail did not contain a local sign-in link");

  phase = "scanner opens the link without signing in";
  await scannerPage.goto(link);
  check(scannerPage.url() === base + confirmPage, "landing did not scrub the URL");
  const scannerCookies = await scanner.cookies();
  check(
    scannerCookies.some((c) => c.name === "dd_auth_confirm"),
    "scanner received no confirm cookie",
  );
  check(!scannerCookies.some((c) => c.name === "dd_session"), "scanner got a session from a GET");
  check((await scannerPage.goto(base + "/me")).status() === 401, "scanner accessed the protected page");

  phase = "display the account and scrub the bearer";
  const relatedRequests = [];
  page.on("request", (r) => relatedRequests.push(r));
  const pageResponse = await page.goto(link);
  check((await pageResponse.headerValue("cache-control")) === "no-store", "confirm page was cacheable");
  check((await pageResponse.headerValue("x-frame-options")) === "DENY", "confirm page allowed framing");
  const button = page.getByRole("button", { name: "Continue sign in" });
  await button.waitFor();
  check((await page.locator("#account").textContent()) === "a•••••@example.test", "account was not displayed");
  check(page.url() === base + confirmPage, "browser URL retained the bearer");
  check(!(await page.content()).includes(token), "confirm HTML included the bearer");
  for (const request of relatedRequests) {
    if (request.url() !== link) {
      check(!request.url().includes(token), "a subrequest URL included the bearer");
      const referer = (await request.allHeaders()).referer;
      check(!referer?.includes(token), "a referrer included the bearer");
    }
  }
  const nonce = await page.locator('[name="confirmation"]').inputValue();
  const flow = (await human.cookies()).find((c) => c.name === "dd_auth_confirm");
  check(flow?.httpOnly && flow.path === "/auth" && flow.sameSite === "Lax", "flow cookie policy was wrong");

  phase = "reject a real cross-origin confirmation";
  await foreignForm(human, foreign, base + consume, { confirmation: nonce });

  phase = "confirm deliberately and authenticate a live session";
  await Promise.all([page.waitForURL(base + complete), button.click()]);
  await page.getByRole("heading", { name: "Signed in" }).waitFor();
  const cookies = await human.cookies();
  check(!cookies.some((c) => c.name === "dd_auth_confirm"), "confirm cookie survived success");
  const session = cookies.find((c) => c.name === "dd_session");
  check(session?.httpOnly && session.path === "/" && session.sameSite === "Lax", "session cookie policy was wrong");

  phase = "reject confirmation replay";
  const replay = await fetch(base + consume, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      origin: base,
      cookie: `dd_auth_confirm=${flow.value}`,
    },
    body: JSON.stringify({ confirmation: nonce }),
  });
  check(replay.status === 400, "consumed link was replayable");
  check(!replay.headers.getSetCookie().some((c) => c.startsWith("dd_session=")), "replay set a session");

  phase = "reject a real cross-origin logout and revoke on the intended POST";
  await foreignForm(human, foreign, base + "/auth/logout");
  check((await page.reload()).status() === 200, "foreign form ended the session");
  await Promise.all([page.waitForURL(base + "/"), page.getByRole("button", { name: "Sign out" }).click()]);
  check(!(await human.cookies()).some((c) => c.name === "dd_session"), "logout did not clear the cookie");
  const revoked = await fetch(base + "/me", { headers: { cookie: `dd_session=${session.value}` } });
  check(
    revoked.status === 401 && revoked.headers.get("www-authenticate") === "DD-Session",
    "saved cookie still authenticated after logout",
  );

  console.log("Bandit + Chromium: scanner, confirmation, protected page, replay and logout passed.");
} catch (error) {
  // Browser protocol errors may include request URLs or headers. Do not dump
  // them (or screenshots/HAR files) even for this synthetic demo.
  console.error(error instanceof CheckFailed ? error.message : `Browser smoke failed: ${phase}.`);
  process.exitCode = 1;
} finally {
  try {
    await browser?.close();
  } finally {
    stop(child);
  }
}
