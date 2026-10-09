// Mutation check for the TLA+ models: every invariant must be able to fail.
//
// Each mutant edits one model (or flips one constant) the way a plausible bug
// in the Rust code would, and runs the checker with ONLY the target invariant
// (or the deadlock check) enabled. The mutant passes the harness only when the
// checker reports that exact violation. A mutant the checker accepts means the
// invariant has no teeth, and this script fails.
//
// Run: mise run spec-mutants

import { $ } from "bun";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type Mutant = {
  name: string;
  spec: string; // model file name in spec/tla
  config?: string; // cfg file name; default <spec>.cfg
  edits?: [string, string][]; // exact, unique text replacements
  constants?: Record<string, string>;
  // Expected failure: an invariant name, or "deadlock".
  expect: string;
  liveness?: boolean;
};

const MUTANTS: Mutant[] = [
  // --- MagicLink.tla -------------------------------------------------------
  {
    name: "GET landing consumes the challenge",
    spec: "MagicLink",
    edits: [[
      "    /\\ landed' = TRUE\n    /\\ UNCHANGED << challenge, session, consumedByPost,",
      "    /\\ landed' = TRUE\n    /\\ challenge' = \"Consumed\"\n    /\\ UNCHANGED << session, consumedByPost,",
    ]],
    expect: "Inv001_LandingNeverConsumes",
  },
  {
    name: "confirm does not require an unconsumed challenge",
    spec: "MagicLink",
    edits: [[
      "ConfirmCorrect ==\n    /\\ challenge = \"Issued\"",
      "ConfirmCorrect ==\n    /\\ challenge \\in {\"Issued\", \"Consumed\"}",
    ]],
    expect: "Inv002_AtMostOneSession",
  },
  {
    name: "confirm creates a session without consuming",
    spec: "MagicLink",
    edits: [["    /\\ challenge' = \"Consumed\"\n    /\\ session' = \"Active\"", "    /\\ challenge' = challenge\n    /\\ session' = \"Active\""]],
    expect: "Inv003_SessionImpliesConsumed",
  },
  {
    name: "confirm consumes without creating a session",
    spec: "MagicLink",
    edits: [["    /\\ challenge' = \"Consumed\"\n    /\\ session' = \"Active\"", "    /\\ challenge' = \"Consumed\"\n    /\\ session' = session"]],
    expect: "Inv003_ConsumedImpliesSession",
  },
  {
    name: "wrong binding creates a session",
    spec: "MagicLink",
    edits: [[
      "    /\\ rejectedWrongBinding' = TRUE\n    /\\ UNCHANGED << challenge, session, landed,",
      "    /\\ rejectedWrongBinding' = TRUE\n    /\\ session' = \"Active\"\n    /\\ UNCHANGED << challenge, landed,",
    ]],
    expect: "Inv004_SessionNeedsCorrectBinding",
  },
  {
    name: "wrong binding burns the challenge",
    spec: "MagicLink",
    edits: [[
      "    /\\ rejectedWrongBinding' = TRUE\n    /\\ UNCHANGED << challenge, session, landed,",
      "    /\\ rejectedWrongBinding' = TRUE\n    /\\ challenge' = \"Consumed\"\n    /\\ UNCHANGED << session, landed,",
    ]],
    expect: "Inv004_ConsumeNeedsCorrectBinding",
  },
  {
    name: "disabled-user confirm burns the challenge",
    spec: "MagicLink",
    edits: [[
      "    /\\ disabledConfirmAttempted' = TRUE\n    /\\ UNCHANGED << challenge, session,",
      "    /\\ disabledConfirmAttempted' = TRUE\n    /\\ challenge' = \"Consumed\"\n    /\\ UNCHANGED << session,",
    ]],
    expect: "Inv005_DisabledAttemptDoesNotBurn",
  },
  // --- MagicLinkRace.tla ---------------------------------------------------
  {
    name: "commit is not conditional on an unconsumed challenge",
    spec: "MagicLinkRace",
    edits: [[
      "CommitSucceeds(a) ==\n    /\\ clientStatus[a] \\in {\"pending\", \"ambiguous\"}\n    /\\ challenge = \"Issued\"",
      "CommitSucceeds(a) ==\n    /\\ clientStatus[a] \\in {\"pending\", \"ambiguous\"}",
    ]],
    expect: "Inv_AtMostOneSession",
  },
  // --- Session.tla: validation and refresh (Session.cfg) -------------------
  {
    name: "validation ignores revocation",
    spec: "Session",
    edits: [["         /\\ NotRevoked(s)\n", ""]],
    constants: { WithAdmin: "FALSE" },
    expect: "Inv_NoAcceptRevoked",
  },
  {
    name: "validation ignores the idle bound",
    spec: "Session",
    edits: [["    /\\ Sat(v, c.ts) <= Idle\n", ""]],
    expect: "Inv_NoAcceptPastIdle",
  },
  {
    name: "validation ignores every absolute bound",
    spec: "Session",
    edits: [
      ["    /\\ Sat(v, c.iat) <= Abs\n", ""],
      ["    /\\ Sat(v, rec[s].created) <= Abs\n", ""],
      ["         /\\ StorageLive(s, v)\n", ""],
    ],
    expect: "Inv_NoAcceptPastAbsolute",
  },
  {
    name: "refresh re-stamps iat",
    spec: "Session",
    edits: [["[iat |-> c.iat, ts |-> r, tm |-> now]", "[iat |-> r, ts |-> r, tm |-> now]"]],
    expect: "Inv_RefreshKeepsIat",
  },
  {
    name: "refresh ignores the absolute lifetime",
    spec: "Session",
    edits: [["          /\\ BeforeAbs(c, r)\n", ""]],
    expect: "Inv_RefreshNeverPastAbsolute",
  },
  {
    name: "refresh accepts a stale validation",
    spec: "Session",
    edits: [["       IN /\\ SameRequest(v, r)\n          /\\ RefreshDue(c, r)", "       IN /\\ RefreshDue(c, r)"]],
    expect: "Inv_RefreshOnlyFromFreshValidation",
  },
  // --- Session.tla: admin (SessionAdmin.cfg) -------------------------------
  {
    name: "validation ignores a disabled owner",
    spec: "Session",
    config: "SessionAdmin",
    edits: [["         /\\ OwnerEnabled\n", ""]],
    expect: "Inv_NoAcceptDisabledOwner",
  },
  {
    name: "validation ignores the enable watermark",
    spec: "Session",
    config: "SessionAdmin",
    edits: [["         /\\ AfterWatermark(s)\n", ""]],
    expect: "Inv_NoAcceptAtOrBeforeWatermark",
  },
  {
    name: "0.4.1 enable: re-enable without revoking first (finding SES-F1)",
    spec: "Session",
    config: "SessionAdmin",
    constants: { EnableRevokesFirst: "FALSE" },
    expect: "Inv_NoPreEnableSurvivor",
  },
  // --- KeyRotation.tla -----------------------------------------------------
  {
    name: "0.4.1 create: no previous-key row (finding ROT-F1)",
    spec: "KeyRotation",
    constants: { DualWrite: "FALSE" },
    expect: "Inv_OneAccountPerEmail",
  },
  {
    // Dropping the previous-key fallback in find is not a safety mutant: the
    // fixed create's previous-key condition still refuses the duplicate (the
    // user sees a retryable conflict). The current-key condition is the one
    // safety rests on.
    name: "create is not conditional on the current-key row",
    spec: "KeyRotation",
    edits: [["    /\\ idx[Current(n)] = None\n    /\\ (DualWrite", "    /\\ (DualWrite"]],
    expect: "Inv_OneAccountPerEmail",
  },
  // --- Pow.tla -------------------------------------------------------------
  {
    name: "verify ignores the bound difficulty",
    spec: "Pow",
    edits: [["         /\\ w >= mintedDiff\n", ""]],
    expect: "Inv002_AcceptedMeetsMint",
  },
  {
    name: "verify checks the current policy, not the bound difficulty",
    spec: "Pow",
    edits: [["         /\\ w >= mintedDiff\n", "         /\\ w >= Effective(mintCountry)\n"]],
    expect: "Inv002_AcceptedMeetsMint",
  },
  {
    name: "mint ignores the production floor",
    spec: "Pow",
    edits: [["Effective(c) == Max3(Floor, Base, countryDiff[c])", "Effective(c) == countryDiff[c]"]],
    expect: "Inv003_MintMeetsFloor",
  },
  // --- Liveness.tla --------------------------------------------------------
  {
    name: "no retry after an ambiguous commit",
    spec: "Liveness",
    edits: [["    \\/ Retry\n", ""]],
    expect: "deadlock",
    liveness: true,
  },
];

const root = join(import.meta.dir, "..", "spec", "tla");

function applyEdits(text: string, edits: [string, string][], label: string): string {
  let out = text;
  for (const [from, to] of edits) {
    const first = out.indexOf(from);
    if (first < 0 || out.indexOf(from, first + 1) >= 0) {
      throw new Error(`${label}: edit anchor must match exactly once: ${JSON.stringify(from)}`);
    }
    out = out.slice(0, first) + to + out.slice(first + from.length);
  }
  return out;
}

// Keep SPECIFICATION and CONSTANT lines; keep only the target invariant.
function focusConfig(cfg: string, mutant: Mutant): string {
  const lines = cfg.split("\n").filter((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("INVARIANT") || trimmed.startsWith("PROPERTY")) {
      return mutant.expect !== "deadlock" && trimmed === `INVARIANT ${mutant.expect}`;
    }
    return true;
  });
  if (mutant.expect !== "deadlock" && !lines.some((l) => l.trim() === `INVARIANT ${mutant.expect}`)) {
    throw new Error(`${mutant.name}: ${mutant.expect} is not checked by the model's cfg`);
  }
  return lines.join("\n");
}

let failures = 0;
for (const mutant of MUTANTS) {
  const dir = mkdtempSync(join(tmpdir(), "spec-mutant-"));
  try {
    const source = readFileSync(join(root, `${mutant.spec}.tla`), "utf8");
    const cfg = readFileSync(join(root, `${mutant.config ?? mutant.spec}.cfg`), "utf8");
    writeFileSync(join(dir, `${mutant.spec}.tla`), applyEdits(source, mutant.edits ?? [], mutant.name));
    writeFileSync(join(dir, "mutant.cfg"), focusConfig(cfg, mutant));
    const args = [join(dir, `${mutant.spec}.tla`), "--config", join(dir, "mutant.cfg")];
    if (mutant.liveness) args.push("--check-liveness");
    else args.push("--allow-deadlock");
    for (const [name, value] of Object.entries(mutant.constants ?? {})) args.push("-c", `${name}=${value}`);

    const result = await $`tla ${args}`.nothrow().quiet();
    const output = result.stdout.toString() + result.stderr.toString();
    const caught =
      result.exitCode !== 0 &&
      (mutant.expect === "deadlock"
        ? output.includes("Deadlock detected")
        : output.includes(`(${mutant.expect}) violated`));
    console.log(`${caught ? "killed " : "SURVIVED"}  ${mutant.spec}: ${mutant.name}`);
    if (!caught) {
      failures += 1;
      console.log(output.split("\n").slice(-15).join("\n"));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (failures > 0) {
  console.error(`${failures} of ${MUTANTS.length} mutants survived: those invariants have no teeth.`);
  process.exit(1);
}
console.log(`All ${MUTANTS.length} mutants killed.`);
