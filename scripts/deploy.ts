#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run=ssh,tar --allow-env=HOME,USER,XDG_CONFIG_HOME,TERM,NO_COLOR --allow-net
/**
 * Deploy script for webauthnp256-publickey-index.
 *
 * Usage:
 *   deno task deploy              # interactive: pick target, upload, activate
 *   deno task deploy rollback     # swap symlink to previous release
 *   deno task deploy status       # check remote status
 */
import {
  type DeployConfig,
  type DeployTarget,
  describeTarget,
  loadDeployConfig,
  saveDeployConfig,
  upsertTarget,
} from "./deploy/config.ts";
import { createSshSession } from "./deploy/ssh.ts";
import {
  CURRENT_LINK,
  DATA_DIR,
  ensureDirectories,
  ensureServiceUser,
  installDeno,
  installSudoers,
  probeRemote,
  RELEASES_DIR,
  releaseTag,
  swapSymlink,
  uploadRelease,
} from "./deploy/remote.ts";

const SYSTEMD_UNIT = "webauthnp256-publickey-index.service";
const ALERT_UNIT = "webauthnp256-alert.service";
const HTTP_PORT = 11256;

// ── Prompts ──

async function prompt(msg: string, defaultVal?: string): Promise<string> {
  const suffix = defaultVal ? ` [${defaultVal}]` : "";
  const buf = new Uint8Array(1024);
  await Deno.stdout.write(new TextEncoder().encode(`${msg}${suffix}: `));
  const n = await Deno.stdin.read(buf);
  const input = new TextDecoder().decode(buf.subarray(0, n ?? 0)).trim();
  return input || defaultVal || "";
}

async function choose(msg: string, options: string[]): Promise<number> {
  console.log(`\n${msg}`);
  options.forEach((o, i) => console.log(`  ${i + 1}) ${o}`));
  const ans = await prompt("Choice", "1");
  return Math.max(0, Math.min(options.length - 1, parseInt(ans) - 1));
}

// ── Main ──

async function main() {
  const subcommand = Deno.args[0] ?? "deploy";
  const cfg = await loadDeployConfig();

  if (subcommand === "deploy") {
    await runDeploy(cfg);
  } else if (subcommand === "status") {
    await runStatus(cfg);
  } else if (subcommand === "rollback") {
    await runRollback(cfg);
  } else {
    console.log("Usage: deno task deploy [deploy|status|rollback]");
  }
}

async function pickTarget(cfg: DeployConfig): Promise<{ target: DeployTarget; cfg: DeployConfig }> {
  let target: DeployTarget;

  if (cfg.targets.length > 0) {
    const options = [...cfg.targets.map(describeTarget), "+ Add new target"];
    if (cfg.lastTarget) {
      const last = cfg.targets.find((t) => t.name === cfg.lastTarget);
      if (last) options.unshift(`Last: ${describeTarget(last)}`);
    }
    const idx = await choose("Select deploy target:", options);
    if (cfg.lastTarget && idx === 0) {
      target = cfg.targets.find((t) => t.name === cfg.lastTarget)!;
    } else {
      const adjustedIdx = cfg.lastTarget ? idx - 1 : idx;
      if (adjustedIdx >= cfg.targets.length) {
        target = await promptNewTarget();
      } else {
        target = cfg.targets[adjustedIdx];
      }
    }
  } else {
    target = await promptNewTarget();
  }

  const updated = upsertTarget(cfg, target);
  await saveDeployConfig(updated);
  return { target, cfg: updated };
}

async function promptNewTarget(): Promise<DeployTarget> {
  const name = await prompt("Target name (e.g. prod, staging)");
  const host = await prompt("Host (IP or domain)");
  const port = parseInt(await prompt("SSH port", "22"));
  const user = await prompt("SSH user", "root");
  const authIdx = await choose("Auth method:", ["SSH key", "Password"]);
  const authMethod = authIdx === 0 ? "key" as const : "password" as const;
  let keyPath: string | undefined;
  if (authMethod === "key") {
    keyPath = await prompt("Key path", "~/.ssh/id_ed25519");
  }
  return { name, host, port, user, authMethod, keyPath };
}

async function runDeploy(cfg: DeployConfig) {
  console.log("\n--- WebAuthn P256 Public Key Index Deploy ---\n");

  const { target, cfg: updatedCfg } = await pickTarget(cfg);
  console.log(`\nTarget: ${describeTarget(target)}\n`);

  const ssh = createSshSession(target);
  try {
    console.log("-> Connecting...");
    await ssh.primeConnection();

    // Probe
    console.log("-> Checking remote...");
    const state = await probeRemote(ssh);
    console.log(`  Deno: ${state.denoInstalled ? `v${state.denoVersion}` : "NOT installed"}`);
    console.log(`  systemd: ${state.systemdAvailable ? "yes" : "no"}`);
    console.log(`  First deploy: ${state.firstTime ? "yes" : "no"}`);

    if (!state.systemdAvailable) {
      throw new Error("systemd not found -- required for service management");
    }

    // Bootstrap
    if (!state.denoInstalled) {
      console.log("-> Installing Deno...");
      await installDeno(ssh);
    }
    console.log("-> Ensuring service user...");
    await ensureServiceUser(ssh);
    console.log("-> Creating directories...");
    await ensureDirectories(ssh);

    // Prompt for .env on first deploy or if .env missing
    const envPath = `${DATA_DIR}/.env`;
    const envCheck = await ssh.runCapture(["bash", "-lc", `test -f ${envPath} && echo found || echo missing`]);
    if (state.firstTime || envCheck.stdout.trim() === "missing") {
      console.log("\n-> Configure environment variables:");
      const portVal = await prompt("PORT", "11256");
      const privateKey = await prompt("PRIVATE_KEY (server wallet, 0x...)");
      const queueDbPath = `${DATA_DIR}/queue.db`;
      const telegramBotToken = await prompt("TELEGRAM_BOT_TOKEN (optional)");
      const telegramChatId = await prompt("TELEGRAM_CHAT_ID (optional)");
      if (!privateKey) {
        console.log("  WARNING: PRIVATE_KEY not set -- POST /api/create will fail");
      }

      const envLines = [
        `PORT=${portVal}`,
        `QUEUE_DB_PATH=${queueDbPath}`,
        privateKey ? `PRIVATE_KEY=${privateKey}` : "# PRIVATE_KEY=0x...",
        telegramBotToken ? `TELEGRAM_BOT_TOKEN=${telegramBotToken}` : "# TELEGRAM_BOT_TOKEN=",
        telegramChatId ? `TELEGRAM_CHAT_ID=${telegramChatId}` : "# TELEGRAM_CHAT_ID=",
      ].join("\n");

      const writeCode = await ssh.runShell(`
        set -e
        cat <<'ENVEOF' | sudo tee ${envPath} >/dev/null
${envLines}
ENVEOF
        sudo chown webauthn:webauthn ${envPath}
        sudo chmod 0600 ${envPath}
      `);
      if (writeCode !== 0) throw new Error("failed to write .env file");
      console.log("  .env saved");
    }

    console.log("-> Installing sudoers...");
    await installSudoers(ssh, target.user);

    // Upload
    const tag = releaseTag();
    const releaseDir = `${RELEASES_DIR}/${tag}`;
    console.log(`-> Uploading release ${tag}...`);
    const repoRoot = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
    await uploadRelease(ssh, repoRoot, releaseDir);

    // Install systemd units (service + its OnFailure Telegram pager)
    console.log("-> Installing systemd units...");
    for (const unit of [SYSTEMD_UNIT, ALERT_UNIT]) {
      const unitBytes = await Deno.readFile(`${repoRoot}/deploy/systemd/${unit}`);
      const b64 = bytesToBase64(unitBytes);
      const installCode = await ssh.runShell(`
        set -e
        printf '%s' '${b64}' | base64 -d > /tmp/${unit}
        sudo mv /tmp/${unit} /etc/systemd/system/${unit}
        sudo chmod 644 /etc/systemd/system/${unit}
      `);
      if (installCode !== 0) throw new Error(`systemd unit install failed: ${unit}`);
    }
    const reloadCode = await ssh.runShell(`
      set -e
      sudo systemctl daemon-reload
      sudo systemctl enable ${SYSTEMD_UNIT}
    `);
    if (reloadCode !== 0) throw new Error("systemd enable failed");

    const remotePort = await readRemotePort(ssh);

    // Capture the LAST-KNOWN-GOOD release (what `current` points at now, before
    // we swap) so an auto-rollback returns to a release that WAS serving, not
    // merely "the newest other dir".
    const lkgOut = await ssh.runCapture(["bash", "-lc", `readlink ${CURRENT_LINK} 2>/dev/null | xargs -r basename`]);
    const lastKnownGood = lkgOut.stdout.trim();

    // Swap symlink
    console.log("-> Swapping symlink...");
    await swapSymlink(ssh, releaseDir);

    // Restart
    console.log("-> Restarting service...");
    await ssh.runShell(`sudo systemctl restart ${SYSTEMD_UNIT}`);

    // Health gate (JSON status; degraded still counts as serving).
    console.log("-> Waiting for health...");
    const healthy = await pollHealth(ssh, remotePort, 30);
    let liveRelease = tag;

    if (!healthy) {
      console.error("Health gate FAILED.");
      if (lastKnownGood && lastKnownGood !== tag) {
        console.error(`-> Rolling back to last-known-good release ${lastKnownGood}...`);
        await swapSymlink(ssh, `${RELEASES_DIR}/${lastKnownGood}`);
        await ssh.runShell(`sudo systemctl restart ${SYSTEMD_UNIT}`);
        const rolledHealthy = await pollHealth(ssh, remotePort, 15);
        liveRelease = lastKnownGood;
        console.error(rolledHealthy
          ? `Rolled back to ${lastKnownGood} (health OK). Failed release ${tag} kept for inspection.`
          : `Rolled back to ${lastKnownGood} but its health is INCONCLUSIVE — investigate NOW.`);
      } else {
        console.error("No last-known-good release to roll back to — the failed release stays live. Investigate immediately.");
      }
    }

    // Record only what is actually live now (never the failed tag).
    target.lastDeployedAt = new Date().toISOString();
    target.lastReleaseTag = liveRelease;
    await saveDeployConfig(upsertTarget(updatedCfg, target));

    // Summary
    console.log("\n" + "=".repeat(50));
    console.log(healthy ? "Deploy successful!" : "Deploy FAILED — rolled back (see above)");
    console.log(`  Live release: ${liveRelease}${healthy ? "" : `  (attempted: ${tag})`}`);
    console.log(`  Service: ${SYSTEMD_UNIT}`);
    console.log(`  HTTP:    http://${target.host}:${remotePort}/`);
    console.log("=".repeat(50) + "\n");
    if (!healthy) Deno.exit(1); // machine-visible failure
  } finally {
    await ssh.close();
  }
}

/** Read the service PORT from the remote .env (falls back to the default). */
async function readRemotePort(ssh: ReturnType<typeof createSshSession>): Promise<number> {
  const out = await ssh.runCapture(["bash", "-lc", `grep -E '^PORT=' ${DATA_DIR}/.env 2>/dev/null | tail -1 | cut -d= -f2`]);
  return parseInt(out.stdout.trim()) || HTTP_PORT;
}

/** Poll /api/health up to `tries` times (2s apart); JSON ok|degraded passes. */
async function pollHealth(ssh: ReturnType<typeof createSshSession>, port: number, tries: number): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const check = await ssh.runCapture(["bash", "-lc", `curl -sf http://127.0.0.1:${port}/api/health 2>/dev/null || true`]);
    try {
      const body = JSON.parse(check.stdout);
      if (body.status === "ok" || body.status === "degraded") return true;
    } catch { /* not up yet */ }
  }
  return false;
}

async function runStatus(cfg: DeployConfig) {
  if (cfg.targets.length === 0) {
    console.log("No targets configured. Run: deno task deploy");
    return;
  }
  const { target } = await pickTarget(cfg);
  const ssh = createSshSession(target);
  try {
    await ssh.primeConnection();
    console.log(`\n-> Status of ${describeTarget(target)}\n`);
    await ssh.run(["bash", "-lc", `sudo systemctl status ${SYSTEMD_UNIT} --no-pager 2>/dev/null || echo 'Service not found'`]);
    console.log("\n-> Current release:");
    await ssh.run(["bash", "-lc", `readlink ${CURRENT_LINK} 2>/dev/null || echo 'No current release'`]);
    console.log("\n-> Recent releases:");
    await ssh.run(["bash", "-lc", `ls -lt ${RELEASES_DIR}/ 2>/dev/null | head -5`]);
    const statusPort = await readRemotePort(ssh);
    console.log(`\n-> Health (port ${statusPort}):`);
    await ssh.run(["bash", "-lc", `curl -sf http://127.0.0.1:${statusPort}/api/health 2>/dev/null || echo 'Service not responding'`]);
  } finally {
    await ssh.close();
  }
}

async function runRollback(cfg: DeployConfig) {
  if (cfg.targets.length === 0) {
    console.log("No targets configured.");
    return;
  }
  const { target } = await pickTarget(cfg);
  const ssh = createSshSession(target);
  try {
    await ssh.primeConnection();
    const releases = await ssh.runCapture(["bash", "-lc", `ls -t ${RELEASES_DIR}/ 2>/dev/null`]);
    const dirs = releases.stdout.trim().split("\n").filter(Boolean);
    if (dirs.length < 2) {
      console.log("Not enough releases to rollback");
      return;
    }
    const current = await ssh.runCapture(["bash", "-lc", `readlink ${CURRENT_LINK} | xargs basename`]);
    const currentTag = current.stdout.trim();

    // Explicit target: `deno task deploy rollback <tag>` — the old "newest
    // non-current" heuristic OSCILLATED between the two newest releases and
    // could never reach older ones.
    const requested = Deno.args[1];
    let dest: string;
    if (requested) {
      if (!dirs.includes(requested)) {
        console.error(`Release '${requested}' not found. Available:\n  ${dirs.join("\n  ")}`);
        return;
      }
      dest = requested;
    } else {
      // Default: the release IMMEDIATELY OLDER than current (true rollback);
      // running it twice keeps going further back instead of ping-ponging.
      const idx = dirs.indexOf(currentTag);
      const older = idx >= 0 ? dirs[idx + 1] : dirs.find((d) => d !== currentTag);
      if (!older) {
        console.log(`No release older than current (${currentTag}). Use: deno task deploy rollback <tag>`);
        return;
      }
      dest = older;
    }

    console.log(`\nRolling back: ${currentTag} -> ${dest}`);
    await swapSymlink(ssh, `${RELEASES_DIR}/${dest}`);
    await ssh.runShell(`sudo systemctl restart ${SYSTEMD_UNIT}`);

    // Verify the rolled-back release actually serves.
    const portOut = await ssh.runCapture(["bash", "-lc", `grep -E '^PORT=' ${DATA_DIR}/.env 2>/dev/null | tail -1 | cut -d= -f2`]);
    const remotePort = parseInt(portOut.stdout.trim()) || HTTP_PORT;
    let healthy = false;
    for (let i = 0; i < 15; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const check = await ssh.runCapture(["bash", "-lc", `curl -sf http://127.0.0.1:${remotePort}/api/health 2>/dev/null || true`]);
      try {
        const body = JSON.parse(check.stdout);
        if (body.status === "ok" || body.status === "degraded") { healthy = true; break; }
      } catch { /* not up yet */ }
    }
    console.log(healthy ? "Rollback complete — health OK" : "Rollback done but health check INCONCLUSIVE — investigate");
  } finally {
    await ssh.close();
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

main().catch((err) => {
  console.error("Deploy failed:", err.message);
  Deno.exit(1);
});
