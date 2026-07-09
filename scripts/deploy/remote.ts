import type { SshSession } from "./ssh.ts";

export const SERVICE_USER = "webauthn";
export const INSTALL_ROOT = "/opt/webauthnp256-publickey-index";
export const DATA_DIR = `${INSTALL_ROOT}/data`;
export const RELEASES_DIR = `${INSTALL_ROOT}/releases`;
export const CURRENT_LINK = `${INSTALL_ROOT}/current`;

function sh(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

export async function probeRemote(ssh: SshSession) {
  const deno = await ssh.runCapture([
    "bash", "-lc",
    'for p in /usr/local/bin/deno /usr/bin/deno; do if [ -x "$p" ]; then "$p" --version; exit 0; fi; done; exit 1',
  ]);
  const systemd = await ssh.runCapture(["bash", "-lc", "command -v systemctl"]);
  const current = await ssh.runCapture(["bash", "-lc", `test -L ${sh(CURRENT_LINK)}`]);
  return {
    denoInstalled: deno.code === 0 && /^deno [\d.]+/m.test(deno.stdout),
    denoVersion: deno.stdout.match(/^deno ([\d.]+)/m)?.[1],
    systemdAvailable: systemd.code === 0,
    firstTime: current.code !== 0,
  };
}

// Pinned: an unpinned install meant servers deployed at different times ran
// different Deno versions than CI verified. Bump together with ci.yml.
export const DENO_VERSION = "v2.7.5";

export async function installDeno(ssh: SshSession): Promise<void> {
  const code = await ssh.runShell(`
    set -e
    TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
    curl -fsSL https://deno.land/install.sh -o "$TMP"
    sudo -n env DENO_INSTALL=/usr/local sh "$TMP" --yes ${DENO_VERSION} || sudo env DENO_INSTALL=/usr/local sh "$TMP" --yes ${DENO_VERSION}
    sudo chmod 0755 /usr/local/bin/deno
    /usr/local/bin/deno --version
  `);
  if (code !== 0) throw new Error("Deno install failed");
}

export async function ensureServiceUser(ssh: SshSession): Promise<void> {
  const code = await ssh.runShell(`
    set -e
    if ! id -u ${SERVICE_USER} >/dev/null 2>&1; then
      sudo useradd --system --create-home --shell /usr/sbin/nologin --home-dir /var/lib/${SERVICE_USER} ${SERVICE_USER}
    fi
  `);
  if (code !== 0) throw new Error(`failed to ensure user ${SERVICE_USER}`);
}

export async function ensureDirectories(ssh: SshSession): Promise<void> {
  const code = await ssh.runShell(`
    set -e
    sudo mkdir -p ${sh(INSTALL_ROOT)} ${sh(RELEASES_DIR)} \
      ${sh(DATA_DIR)} ${sh(DATA_DIR + "/cache")} ${sh(DATA_DIR + "/cache/deno")}
    sudo chown -R ${SERVICE_USER}:${SERVICE_USER} ${sh(DATA_DIR)}
    sudo chmod 0750 ${sh(DATA_DIR)}
    sudo chown root:root ${sh(INSTALL_ROOT)}
    sudo chmod 0755 ${sh(INSTALL_ROOT)}
  `);
  if (code !== 0) throw new Error("failed to create directories");
}

export async function installSudoers(ssh: SshSession, deployUser: string): Promise<void> {
  const unit = "webauthnp256-publickey-index";
  const content = [
    `# Allow ${deployUser} to manage ${unit} without password.`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/systemctl start ${unit}*`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/systemctl stop ${unit}*`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/systemctl restart ${unit}*`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/systemctl enable ${unit}*`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/systemctl status ${unit}*`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/systemctl daemon-reload`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/ln -sfn ${RELEASES_DIR}/* ${CURRENT_LINK}`,
    `${deployUser} ALL=(root) NOPASSWD: /bin/rm -rf ${RELEASES_DIR}/*`,
    "",
  ].join("\n");
  const b64 = btoa(content);
  const code = await ssh.runShell(`
    set -e
    printf %s '${b64}' | base64 -d > /tmp/webauthn-sudoers.tmp
    chmod 0440 /tmp/webauthn-sudoers.tmp
    sudo visudo -cf /tmp/webauthn-sudoers.tmp
    sudo mv /tmp/webauthn-sudoers.tmp /etc/sudoers.d/${unit}
    sudo chown root:root /etc/sudoers.d/${unit}
  `);
  if (code !== 0) throw new Error("sudoers install failed");
}

export async function uploadRelease(ssh: SshSession, repoRoot: string, releaseDir: string): Promise<void> {
  const isMac = Deno.build.os === "darwin";
  const tarArgs = ["-czf", "-", "-C", repoRoot];
  if (isMac) tarArgs.push("--no-mac-metadata");
  tarArgs.push("deno", "shared", "deno.json");
  try {
    await Deno.stat(`${repoRoot}/deno.lock`);
    tarArgs.push("deno.lock");
  } catch { /* no lock file */ }

  const tarProc = new Deno.Command("tar", {
    args: tarArgs,
    stdin: "null", stdout: "piped", stderr: "piped",
  }).spawn();

  await ssh.runShell(`mkdir -p ${sh(releaseDir)}`, { stdio: "null" });
  const extractCode = await ssh.runWithStdin(
    ["tar", "-xzf", "-", "-C", releaseDir],
    tarProc.stdout,
  );
  const tarStatus = await tarProc.status;
  if (tarStatus.code !== 0) {
    const stderr = await new Response(tarProc.stderr).text();
    throw new Error(`local tar failed (exit ${tarStatus.code}): ${stderr.trim()}`);
  }
  if (extractCode !== 0) throw new Error(`remote tar extract failed (exit ${extractCode})`);

  await ssh.runShell(`chown -R ${SERVICE_USER}:${SERVICE_USER} ${sh(releaseDir)}`);
}

export async function swapSymlink(ssh: SshSession, releaseDir: string): Promise<void> {
  const code = await ssh.runShell(
    `sudo ln -sfn ${sh(releaseDir)} ${sh(CURRENT_LINK)} && sudo chown -h ${SERVICE_USER}:${SERVICE_USER} ${sh(CURRENT_LINK)}`,
  );
  if (code !== 0) throw new Error("symlink swap failed");
}

export function releaseTag(now = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${now.getUTCFullYear()}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}-${p(now.getUTCHours())}${p(now.getUTCMinutes())}${p(now.getUTCSeconds())}`;
}
