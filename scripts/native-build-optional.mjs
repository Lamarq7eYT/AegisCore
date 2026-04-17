import { execSync } from "node:child_process";
import process from "node:process";
import path from "node:path";

function hasCommand(command) {
  try {
    execSync(command, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function findVcvars64() {
  const programFilesX86 = process.env["ProgramFiles(x86)"];
  if (!programFilesX86) {
    return null;
  }

  const vswhere = path.join(programFilesX86, "Microsoft Visual Studio", "Installer", "vswhere.exe");
  if (!hasCommand(`"${vswhere}" -?`)) {
    return null;
  }

  try {
    const installationPath = execSync(
      `"${vswhere}" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`,
      { encoding: "utf8" }
    ).trim();
    const vcvars = path.join(installationPath, "VC", "Auxiliary", "Build", "vcvars64.bat");
    return vcvars;
  } catch {
    return null;
  }
}

const onWindows = process.platform === "win32";
const hasRust = hasCommand("cargo -V");
const hasLinker = onWindows ? hasCommand("where.exe link") : true;

if (!hasRust) {
  console.warn("[aegis] Cargo não está disponível; o binding Rust foi pulado no postinstall.");
  process.exit(0);
}

if (!hasLinker) {
  const vcvars = findVcvars64();
  if (!vcvars) {
    console.warn(
      "[aegis] link.exe não está disponível neste ambiente; o binding Rust foi pulado no postinstall. Use ALLOW_NATIVE_FALLBACK=true apenas em dev/teste."
    );
    process.exit(0);
  }

  execSync(`cmd /d /s /c ""${vcvars}" && pnpm --filter @aegis/native build"`, {
    stdio: "inherit"
  });
  process.exit(0);
}

execSync("pnpm --filter @aegis/native build", {
  stdio: "inherit"
});
