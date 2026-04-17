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
    return path.join(installationPath, "VC", "Auxiliary", "Build", "vcvars64.bat");
  } catch {
    return null;
  }
}

const onWindows = process.platform === "win32";
const hasRust = hasCommand("cargo -V");
const hasLinker = onWindows ? hasCommand("where.exe link") : true;

if (!hasRust) {
  console.warn(
    "[aegis] Testes Rust foram pulados neste ambiente porque cargo não está disponível."
  );
  process.exit(0);
}

if (!hasLinker) {
  const vcvars = findVcvars64();
  if (!vcvars) {
    console.warn(
      "[aegis] Testes Rust foram pulados neste ambiente. Para executar o binding nativo e os testes Rust no Windows, instale o toolchain MSVC com link.exe."
    );
    process.exit(0);
  }

  execSync(
    `cmd /d /s /c ""${vcvars}" && cargo test --manifest-path native/Cargo.toml -p payload_normalizer -p request_inspector -p risk_scoring_core -p security_parser"`,
    {
      stdio: "inherit"
    }
  );
  process.exit(0);
}

execSync(
  "cargo test --manifest-path native/Cargo.toml -p payload_normalizer -p request_inspector -p risk_scoring_core -p security_parser",
  {
    stdio: "inherit"
  }
);
