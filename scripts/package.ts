import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import spawn, { sync as spawnSync } from "cross-spawn";
import {
  Arch,
  build as buildElectronApplication,
  Platform,
} from "electron-builder";

import { goCommand } from "./goCommand";
import { findBoxDirectory } from "./sing-box";
import { configureReproducibleBuild } from "./reproducibility";
import { readApplicationVersion, readGoVersion } from "./version";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const singBoxDirectory = findBoxDirectory();
const dashboardDirectory = path.join(repositoryRoot, "dashboard");
const signingConfigurationPath = path.join(
  repositoryRoot,
  "signing.local.json",
);
const developmentPackage = process.argv[2] === "dev";
const packageModeArgumentIndex = developmentPackage ? 3 : 2;
const packageMode = process.argv[packageModeArgumentIndex] ?? "win";
const packageArguments = process.argv
  .slice(packageModeArgumentIndex + 1)
  .filter((argument) => argument !== "--");

const sourceDateEpoch = configureReproducibleBuild([
  repositoryRoot,
  singBoxDirectory,
  dashboardDirectory,
]);
const goVersion = readGoVersion();

interface WindowsSigningConfiguration {
  certificateFile: string;
  certificatePassword: string;
}

function goEnvironment(): NodeJS.ProcessEnv {
  return { ...process.env, GOTOOLCHAIN: goVersion };
}

function runChecked(
  command: string,
  commandArguments: string[],
  environment?: NodeJS.ProcessEnv,
  workingDirectory = repositoryRoot,
) {
  const result = spawnSync(command, commandArguments, {
    cwd: workingDirectory,
    stdio: "inherit",
    env: environment ?? process.env,
  });
  if (result.error) {
    throw new Error(`${command}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} exited with code ${result.status ?? 1}`);
  }
}

function verifyGoVersion() {
  const result = spawnSync(goCommand(), ["env", "GOVERSION"], {
    cwd: singBoxDirectory,
    encoding: "utf-8",
    env: goEnvironment(),
  });
  if (result.error) {
    throw new Error(`go: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`go exited with code ${result.status ?? 1}`);
  }
  const actualVersion = result.stdout.trim();
  if (actualVersion !== goVersion) {
    throw new Error(
      `Go ${goVersion} is required, current version is ${actualVersion}`,
    );
  }
}

function runCheckedConcurrent(
  command: string,
  commandArguments: string[],
  environment?: NodeJS.ProcessEnv,
  workingDirectory = repositoryRoot,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArguments, {
      cwd: workingDirectory,
      stdio: "inherit",
      env: environment ?? process.env,
    });
    child.once("error", (error) =>
      reject(new Error(`${command}: ${error.message}`)),
    );
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `${command} exited with ${signal === null ? `code ${code ?? 1}` : `signal ${signal}`}`,
        ),
      );
    });
  });
}

function ensureGenerated() {
  if (!fs.existsSync(path.join(repositoryRoot, "dashboard", "package.json"))) {
    throw new Error(
      "dashboard submodule is not initialized, run: git submodule update --init --recursive",
    );
  }
  if (!fs.existsSync(path.join(repositoryRoot, "dashboard", "node_modules"))) {
    runChecked("pnpm", ["-C", "dashboard", "install", "--frozen-lockfile"]);
  }
  runChecked("pnpm", ["-C", "dashboard", "generate"]);
  runChecked("pnpm", ["generate"]);
}

function buildBoxdd(
  goOperatingSystem: string,
  goArchitecture: string,
  outputPath: string,
): Promise<void> {
  const suffix = goOperatingSystem === "windows" ? ".exe" : "";
  if (!outputPath.endsWith(suffix)) {
    throw new Error(
      `invalid ${goOperatingSystem} daemon output path: ${outputPath}`,
    );
  }
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  return runCheckedConcurrent(
    goCommand(),
    [
      "run",
      "./cmd/internal/build_boxdd",
      `-target=${goOperatingSystem}/${goArchitecture}`,
      `-output=${outputPath}`,
    ],
    goEnvironment(),
    singBoxDirectory,
  );
}

function portableExecutableMachine(filePath: string): number {
  const executable = fs.readFileSync(filePath);
  if (
    executable.length < 64 ||
    executable[0] !== 0x4d ||
    executable[1] !== 0x5a
  ) {
    throw new Error(`${filePath} is not a Windows executable`);
  }
  const headerOffset = executable.readUInt32LE(0x3c);
  if (
    headerOffset + 6 > executable.length ||
    executable[headerOffset] !== 0x50 ||
    executable[headerOffset + 1] !== 0x45 ||
    executable[headerOffset + 2] !== 0 ||
    executable[headerOffset + 3] !== 0
  ) {
    throw new Error(`${filePath} has an invalid Windows executable header`);
  }
  return executable.readUInt16LE(headerOffset + 4);
}

function verifyPortableExecutableArchitecture(
  filePath: string,
  expectedMachine: number,
) {
  const actualMachine = portableExecutableMachine(filePath);
  if (actualMachine !== expectedMachine) {
    throw new Error(
      `${filePath} has Windows machine 0x${actualMachine.toString(16)}, expected 0x${expectedMachine.toString(16)}`,
    );
  }
}

function stageWindowsCronetLibrary(
  goArchitecture: string,
  builderArchitecture: string,
) {
  const modulePath = `github.com/sagernet/cronet-go/lib/windows_${goArchitecture}`;
  const result = spawnSync(goCommand(), ["list", "-m", "-f", "{{.Dir}}", modulePath], {
    cwd: singBoxDirectory,
    encoding: "utf-8",
    env: goEnvironment(),
  });
  if (result.error) {
    throw new Error(`go: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `go exited with code ${result.status ?? 1}: ${(result.stderr || result.stdout).trim()}`,
    );
  }
  const moduleDirectory = result.stdout.trim();
  if (moduleDirectory === "") {
    throw new Error(`Go module has no source directory: ${modulePath}`);
  }
  const sourcePath = path.join(moduleDirectory, "libcronet.dll");
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Cronet library does not exist: ${sourcePath}`);
  }
  const destinationPath = path.join(
    repositoryRoot,
    "bin",
    "windows",
    builderArchitecture,
    "libcronet.dll",
  );
  fs.rmSync(destinationPath, { force: true });
  fs.copyFileSync(sourcePath, destinationPath);
  fs.chmodSync(destinationPath, 0o644);
}

function readWindowsSigningConfiguration(): WindowsSigningConfiguration | null {
  // VPN4TV: we have no Windows code-signing certificate yet. Without one the
  // build still works; SmartScreen just warns on first run.
  if (!fs.existsSync(signingConfigurationPath)) {
    console.warn(
      "[package] signing.local.json is absent: building an UNSIGNED package, SmartScreen will warn users",
    );
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(fs.readFileSync(signingConfigurationPath, "utf-8"));
  } catch (error) {
    throw new Error(`read ${path.basename(signingConfigurationPath)}`, {
      cause: error,
    });
  }
  const windows = (value as { windows?: unknown } | null)?.windows;
  if (
    typeof windows !== "object" ||
    windows === null ||
    typeof (windows as Record<string, unknown>).certificateFile !== "string" ||
    (windows as Record<string, unknown>).certificateFile === "" ||
    typeof (windows as Record<string, unknown>).certificatePassword !== "string"
  ) {
    throw new Error(
      `${path.basename(signingConfigurationPath)} has invalid Windows signing settings`,
    );
  }
  const configuration = windows as unknown as WindowsSigningConfiguration;
  const certificateFile = path.isAbsolute(configuration.certificateFile)
    ? configuration.certificateFile
    : path.resolve(repositoryRoot, configuration.certificateFile);
  if (!fs.existsSync(certificateFile)) {
    throw new Error(
      `Windows signing certificate does not exist: ${certificateFile}`,
    );
  }
  return { ...configuration, certificateFile };
}

async function runWindowsElectronBuilder(
  architecture: Arch,
  artifactArchitecture: string,
  signingConfiguration: WindowsSigningConfiguration | null,
): Promise<void> {
  const artifactName = `VPN4TV-Windows-\${version}-${artifactArchitecture}${developmentPackage ? "-dev" : ""}.\${ext}`;
  const unpackedDirectory = {
    x64: "win-unpacked",
    x86: "win-ia32-unpacked",
    arm64: "win-arm64-unpacked",
  }[artifactArchitecture];
  if (unpackedDirectory === undefined) {
    throw new Error(
      `unsupported Windows artifact architecture: ${artifactArchitecture}`,
    );
  }
  fs.rmSync(path.join(repositoryRoot, "release", unpackedDirectory), {
    recursive: true,
    force: true,
  });
  const previousBuildCacheSetting =
    process.env.ELECTRON_BUILDER_DISABLE_BUILD_CACHE;
  const previousArchiveFilter = process.env.ELECTRON_BUILDER_7Z_FILTER;
  process.env.ELECTRON_BUILDER_DISABLE_BUILD_CACHE = "true";
  if (architecture === Arch.arm64) {
    process.env.ELECTRON_BUILDER_7Z_FILTER = "BCJ2";
  }
  try {
    await buildElectronApplication({
      projectDir: repositoryRoot,
      targets: Platform.WINDOWS.createTarget("nsis", architecture),
      publish: "never",
      config: {
        compression: developmentPackage ? "store" : undefined,
        extends: path.join(repositoryRoot, "electron-builder.yml"),
        extraMetadata: { version: readApplicationVersion() },
        npmRebuild: false,
        win:
          signingConfiguration === null
            ? { artifactName, forceCodeSigning: false }
            : {
                artifactName,
                signtoolOptions: {
                  certificateFile: signingConfiguration.certificateFile,
                  certificatePassword: signingConfiguration.certificatePassword,
                },
              },
        nsis: { artifactName, warningsAsErrors: false },
      },
    });
  } finally {
    if (previousBuildCacheSetting === undefined) {
      delete process.env.ELECTRON_BUILDER_DISABLE_BUILD_CACHE;
    } else {
      process.env.ELECTRON_BUILDER_DISABLE_BUILD_CACHE =
        previousBuildCacheSetting;
    }
    if (previousArchiveFilter === undefined) {
      delete process.env.ELECTRON_BUILDER_7Z_FILTER;
    } else {
      process.env.ELECTRON_BUILDER_7Z_FILTER = previousArchiveFilter;
    }
  }
}

const windowsArchitectures = [
  {
    goArchitecture: "amd64",
    builderArchitecture: Arch.x64,
    builderArchitectureName: "x64",
    artifactArchitecture: "x64",
    portableExecutableMachine: 0x8664,
    includesCronet: true,
  },
  {
    goArchitecture: "386",
    builderArchitecture: Arch.ia32,
    builderArchitectureName: "ia32",
    artifactArchitecture: "x86",
    portableExecutableMachine: 0x014c,
    includesCronet: false,
  },
  {
    goArchitecture: "arm64",
    builderArchitecture: Arch.arm64,
    builderArchitectureName: "arm64",
    artifactArchitecture: "arm64",
    portableExecutableMachine: 0xaa64,
    includesCronet: true,
  },
] as const;

async function packageWindowsArchitecture(artifactArchitecture: string) {
  const architecture = windowsArchitectures.find(
    (candidate) => candidate.artifactArchitecture === artifactArchitecture,
  );
  if (architecture === undefined) {
    throw new Error(`unknown Windows architecture: ${artifactArchitecture}`);
  }
  const stagedPaths = ["sing-box-daemon.exe"];
  if (architecture.includesCronet) {
    stagedPaths.push("libcronet.dll");
  }
  for (const stagedPath of stagedPaths) {
    verifyPortableExecutableArchitecture(
      path.join(
        repositoryRoot,
        "bin",
        "windows",
        architecture.builderArchitectureName,
        stagedPath,
      ),
      architecture.portableExecutableMachine,
    );
  }
  const signingConfiguration = readWindowsSigningConfiguration();
  const startedAt = Date.now();
  console.info(`[package:${artifactArchitecture}] electron-builder started`);
  await runWindowsElectronBuilder(
    architecture.builderArchitecture,
    architecture.artifactArchitecture,
    signingConfiguration,
  );
  console.info(
    `[package:${artifactArchitecture}] electron-builder completed in ${Math.round((Date.now() - startedAt) / 1000)}s`,
  );
}

async function packageWindows() {
  const requestedArchitectures = new Set(packageArguments);
  const supportedArchitectures = new Set<string>(
    windowsArchitectures.map(
      (architecture) => architecture.artifactArchitecture,
    ),
  );
  for (const architecture of requestedArchitectures) {
    if (!supportedArchitectures.has(architecture)) {
      throw new Error(`unknown Windows architecture: ${architecture}`);
    }
  }
  const selectedArchitectures = windowsArchitectures.filter(
    (architecture) =>
      requestedArchitectures.size === 0 ||
      requestedArchitectures.has(architecture.artifactArchitecture),
  );
  runChecked("electron-vite", ["build"]);
  console.info(
    `[package] building Windows daemons concurrently: ${selectedArchitectures.map((architecture) => architecture.artifactArchitecture).join(", ")}`,
  );
  await Promise.all(
    selectedArchitectures.map(async (architecture) => {
      const outputPath = path.join(
        repositoryRoot,
        "bin",
        "windows",
        architecture.builderArchitectureName,
        "sing-box-daemon.exe",
      );
      await buildBoxdd("windows", architecture.goArchitecture, outputPath);
      verifyPortableExecutableArchitecture(
        outputPath,
        architecture.portableExecutableMachine,
      );
      const cronetLibraryPath = path.join(
        repositoryRoot,
        "bin",
        "windows",
        architecture.builderArchitectureName,
        "libcronet.dll",
      );
      if (architecture.includesCronet) {
        stageWindowsCronetLibrary(
          architecture.goArchitecture,
          architecture.builderArchitectureName,
        );
        verifyPortableExecutableArchitecture(
          cronetLibraryPath,
          architecture.portableExecutableMachine,
        );
      } else {
        fs.rmSync(cronetLibraryPath, { force: true });
      }
    }),
  );
  const buildEnvironment = {
    ...process.env,
    ELECTRON_BUILDER_DISABLE_BUILD_CACHE: "true",
  };
  console.info(
    `[package] running electron-builder concurrently: ${selectedArchitectures.map((architecture) => architecture.artifactArchitecture).join(", ")}`,
  );
  const results = await Promise.allSettled(
    selectedArchitectures.map((architecture) =>
      runCheckedConcurrent(
        "tsx",
        [
          "scripts/package.ts",
          ...(developmentPackage ? ["dev"] : []),
          "win-architecture",
          architecture.artifactArchitecture,
        ],
        buildEnvironment,
      ),
    ),
  );
  const failure = results.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (failure !== undefined) {
    throw failure.reason;
  }
}

const MAC_PRODUCT_NAME = "VPN4TV Desktop";

/**
 * electron-builder notarises the .app before it packs the DMG, so the image
 * itself stays unsigned and Gatekeeper rejects it on mount. Sign, notarise and
 * staple it here.
 */
function notarizeDiskImage(identity: string, artifactArchitecture: string) {
  const imagePath = path.join(
    repositoryRoot,
    "release",
    `VPN4TV-macOS-${readApplicationVersion()}-${artifactArchitecture}.dmg`,
  );
  if (!fs.existsSync(imagePath)) {
    throw new Error(`disk image does not exist: ${imagePath}`);
  }
  runChecked("codesign", ["--sign", `Developer ID Application: ${identity}`, "--timestamp", imagePath]);
  const credentials =
    process.env.APPLE_API_KEY !== undefined
      ? [
          "--key",
          process.env.APPLE_API_KEY,
          "--key-id",
          process.env.APPLE_API_KEY_ID ?? "",
          "--issuer",
          process.env.APPLE_API_ISSUER ?? "",
        ]
      : [
          "--apple-id",
          process.env.APPLE_ID ?? "",
          "--password",
          process.env.APPLE_APP_SPECIFIC_PASSWORD ?? "",
          "--team-id",
          process.env.APPLE_TEAM_ID ?? "",
        ];
  runChecked("xcrun", ["notarytool", "submit", imagePath, ...credentials, "--wait"]);
  runChecked("xcrun", ["stapler", "staple", imagePath]);
}

const macArchitectures = [
  { goArchitecture: "arm64", builderArchitectureArgument: "--arm64", artifactArchitecture: "arm64" },
  { goArchitecture: "amd64", builderArchitectureArgument: "--x64", artifactArchitecture: "x64" },
] as const;

/**
 * VPN4TV: only a "Developer ID Application" certificate is accepted outside the
 * App Store and by notarytool. Apple Development / Apple Distribution
 * certificates in the keychain do NOT qualify, so the build falls back to an
 * ad-hoc signature and says so.
 */
function macSigningIdentity(): string | null {
  applyMacSigningConfiguration();
  const override = process.env.VPN4TV_MAC_IDENTITY;
  if (override !== undefined && override !== "") {
    return override;
  }
  const result = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], {
    encoding: "utf-8",
  });
  if (result.status !== 0) {
    return null;
  }
  // electron-builder wants the common name without the certificate-type prefix.
  const match = /"Developer ID Application: ([^"]+)"/u.exec(result.stdout);
  return match === null ? null : match[1];
}

/**
 * notarytool credentials. electron-builder reads them from the environment; we
 * also accept them from signing.local.json so both platforms are configured in
 * one gitignored file:
 *
 *   "mac": { "appleId": "…", "appSpecificPassword": "…", "teamId": "…" }
 */
function macNotarizationConfigured(): boolean {
  applyMacSigningConfiguration();
  const { APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID, APPLE_API_KEY, APPLE_API_KEY_ID, APPLE_API_ISSUER } =
    process.env;
  const withAppleId =
    APPLE_ID !== undefined && APPLE_APP_SPECIFIC_PASSWORD !== undefined && APPLE_TEAM_ID !== undefined;
  const withApiKey =
    APPLE_API_KEY !== undefined && APPLE_API_KEY_ID !== undefined && APPLE_API_ISSUER !== undefined;
  return withAppleId || withApiKey;
}

function applyMacSigningConfiguration() {
  if (!fs.existsSync(signingConfigurationPath)) {
    return;
  }
  let mac: unknown;
  try {
    mac = (JSON.parse(fs.readFileSync(signingConfigurationPath, "utf-8")) as { mac?: unknown }).mac;
  } catch (error) {
    throw new Error(`read ${path.basename(signingConfigurationPath)}`, { cause: error });
  }
  if (typeof mac !== "object" || mac === null) {
    return;
  }
  const configuration = mac as Record<string, unknown>;
  const assign = (key: string, variable: string) => {
    const value = configuration[key];
    if (typeof value === "string" && value !== "" && process.env[variable] === undefined) {
      process.env[variable] = value;
    }
  };
  assign("appleId", "APPLE_ID");
  assign("appSpecificPassword", "APPLE_APP_SPECIFIC_PASSWORD");
  assign("teamId", "APPLE_TEAM_ID");
  assign("apiKey", "APPLE_API_KEY");
  assign("apiKeyId", "APPLE_API_KEY_ID");
  assign("apiIssuer", "APPLE_API_ISSUER");
  const identity = configuration.identity;
  if (typeof identity === "string" && identity !== "" && process.env.VPN4TV_MAC_IDENTITY === undefined) {
    process.env.VPN4TV_MAC_IDENTITY = identity;
  }
}

async function packageMac() {
  const requestedArchitectures = new Set(packageArguments);
  const supported = new Set<string>(macArchitectures.map((entry) => entry.artifactArchitecture));
  for (const architecture of requestedArchitectures) {
    if (!supported.has(architecture)) {
      throw new Error(`unknown macOS architecture: ${architecture}`);
    }
  }
  const selected = macArchitectures.filter(
    (architecture) =>
      requestedArchitectures.size === 0 ||
      requestedArchitectures.has(architecture.artifactArchitecture),
  );
  const identity = macSigningIdentity();
  const notarize = identity !== null && macNotarizationConfigured();
  if (identity === null) {
    console.warn(
      "[package] no Developer ID Application certificate: building an AD-HOC signed app." +
        " Gatekeeper will block it on other Macs (Privacy & Security -> Open Anyway).",
    );
  } else if (!notarize) {
    console.warn(
      "[package] signing with " +
        identity +
        " but NOT notarising: set APPLE_ID + APPLE_APP_SPECIFIC_PASSWORD + APPLE_TEAM_ID" +
        " (or APPLE_API_KEY + APPLE_API_KEY_ID + APPLE_API_ISSUER).",
    );
  }
  runChecked("electron-vite", ["build"]);
  for (const architecture of selected) {
    await buildBoxdd(
      "darwin",
      architecture.goArchitecture,
      path.join(repositoryRoot, "bin", "sing-box-daemon"),
    );
    runChecked("electron-builder", [
      "--mac",
      "dmg",
      architecture.builderArchitectureArgument,
      "--config",
      "electron-builder.yml",
      // VPN4TV: the native SwiftUI client also installs as VPN4TV.app, and the
      // one that lands second replaces the other. Only macOS needs the suffix.
      `--config.productName=${MAC_PRODUCT_NAME}`,
      `--config.extraMetadata.version=${readApplicationVersion()}`,
      ...(identity === null
        ? ["--config.mac.identity=null", "--config.mac.hardenedRuntime=false"]
        : [`--config.mac.identity=${identity}`]),
      `--config.mac.notarize=${notarize ? "true" : "false"}`,
      ...(developmentPackage ? ["--config.compression=store"] : []),
      "--publish",
      "never",
    ]);
    if (notarize && identity !== null) {
      notarizeDiskImage(identity, architecture.artifactArchitecture);
    }
  }
}

const linuxArchitectures = [
  {
    goArchitecture: "amd64",
    builderArchitectureArgument: "--x64",
    artifactArchitecture: "x64",
  },
  {
    goArchitecture: "arm64",
    builderArchitectureArgument: "--arm64",
    artifactArchitecture: "arm64",
  },
  {
    goArchitecture: "arm",
    builderArchitectureArgument: "--armv7l",
    artifactArchitecture: "armv7l",
  },
] as const;

const linuxTargets = new Set(["deb", "rpm", "pacman"]);

async function packageLinux() {
  const requestedArchitectures = new Set<string>();
  const requestedTargets: string[] = [];
  const supportedArchitectures = new Set<string>(
    linuxArchitectures.map((architecture) => architecture.artifactArchitecture),
  );
  for (const argument of packageArguments) {
    if (supportedArchitectures.has(argument)) {
      requestedArchitectures.add(argument);
    } else if (linuxTargets.has(argument)) {
      requestedTargets.push(argument);
    } else {
      throw new Error(`unknown Linux package argument: ${argument}`);
    }
  }
  const selectedArchitectures = linuxArchitectures.filter(
    (architecture) =>
      requestedArchitectures.size === 0 ||
      requestedArchitectures.has(architecture.artifactArchitecture),
  );
  runChecked("electron-vite", ["build"]);
  for (const architecture of selectedArchitectures) {
    await buildBoxdd(
      "linux",
      architecture.goArchitecture,
      path.join(repositoryRoot, "bin", "sing-box-daemon"),
    );
    const argumentsList = [
      "--linux",
      ...requestedTargets,
      architecture.builderArchitectureArgument,
      "--config",
      "electron-builder.yml",
      `--config.extraMetadata.version=${readApplicationVersion()}`,
      ...(developmentPackage
        ? [
            "--config.compression=store",
            "--config.linux.artifactName=SFL-${version}-${arch}-dev.${ext}",
            "--config.pacman.artifactName=SFL-${version}-${arch}-dev.pkg.tar.zst",
          ]
        : []),
      "--publish",
      "never",
    ];
    runChecked("electron-builder", argumentsList);
  }
}

async function main(): Promise<void> {
  console.info(`[package] SOURCE_DATE_EPOCH=${sourceDateEpoch}`);
  // A circular import throws at startup on whichever platform reaches the
  // module-scope read, so it must never reach a package.
  runChecked("node", ["scripts/check-cycles.mjs"]);
  verifyGoVersion();
  if (packageMode !== "win-architecture") {
    ensureGenerated();
  }
  switch (packageMode) {
    case "win":
      await packageWindows();
      break;
    case "win-architecture":
      await packageWindowsArchitecture(packageArguments[0] ?? "");
      break;
    case "linux":
      await packageLinux();
      break;
    case "mac":
      await packageMac();
      break;
    default:
      throw new Error(`unknown platform: ${packageMode}`);
  }
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
