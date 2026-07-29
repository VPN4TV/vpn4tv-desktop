const asar = require("@electron/asar");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const sentinel = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX");
const expectedFuses = [
  ["runAsNode", "0"],
  ["enableCookieEncryption", "1"],
  ["enableNodeOptionsEnvironmentVariable", "0"],
  ["enableNodeCliInspectArguments", "0"],
  ["enableEmbeddedAsarIntegrityValidation", "1"],
  ["onlyLoadAppFromAsar", "1"],
  ["loadBrowserProcessSpecificV8Snapshot", "0"],
  ["grantFileProtocolExtraPrivileges", "1"],
  ["wasmTrapHandlers", "1"],
];

exports.afterSign = async (context) => {
  const productFilename = context.packager.appInfo.productFilename;
  // VPN4TV: on macOS everything lives inside the bundle and the asar hash is
  // recorded in Info.plist instead of being embedded in the executable.
  const macOS = context.electronPlatformName === "darwin";
  const bundlePath = path.join(context.appOutDir, `${productFilename}.app`);
  const asarPath = macOS
    ? path.join(bundlePath, "Contents", "Resources", "app.asar")
    : path.join(context.appOutDir, "resources", "app.asar");
  const executablePath = macOS
    ? path.join(bundlePath, "Contents", "MacOS", productFilename)
    : path.join(
        context.appOutDir,
        `${productFilename}${context.electronPlatformName === "win32" ? ".exe" : ""}`,
      );
  // The fuse wire is compiled into the framework on macOS, not the launcher.
  const fusePath = macOS
    ? path.join(
        bundlePath,
        "Contents",
        "Frameworks",
        "Electron Framework.framework",
        "Versions",
        "A",
        "Electron Framework",
      )
    : executablePath;
  const executable = await fs.readFile(fusePath);
  const currentAsarHash = crypto
    .createHash("sha256")
    .update(asar.getRawHeader(asarPath).headerString)
    .digest("hex");
  if (macOS) {
    const plist = await fs.readFile(
      path.join(bundlePath, "Contents", "Info.plist"),
      "utf-8",
    );
    if (!plist.includes(currentAsarHash)) {
      throw new Error("Info.plist does not carry the current app.asar integrity hash");
    }
  } else {
    const currentAsarHashBuffer = Buffer.from(currentAsarHash);
    const asarHashPosition = executable.indexOf(currentAsarHashBuffer);
    if (
      asarHashPosition === -1 ||
      executable.lastIndexOf(currentAsarHashBuffer) !== asarHashPosition
    ) {
      throw new Error("the executable does not contain the current app.asar integrity hash");
    }
  }
  const sentinelPosition = executable.indexOf(sentinel);
  if (sentinelPosition === -1 || executable.lastIndexOf(sentinel) !== sentinelPosition) {
    throw new Error("expected exactly one Electron fuse wire");
  }
  const wirePosition = sentinelPosition + sentinel.length;
  const version = executable[wirePosition];
  const length = executable[wirePosition + 1];
  if (version !== 1 || length !== expectedFuses.length) {
    throw new Error(`unsupported Electron fuse wire version ${version} length ${length}`);
  }
  for (let index = 0; index < expectedFuses.length; index += 1) {
    const [name, state] = expectedFuses[index];
    const actual = String.fromCharCode(executable[wirePosition + 2 + index]);
    if (actual !== state) {
      throw new Error(`unexpected Electron fuse ${name}: ${actual}`);
    }
  }
};
