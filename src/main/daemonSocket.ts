// VPN4TV: where the daemon listens, in a module of its own.
//
// This used to live in daemon.ts, and repair.ts imported it from there — which
// closed a cycle (daemon → worker → repair → daemon). On Windows the packaged
// app then died at startup with "Cannot access 'daemonWorkerTransport' before
// initialization", because daemon.ts runs code at module scope while worker.ts
// is still initialising. Keep this file free of imports from that cluster.

import { developmentSwitchValue } from "./development";

function defaultSocketPath(): string | null {
  switch (process.platform) {
    case "win32":
      return "\\\\.\\pipe\\ProtectedPrefix\\Administrators\\sing-box";
    case "linux":
      return "/run/sing-box.socket";
    // macOS has no /run; the LaunchDaemon listens here.
    case "darwin":
      return "/var/run/sing-box.socket";
    default:
      return null;
  }
}

/** The socket the client connects to, or null when there is none to use. */
export function daemonSocketPath(): string | null {
  return developmentSwitchValue("daemon-socket") || defaultSocketPath();
}
