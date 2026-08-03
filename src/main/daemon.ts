import type { Client, Transport } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { app } from "electron";
import * as net from "node:net";

import { ManagedService } from "../shared/gen/daemon/managed_service_pb";
import { StartedService } from "../shared/gen/daemon/started_service_pb";
import { DesktopService } from "../shared/gen/experimental/boxdd/desktop_service_pb";
import { developmentSwitchValue } from "./development";
import { localeInterceptor } from "./locale";
import { daemonWorkerTransport } from "./worker";

let daemonTransport: Transport | null;
let resolvedSocketPath: string | null = null;
if (process.platform === "win32" && app.isPackaged) {
  daemonTransport = daemonWorkerTransport;
} else {
  const defaultSocketPath =
    process.platform === "win32"
      ? "\\\\.\\pipe\\ProtectedPrefix\\Administrators\\sing-box"
      : process.platform === "linux"
        ? "/run/sing-box.socket"
        // VPN4TV: macOS has no /run; the LaunchDaemon listens here.
        : process.platform === "darwin"
          ? "/var/run/sing-box.socket"
          : null;
  const socketPath = developmentSwitchValue("daemon-socket") || defaultSocketPath;
  resolvedSocketPath = socketPath || null;
  if (!socketPath) {
    daemonTransport = null;
  } else {
    daemonTransport = createGrpcTransport({
      baseUrl: "http://sing-box",
      interceptors: [localeInterceptor],
      nodeOptions: {
        createConnection: () => net.connect({ path: socketPath }),
      },
    });
  }
}

export { daemonTransport };

/** Where the daemon listens, so callers can wait for it to come up. */
export function daemonSocketPath(): string | null {
  return resolvedSocketPath;
}

export const desktopService: Client<typeof DesktopService> | null = daemonTransport
  ? createClient(DesktopService, daemonTransport)
  : null;

export const startedService: Client<typeof StartedService> | null = daemonTransport
  ? createClient(StartedService, daemonTransport)
  : null;

export const managedService: Client<typeof ManagedService> | null = daemonTransport
  ? createClient(ManagedService, daemonTransport)
  : null;
