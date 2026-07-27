/**
 * VPN4TV: which `go` to build the daemon with.
 *
 * Our fork needs Go >= 1.24.7 but must NOT use go1.27rc1 — tailscale's
 * go-json-experiment does not compile there (the json/v2 API moved), and the
 * daemon build pulls tailscale in through the default build tags. Set VPN4TV_GO
 * to an explicit toolchain when the `go` on PATH is not suitable, e.g.
 *
 *   VPN4TV_GO=$HOME/sdk/go1.26.4/bin/go pnpm dev
 */
export function goCommand(): string {
  return process.env.VPN4TV_GO ?? "go";
}
