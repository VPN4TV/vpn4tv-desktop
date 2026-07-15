import { BrowserWindow, ipcMain, shell } from "electron";
import { join } from "node:path";

import { TERMINAL_WINDOW_CLOSE, TERMINAL_WINDOW_OPEN } from "../shared/ipc";
import { captureRuntimeCrash } from "./appReports";
import { developmentRendererURL } from "./development";
import { resourcePath } from "./resources";
import { titleBarOverlay } from "./titleBarOverlay";

export function registerTerminalWindows(onAllClosed: () => void): Set<BrowserWindow> {
  const windows = new Set<BrowserWindow>();

  ipcMain.handle(TERMINAL_WINDOW_OPEN, async (_event, route: string) => {
    const overlay = titleBarOverlay();
    const window = new BrowserWindow({
      width: 960,
      height: 640,
      minWidth: 640,
      minHeight: 400,
      show: true,
      backgroundColor: overlay?.color,
      title: "SSH",
      titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "hidden",
      trafficLightPosition: process.platform === "darwin" ? { x: 18, y: 19 } : undefined,
      titleBarOverlay: overlay,
      icon: process.platform === "linux" ? resourcePath("icons", "512x512.png") : undefined,
      webPreferences: {
        preload: join(import.meta.dirname, "../preload/index.cjs"),
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        backgroundThrottling: false,
      },
    });
    if (process.platform !== "darwin") {
      window.removeMenu();
    }
    windows.add(window);
    window.webContents.setWindowOpenHandler(({ url }) => {
      if (url.startsWith("https://") || url.startsWith("http://")) {
        void shell.openExternal(url);
      }
      return { action: "deny" };
    });
    window.webContents.on("will-navigate", (event, url) => {
      if (url !== window.webContents.getURL()) {
        event.preventDefault();
      }
    });
    window.webContents.on("render-process-gone", (_event, details) => {
      if (details.reason !== "clean-exit") {
        captureRuntimeCrash(
          "terminal-render-process-gone",
          new Error(`renderer ${details.reason} (exit code ${details.exitCode})`),
        );
      }
    });
    window.on("closed", () => {
      windows.delete(window);
      if (windows.size === 0) {
        onAllClosed();
      }
    });
    try {
      const rendererURL = developmentRendererURL();
      if (rendererURL !== "") {
        const url = new URL(rendererURL);
        url.hash = `#/${route}`;
        await window.loadURL(url.toString());
      } else {
        await window.loadFile(join(import.meta.dirname, "../renderer/index.html"), {
          hash: `/${route}`,
        });
      }
    } catch (error) {
      window.destroy();
      throw error;
    }
  });

  ipcMain.on(TERMINAL_WINDOW_CLOSE, (event) => {
    const window = BrowserWindow.fromWebContents(event.sender);
    if (window !== null && windows.has(window)) {
      window.close();
    }
  });

  return windows;
}
