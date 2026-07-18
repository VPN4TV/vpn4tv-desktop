import { BrowserWindow, ipcMain, session, shell } from "electron";
import type { WebContents } from "electron";

import { OPENCONNECT_BROWSER_AUTHENTICATE } from "../shared/ipc";
import type {
  OpenConnectBrowserRequest,
  OpenConnectBrowserResult,
} from "../shared/ipc";

let authenticationActive = false;

function parseRequest(value: unknown): OpenConnectBrowserRequest {
  if (typeof value !== "object" || value === null) {
    throw new Error("invalid OpenConnect browser request");
  }
  const request = value as Partial<OpenConnectBrowserRequest>;
  if (
    typeof request.url !== "string" ||
    typeof request.finalURL !== "string" ||
    !Array.isArray(request.cookieNames) ||
    !request.cookieNames.every((name) => typeof name === "string") ||
    !Array.isArray(request.headerNames) ||
    !request.headerNames.every((name) => typeof name === "string")
  ) {
    throw new Error("invalid OpenConnect browser request");
  }
  const scheme = new URL(request.url).protocol;
  if (scheme !== "http:" && scheme !== "https:" && scheme !== "data:") {
    throw new Error(`unsupported OpenConnect browser URL scheme: ${scheme}`);
  }
  return {
    url: request.url,
    finalURL: request.finalURL,
    cookieNames: [...request.cookieNames],
    headerNames: [...request.headerNames],
  };
}

function requestedHeaders(
  request: OpenConnectBrowserRequest,
  responseHeaders: Record<string, string[]> | undefined,
): OpenConnectBrowserResult["headers"] {
  const requestedNames = new Set(request.headerNames.map((name) => name.toLowerCase()));
  const headers: OpenConnectBrowserResult["headers"] = [];
  for (const [name, values] of Object.entries(responseHeaders ?? {})) {
    if (requestedNames.has(name.toLowerCase())) {
      headers.push({ name, values: [...values] });
    }
  }
  return headers;
}

function globalProtectComplete(headers: OpenConnectBrowserResult["headers"]): boolean {
  const names = new Set(headers.map((header) => header.name.toLowerCase()));
  return (
    names.has("saml-username") &&
    (names.has("prelogin-cookie") || names.has("portal-userauthcookie"))
  );
}

async function authenticate(
  parent: BrowserWindow,
  request: OpenConnectBrowserRequest,
): Promise<OpenConnectBrowserResult | null> {
  if (authenticationActive) {
    throw new Error("another OpenConnect browser authentication is already active");
  }
  authenticationActive = true;
  const browserSession = session.fromPartition("persist:openconnect-browser");
  const windows = new Set<BrowserWindow>();
  let settled = false;

  return new Promise<OpenConnectBrowserResult | null>((resolve, reject) => {
    const cleanup = () => {
      browserSession.webRequest.onHeadersReceived(null);
      authenticationActive = false;
    };
    const finish = (result: OpenConnectBrowserResult | null) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
      for (const window of windows) {
        if (!window.isDestroyed()) window.close();
      }
    };
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
      for (const window of windows) {
        if (!window.isDestroyed()) window.close();
      }
    };
    const captureCookies = async (url: string) => {
      if (settled || request.finalURL === "" || url !== request.finalURL) return;
      const cookies = (await browserSession.cookies.get({ url }))
        .filter((cookie) => request.cookieNames.includes(cookie.name))
        .map((cookie) => ({ name: cookie.name, value: cookie.value }));
      if (request.cookieNames.length > 0 && cookies.length === 0) return;
      finish({ finalURL: url, cookies, headers: [] });
    };
    const attachContents = (contents: WebContents) => {
      contents.setWindowOpenHandler(({ url }) => {
        let scheme: string;
        try {
          scheme = new URL(url).protocol;
        } catch {
          return { action: "deny" };
        }
        if (
          scheme === "http:" ||
          scheme === "https:" ||
          scheme === "data:" ||
          url === "about:blank"
        ) {
          return {
            action: "allow",
            overrideBrowserWindowOptions: {
              parent: rootWindow,
              autoHideMenuBar: true,
              webPreferences: {
                partition: "persist:openconnect-browser",
                contextIsolation: true,
                sandbox: true,
                nodeIntegration: false,
              },
            },
          };
        }
        if (scheme === "mailto:" || scheme === "tel:") {
          void shell.openExternal(url).catch(() => {});
        }
        return { action: "deny" };
      });
      contents.on("did-create-window", (window) => {
        windows.add(window);
        attachContents(window.webContents);
        window.on("closed", () => windows.delete(window));
      });
      contents.on("did-finish-load", () => {
        void captureCookies(contents.getURL()).catch(fail);
      });
    };

    browserSession.webRequest.onHeadersReceived(
      { urls: ["*://*/*"] },
      (details, callback) => {
        const headers = requestedHeaders(request, details.responseHeaders);
        if (details.resourceType === "mainFrame" && globalProtectComplete(headers)) {
          finish({ finalURL: details.url, cookies: [], headers });
        }
        callback({ responseHeaders: details.responseHeaders });
      },
    );

    const rootWindow = new BrowserWindow({
      parent,
      width: 980,
      height: 760,
      minWidth: 640,
      minHeight: 480,
      show: false,
      title: "OpenConnect Authentication",
      autoHideMenuBar: true,
      webPreferences: {
        partition: "persist:openconnect-browser",
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
      },
    });
    windows.add(rootWindow);
    attachContents(rootWindow.webContents);
    rootWindow.once("ready-to-show", () => rootWindow.show());
    rootWindow.on("closed", () => {
      windows.delete(rootWindow);
      if (!settled) finish(null);
    });
    void rootWindow.loadURL(request.url).catch(fail);
  });
}

export function registerOpenConnectBrowser() {
  ipcMain.handle(OPENCONNECT_BROWSER_AUTHENTICATE, (event, requestValue: unknown) => {
    const parent = BrowserWindow.fromWebContents(event.sender);
    if (parent === null) {
      throw new Error("OpenConnect browser authentication requires an application window");
    }
    return authenticate(parent, parseRequest(requestValue));
  });
}
