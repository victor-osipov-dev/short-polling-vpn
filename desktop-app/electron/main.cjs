const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const { spawn } = require("node:child_process");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const fs = require("node:fs");

const IS_DEV = process.argv.includes("--dev");
const DEV_URL = "http://127.0.0.1:5173";
const APP_ID = "ru.fimdi.vpn";

let mainWindow = null;
let backendProcess = null;
let backendPort = 8899;
let quitting = false;
let shuttingDown = false;

app.setAppUserModelId(APP_ID);

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 8899;
      server.close(() => resolve(port));
    });
  });
}

function backendCommand() {
  if (!app.isPackaged) {
    const venv = path.join(app.getAppPath(), "..", ".venv", "Scripts", "python.exe");
    const python = process.env.FIMDI_PYTHON || (fs.existsSync(venv) ? venv : "python");
    return {
      command: python,
      args: [path.join(app.getAppPath(), "backend", "vpn_backend.py"), "--api-port", String(backendPort)],
      cwd: path.join(app.getAppPath(), ".."),
    };
  }
  const exe = path.join(process.resourcesPath, "backend", "vpn-backend.exe");
  if (fs.existsSync(exe)) {
    return { command: exe, args: ["--api-port", String(backendPort)], cwd: process.resourcesPath };
  }
  return {
    command: process.env.FIMDI_PYTHON || "python",
    args: [path.join(process.resourcesPath, "backend", "vpn_backend.py"), "--api-port", String(backendPort)],
    cwd: process.resourcesPath,
  };
}

function startBackend() {
  const { command, args, cwd } = backendCommand();
  const env = {
    ...process.env,
    PYTHONIOENCODING: "utf-8",
    PYTHONUTF8: "1",
    VPN_CORE_DIR: app.isPackaged
      ? path.join(process.resourcesPath, "core")
      : path.join(app.getAppPath(), ".."),
    FIMDI_SINGBOX: app.isPackaged
      ? path.join(process.resourcesPath, "sing-box", "sing-box.exe")
      : path.join(app.getAppPath(), "resources", "sing-box", "sing-box.exe"),
  };

  backendProcess = spawn(command, args, {
    cwd,
    env,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const relay = (stream, prefix) => {
    let buffer = "";
    stream.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";
      for (const line of lines) {
        if (line.trim()) console.log(prefix, line);
      }
    });
  };
  relay(backendProcess.stdout, "[backend]");
  relay(backendProcess.stderr, "[backend:err]");

  backendProcess.on("exit", (code, signal) => {
    console.log(`[backend] exited code=${code} signal=${signal}`);
    backendProcess = null;
    if (!quitting && !shuttingDown && mainWindow && !mainWindow.isDestroyed()) {
      dialog.showMessageBox(mainWindow, {
        type: "error",
        title: "FIMDI VPN",
        message: "Служба VPN неожиданно остановилась",
        detail: `Код выхода: ${code ?? signal ?? "неизвестно"}. Перезапустите приложение.`,
        buttons: ["ОК"],
      });
    }
  });
}

function request(method, urlPath, body, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port: backendPort,
        path: urlPath,
        method,
        headers: payload
          ? { "Content-Type": "application/json", "Content-Length": payload.length }
          : {},
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let data = {};
          try {
            data = text ? JSON.parse(text) : {};
          } catch {
            data = { error: text.slice(0, 500) };
          }
          if (res.statusCode >= 400) {
            reject(new Error(data.error || `HTTP ${res.statusCode}`));
          } else {
            resolve(data);
          }
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error("Превышено время ожидания ответа службы VPN"));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitForBackend(timeoutMs = 30000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const health = await request("GET", "/api/health", undefined, 1500);
      if (health.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error("Служба VPN не запустилась. Проверьте, что Python 3.10+ доступен в PATH.");
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1220,
    height: 800,
    minWidth: 980,
    minHeight: 660,
    show: false,
    backgroundColor: "#07090f",
    title: "FIMDI VPN",
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#07090f",
      symbolColor: "#9aa4b8",
      height: 40,
    },
    trafficLightPosition: { x: 14, y: 14 },
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  mainWindow.once("ready-to-show", () => mainWindow.show());

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://") || url.startsWith("http://")) shell.openExternal(url);
    return { action: "deny" };
  });

  if (IS_DEV) {
    await mainWindow.loadURL(DEV_URL);
  } else {
    await mainWindow.loadFile(path.join(app.getAppPath(), "dist", "index.html"));
  }
}

// ── IPC ────────────────────────────────────────────────────────────────────

ipcMain.handle("vpn:state", () => request("GET", "/api/state"));
ipcMain.handle("vpn:logs", () => request("GET", "/api/logs"));
ipcMain.handle("vpn:loadSubscription", (_e, url) =>
  request("POST", "/api/subscription", { url }, 60000),
);
ipcMain.handle("vpn:connect", (_e, payload) =>
  request("POST", "/api/connect", payload, 60000),
);
ipcMain.handle("vpn:disconnect", () => request("POST", "/api/disconnect", {}, 30000));
ipcMain.handle("vpn:recheck", () => request("POST", "/api/recheck", {}, 15000));

ipcMain.handle("app:info", () => ({
  version: app.getVersion(),
  platform: process.platform,
  dev: IS_DEV,
  packaged: app.isPackaged,
}));

ipcMain.handle("app:relaunchAdmin", async () => {
  const args = app.isPackaged ? [] : process.argv.slice(1);
  const argList = args.length
    ? `-ArgumentList @(${args.map((a) => `'${String(a).replace(/'/g, "''")}'`).join(",")}) `
    : "";
  const cmd = `Start-Process -FilePath '${process.execPath.replace(/'/g, "''")}' ${argList}-Verb RunAs`;
  const child = spawn("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  child.unref();
  setTimeout(() => app.quit(), 500);
  return { ok: true };
});

ipcMain.handle("app:openExternal", (_e, url) => {
  if (typeof url === "string" && /^https?:\/\//.test(url)) return shell.openExternal(url);
  return null;
});

// ── lifecycle ──────────────────────────────────────────────────────────────

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    try {
      backendPort = await freePort();
      startBackend();
      await waitForBackend();
    } catch (error) {
      dialog.showErrorBox("FIMDI VPN", String(error.message || error));
      app.quit();
      return;
    }
    await createWindow();

    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", async (event) => {
  if (shuttingDown) return;
  event.preventDefault();
  shuttingDown = true;
  quitting = true;
  try {
    await request("POST", "/api/shutdown", {}, 5000);
  } catch {
    // backend may already be gone
  }
  if (backendProcess) {
    try {
      backendProcess.kill();
    } catch {
      // ignore
    }
  }
  app.quit();
});
