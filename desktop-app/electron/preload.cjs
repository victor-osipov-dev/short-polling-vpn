const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("fimdi", {
  getState: () => ipcRenderer.invoke("vpn:state"),
  getLogs: () => ipcRenderer.invoke("vpn:logs"),
  loadSubscription: (url) => ipcRenderer.invoke("vpn:loadSubscription", url),
  connect: (payload) => ipcRenderer.invoke("vpn:connect", payload),
  disconnect: () => ipcRenderer.invoke("vpn:disconnect"),
  recheck: () => ipcRenderer.invoke("vpn:recheck"),
  appInfo: () => ipcRenderer.invoke("app:info"),
  relaunchAdmin: () => ipcRenderer.invoke("app:relaunchAdmin"),
  openExternal: (url) => ipcRenderer.invoke("app:openExternal", url),
});
