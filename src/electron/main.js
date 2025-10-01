import { app, BrowserWindow, nativeImage } from "electron";
import path from "path";
import { fileURLToPath } from "url";

// reconstruir __dirname en ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const iconPath = path.join(__dirname, '..', '..', 'App de inventario', '../logo.png');
app.on("ready", () => {
  const mainWindow = new BrowserWindow({
    fullscreen: true,
    icon: iconPath,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  mainWindow.setOverlayIcon(
    nativeImage.createFromPath(path.join(app.getAppPath(), "../logo.png")),
    "App de inventario"
  );

   mainWindow.loadFile( path.join(app.getAppPath(), "dist-react/index.html") );
});
