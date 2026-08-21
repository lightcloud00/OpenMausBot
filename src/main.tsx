import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { applySkin, readSkin } from "./lib/skins";
import "./styles.css";

// Before the first paint, not inside a component: stamping the skin during
// render would show one frame of the default palette first.
applySkin(readSkin());

function reportRendererError(value: unknown) {
  const error = value instanceof Error ? value : new Error(String(value));
  void fetch("/api/telemetry/error", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: error.name, message: error.message, stack: error.stack }),
  }).catch(() => {});
}

window.addEventListener("error", (event) => reportRendererError(event.error ?? event.message));
window.addEventListener("unhandledrejection", (event) => reportRendererError(event.reason));

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
