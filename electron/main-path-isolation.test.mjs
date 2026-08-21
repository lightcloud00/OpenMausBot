import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const source = readFileSync(fileURLToPath(new URL("./main.mjs", import.meta.url)), "utf8");

it("applies Electron path overrides before credentials and logs are resolved", () => {
  const userDataOverride = source.indexOf('appPathOverride("OMB_USER_DATA_DIR")');
  const userDataSetPath = source.indexOf('app.setPath("userData", USER_DATA_OVERRIDE)');
  const logOverride = source.indexOf('appPathOverride("OMB_LOG_DIR")');
  const logSetPath = source.indexOf('app.setPath("logs", LOG_DIR_OVERRIDE)');
  const credentialsFile = source.indexOf("const CREDENTIALS_FILE =");
  const logDirectory = source.indexOf("const LOG_DIR = app.getPath");

  for (const position of [
    userDataOverride,
    userDataSetPath,
    logOverride,
    logSetPath,
    credentialsFile,
    logDirectory,
  ]) {
    expect(position).not.toBe(-1);
  }
  expect(userDataOverride).toBeLessThan(userDataSetPath);
  expect(userDataSetPath).toBeLessThan(credentialsFile);
  expect(logOverride).toBeLessThan(logSetPath);
  expect(logSetPath).toBeLessThan(logDirectory);
});

it("gives Chromium's explicit user-data-dir switch precedence", () => {
  expect(source).toMatch(
    /const USER_DATA_OVERRIDE = app\.commandLine\.hasSwitch\("user-data-dir"\)\s*\? null\s*: appPathOverride\("OMB_USER_DATA_DIR"\);/,
  );
  expect(source).toMatch(/if \(USER_DATA_OVERRIDE\) app\.setPath\("userData", USER_DATA_OVERRIDE\);/);
});

it("requires isolated absolute non-root path overrides", () => {
  expect(source).toMatch(/if \(!path\.isAbsolute\(configured\)\) throw new Error/);
  expect(source).toMatch(/resolved === path\.parse\(resolved\)\.root/);
  expect(source).toMatch(/fs\.mkdirSync\(resolved, \{ recursive: true, mode: 0o700 \}\)/);
  expect(source).toMatch(/fs\.statSync\(resolved\)\.isDirectory\(\)/);
});
