#!/usr/bin/env node
/**
 * postinstall script for @suatkocar/codegraph
 *
 * Downloads the correct platform binary from GitHub releases
 * and places it in the package's bin/ directory.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");

const REPO = "suatkocar/codegraph";
const BINARY = "codegraph"; // Rust binary name in GitHub releases
const LOCAL_NAME = "codegraph-native"; // Local binary name (wrapper calls this)
const BIN_DIR = path.join(__dirname, "bin");

function getPlatformTarget() {
  const platform = os.platform();
  const arch = os.arch();

  const targets = {
    "darwin-arm64": "aarch64-apple-darwin",
    "darwin-x64": "x86_64-apple-darwin",
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
  };

  const key = `${platform}-${arch}`;
  const target = targets[key];

  if (!target) {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    console.error(`Supported: ${Object.keys(targets).join(", ")}`);
    process.exit(1);
  }

  return target;
}

function getLatestRelease() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "api.github.com",
      path: `/repos/${REPO}/releases/latest`,
      headers: { "User-Agent": "codegraph-npm-installer" },
    };

    https
      .get(options, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          // Follow redirect
          https.get(res.headers.location, { headers: options.headers }, (res2) => {
            let data = "";
            res2.on("data", (chunk) => (data += chunk));
            res2.on("end", () => resolve(JSON.parse(data)));
          });
          return;
        }
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          if (res.statusCode !== 200) {
            reject(new Error(`GitHub API returned ${res.statusCode}: ${data}`));
            return;
          }
          resolve(JSON.parse(data));
        });
      })
      .on("error", reject);
  });
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const follow = (url) => {
      https
        .get(url, { headers: { "User-Agent": "codegraph-npm-installer" } }, (res) => {
          if (res.statusCode === 302 || res.statusCode === 301) {
            follow(res.headers.location);
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`Download failed with status ${res.statusCode}`));
            return;
          }
          const file = fs.createWriteStream(dest);
          res.pipe(file);
          file.on("finish", () => {
            file.close();
            resolve();
          });
        })
        .on("error", reject);
    };
    follow(url);
  });
}

async function main() {
  const target = getPlatformTarget();
  const binPath = path.join(BIN_DIR, LOCAL_NAME);

  // Skip if binary already exists and is executable
  if (fs.existsSync(binPath)) {
    try {
      fs.accessSync(binPath, fs.constants.X_OK);
      console.log(`[codegraph] Binary already installed at ${binPath}`);
      return;
    } catch {
      // Binary exists but not executable, re-download
    }
  }

  console.log(`[codegraph] Installing for ${os.platform()}-${os.arch()}...`);

  try {
    // Try GitHub release first
    const release = await getLatestRelease();
    const assetName = `${BINARY}-${release.tag_name}-${target}.tar.gz`;
    const asset = release.assets.find((a) => a.name === assetName);

    if (!asset) {
      // Try without .tar.gz (direct binary)
      const directAsset = release.assets.find((a) => a.name === `${BINARY}-${target}`);
      if (directAsset) {
        await downloadFile(directAsset.browser_download_url, binPath);
        fs.chmodSync(binPath, 0o755);
        console.log(`[codegraph] Installed ${BINARY} v${release.tag_name}`);
        return;
      }

      console.error(`[codegraph] No binary found for ${target} in release ${release.tag_name}`);
      console.error(`[codegraph] Available assets: ${release.assets.map((a) => a.name).join(", ")}`);
      console.error(`[codegraph] Install manually: https://github.com/${REPO}/releases`);
      process.exit(1);
    }

    // Download tarball and extract
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "codegraph-"));
    const tarPath = path.join(tmpDir, assetName);

    await downloadFile(asset.browser_download_url, tarPath);

    // Extract to temp, then rename to -native
    fs.mkdirSync(BIN_DIR, { recursive: true });
    execSync(`tar -xzf "${tarPath}" -C "${tmpDir}"`, { stdio: "pipe" });

    // Move and rename: codegraph -> codegraph-native
    const extractedBin = path.join(tmpDir, BINARY);
    fs.copyFileSync(extractedBin, binPath);
    fs.chmodSync(binPath, 0o755);

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });

    console.log(`[codegraph] Installed ${BINARY} v${release.tag_name}`);
  } catch (err) {
    console.error(`[codegraph] Installation failed: ${err.message}`);
    console.error(`[codegraph] Install manually:`);
    console.error(`  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash`);
    process.exit(1);
  }
}

main();
