#!/usr/bin/env bash
# CodeGraph installer — downloads the latest release binary for your platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/suatkocar/codegraph-rs/main/install.sh | bash
#
# Environment variables:
#   CODEGRAPH_VERSION   — Version tag to install (default: latest)
#   CODEGRAPH_INSTALL   — Install directory (default: ~/.local/bin)

set -eo pipefail

REPO="suatkocar/codegraph-rs"
BINARY="codegraph-mcp"
INSTALL_DIR="${CODEGRAPH_INSTALL:-$HOME/.local/bin}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { printf "\033[1;34m==>\033[0m %s\n" "$1"; }
ok()    { printf "\033[1;32m==>\033[0m %s\n" "$1"; }
err()   { printf "\033[1;31mError:\033[0m %s\n" "$1" >&2; exit 1; }

detect_platform() {
  local os arch

  case "$(uname -s)" in
    Darwin) os="apple-darwin" ;;
    Linux)  os="unknown-linux-gnu" ;;
    *)      err "Unsupported OS: $(uname -s). Only macOS and Linux are supported." ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)   arch="x86_64" ;;
    arm64|aarch64)   arch="aarch64" ;;
    *)               err "Unsupported architecture: $(uname -m)" ;;
  esac

  echo "${arch}-${os}"
}

get_latest_version() {
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  local version

  if command -v curl &>/dev/null; then
    version=$(curl -fsSL "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
  elif command -v wget &>/dev/null; then
    version=$(wget -qO- "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
  else
    err "Neither curl nor wget found. Please install one and retry."
  fi

  [ -z "$version" ] && err "Could not determine latest version. Check https://github.com/${REPO}/releases"
  echo "$version"
}

download() {
  local url="$1" dest="$2"
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$dest"
  else
    wget -qO "$dest" "$url"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  local platform version archive_name url tmp_dir

  info "Detecting platform..."
  platform=$(detect_platform)
  info "Platform: ${platform}"

  if [ -n "${CODEGRAPH_VERSION:-}" ]; then
    version="$CODEGRAPH_VERSION"
    info "Using specified version: ${version}"
  else
    info "Fetching latest version..."
    version=$(get_latest_version)
    info "Latest version: ${version}"
  fi

  archive_name="${BINARY}-${version}-${platform}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"

  info "Downloading ${archive_name}..."
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' EXIT

  download "$url" "${tmp_dir}/${archive_name}" || err "Download failed. Check that version ${version} has a release for ${platform}."

  info "Extracting..."
  tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"

  info "Installing to ${INSTALL_DIR}..."
  mkdir -p "$INSTALL_DIR"
  mv "${tmp_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  chmod +x "${INSTALL_DIR}/${BINARY}"

  # Check if install dir is in PATH
  if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    printf "\n"
    info "Add this to your shell profile:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    printf "\n"
  fi

  ok "CodeGraph installed successfully!"
  echo ""
  echo "  Get started:"
  echo "    cd your-project"
  echo "    codegraph-mcp init ."
  echo ""
  echo "  That's it. Open Claude Code and your codebase is graph-aware."
  echo ""
}

main "$@"
