#!/usr/bin/env bash

APP_NAME="gitleaks"
REPO_URL="https://github.com/gitleaks/gitleaks"

: ${USE_SUDO:="true"}
: ${GITLEAKS_INSTALL_DIR:="/usr/local/bin"}

# initArch discovers the architecture for this system.
initArch() {
  ARCH=$(uname -m)
  case $ARCH in
    armv6*) ARCH="armv6";;
    armv7*) ARCH="armv7";;
    arm64) ARCH="arm64";;
    aarch64) ARCH="arm64";;
    x86) ARCH="x32";;
    x86_64) ARCH="x64";;
    i686) ARCH="x32";;
    i386) ARCH="x32";;
  esac
}

# initOS discovers the operating system for this system.
initOS() {
  OS=$(uname|tr '[:upper:]' '[:lower:]')

  case "$OS" in
    # Minimalist GNU for Windows
    mingw* | cygwin* | msys* | Windows_NT)
      OS="windows"
      USE_SUDO="false"
      if [[ ! -d "$GITLEAKS_INSTALL_DIR" ]]; then
        # mingw bash that ships with Git for Windows doesn't have /usr/local/bin but ~/bin is first entry in the path
        mkdir -p ~/bin
        GITLEAKS_INSTALL_DIR=~/bin
      fi
      ;;
  esac
}

# runs the given command as root (detects if we are root already)
runAsRoot() {
  local CMD="$*"

  if [ $EUID -ne 0 -a $USE_SUDO = "true" ]; then
    CMD="sudo $CMD"
  fi

  $CMD
}

# scurl invokes `curl` with secure defaults
scurl() {
  # - `--proto =https` requires that all URLs use HTTPS. Attempts to call http://
  #   URLs will fail.
  # - `--tlsv1.2` ensures that at least TLS v1.2 is used, disabling less secure
  #   prior TLS versions.
  # - `--fail` ensures that the command fails if HTTP response is not 2xx.
  # - `--show-error` causes curl to output error messages when it fails (when
  #   also invoked with -s|--silent).
  if [[ "$DEBUG" == "true" ]]; then
    echo "Executing: curl --proto \"=https\" --tlsv1.2 --fail --show-error $*" >&2
  fi
  curl --proto "=https" --tlsv1.2 --fail --show-error "$@"
}

# verifySupported checks that the os/arch combination is supported for
# binary builds.
verifySupported() {
  local supported="darwin_arm64\ndarwin_x64\nlinux_arm64\nlinux_armv6\nlinux_armv7\nlinux_x32\nlinux_x64\nwindows_armv6\nwindows_armv7\nwindows_x32\nwindows_x64"
  if ! echo "${supported}" | grep -q "${OS}_${ARCH}"; then
    echo "No prebuilt binary for ${OS}_${ARCH}."
    echo "To build from source, go to $REPO_URL"
    exit 1
  fi

  if ! type "curl" > /dev/null && ! type "wget" > /dev/null; then
    echo "Either curl or wget is required"
    exit 1
  fi
}

# checkGitleaksInstalledVersion checks which version of gitleaks is installed and
# if it needs to be changed.
checkGitleaksInstalledVersion() {
  if [[ -f "${GITLEAKS_INSTALL_DIR}/${APP_NAME}" ]]; then
    local version=$(gitleaks version)
    if [[ "$version" == "$TAG" ]]; then
      echo "gitleaks ${version} is already ${DESIRED_VERSION:-latest}"
      return 0
    else
      echo "gitleaks ${TAG} is available. Changing from version ${version}."
      return 1
    fi
  else
    return 1
  fi
}

# checkTagProvided checks whether TAG has provided as an environment variable so we can skip checkLatestVersion.
checkTagProvided() {
  [[ ! -z "$TAG" ]]
}

# checkLatestVersion grabs the latest version string from the releases
checkLatestVersion() {
  local latest_release_url="$REPO_URL/releases/latest"
  if type "curl" > /dev/null; then
    TAG=$(scurl -Ls -o /dev/null -w %{url_effective} $latest_release_url | grep -oE "[^/]+$" )
  elif type "wget" > /dev/null; then
    TAG=$(wget $latest_release_url --server-response -O /dev/null 2>&1 | awk '/^\s*Location: /{DEST=$2} END{ print DEST}' | grep -oE "[^/]+$")
  fi
  if [[ "$DEBUG" == "true" ]]; then
    echo "Resolved latest tag: <$TAG>" >&2
  fi
  if [[ "$TAG" == "latest" ]]; then
    echo "Failed to get the latest version for $REPO_URL"
    exit 1
  fi
}

# downloadFile downloads the latest binary package and also the checksum
# for that binary.
downloadFile() {
  case "$OS" in
    linux | darwin)
      ARCHIVE_EXTENSION="tar.gz"
      ;;
    windows)
      ARCHIVE_EXTENSION="zip"
      ;;
  esac

  GITLEAKS_DIST="gitleaks_${TAG:1}_${OS}_${ARCH}"
  DOWNLOAD_URL="$REPO_URL/releases/download/$TAG/$GITLEAKS_DIST.${ARCHIVE_EXTENSION}"
  GITLEAKS_TMP_ROOT="$(mktemp -dt gitleaks-binary-XXXXXX)"
  GITLEAKS_TMP_ARCHIVE_FILE="$GITLEAKS_TMP_ROOT/$GITLEAKS_DIST.${ARCHIVE_EXTENSION}"
  if type "curl" > /dev/null; then
    scurl -sL "$DOWNLOAD_URL" -o "$GITLEAKS_TMP_ARCHIVE_FILE"
  elif type "wget" > /dev/null; then
    wget -q -O "$GITLEAKS_TMP_ARCHIVE_FILE" "$DOWNLOAD_URL"
  fi
}

# Extract the archive based on the OS
extractFile() {
  GITLEAKS_TMP_FILE="$GITLEAKS_TMP_ROOT/$APP_NAME"
  case "$OS" in
    linux | darwin)
      tar -xzf $GITLEAKS_TMP_ARCHIVE_FILE -C $GITLEAKS_TMP_ROOT
      ;;
    windows)
      GITLEAKS_TMP_FILE="$GITLEAKS_TMP_FILE.exe"
      unzip $GITLEAKS_TMP_ARCHIVE_FILE -d $GITLEAKS_TMP_ROOT
      ;;
  esac
}

# installFile verifies the SHA256 for the file, then unpacks and
# installs it.
installFile() {
  echo "Preparing to install $APP_NAME into ${GITLEAKS_INSTALL_DIR}"
  runAsRoot chmod +x "$GITLEAKS_TMP_FILE"
  runAsRoot cp "$GITLEAKS_TMP_FILE" "$GITLEAKS_INSTALL_DIR/$APP_NAME"
  echo "$APP_NAME installed into $GITLEAKS_INSTALL_DIR/$APP_NAME"
}

# fail_trap is executed if an error occurs.
fail_trap() {
  result=$?
  if [ "$result" != "0" ]; then
    if [[ -n "$INPUT_ARGUMENTS" ]]; then
      echo "Failed to install $APP_NAME with the arguments provided: $INPUT_ARGUMENTS"
      help
    else
      echo "Failed to install $APP_NAME"
    fi
    echo -e "\tFor support, go to $REPO_URL."
  fi
  cleanup
  exit $result
}

# testVersion tests the installed client to make sure it is working.
testVersion() {
  if ! command -v $APP_NAME &> /dev/null; then
    echo "$APP_NAME not found. Is $GITLEAKS_INSTALL_DIR on your "'$PATH?'
    exit 1
  fi
  echo "Run '$APP_NAME --help' to see what you can do with it."
}

# help provides possible cli installation arguments
help () {
  echo "Accepted cli arguments are:"
  echo -e "\t[--help|-h ] ->> prints this help"
  echo -e "\t[--no-sudo]  ->> install without sudo"
}

# cleanup temporary files
cleanup() {
  if [[ -d "${GITLEAKS_TMP_ROOT:-}" ]]; then
    rm -rf "$GITLEAKS_TMP_ROOT"
  fi
}

# Execution

#Stop execution on any error
trap "fail_trap" EXIT
set -e

# Parsing input arguments (if any)
export INPUT_ARGUMENTS="${@}"
set -u
while [[ $# -gt 0 ]]; do
  case $1 in
    '--no-sudo')
       USE_SUDO="false"
       ;;
    '--help'|-h)
       help
       exit 0
       ;;
    *) exit 1
       ;;
  esac
  shift
done
set +u

initArch
initOS
verifySupported
checkTagProvided || checkLatestVersion
if ! checkGitleaksInstalledVersion; then
  downloadFile
  extractFile
  installFile
fi
testVersion
cleanup
