const { platform, arch } = process;
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const PLATFORMS = {
  win32: {
    x64: 'npm/win32-x64',
  },
  darwin: {
    x64: 'npm/darwin-x64',
  },
  linux: {
    x64: 'npm/linux-x64',
  },
};

const binPath = PLATFORMS?.[platform]?.[arch];
const bin = platform === 'win32' ? 'gitleaks.exe' : 'gitleaks';

if (binPath) {
  const result = spawnSync('make', ['build'], { stdio: 'inherit' });

  if (result.error) {
    console.error('Failed to build gitleaks:', result.error);
    process.exitCode = 1;
  } else {
    const srcPath = path.join(__dirname, bin);
    const destPath = path.join(__dirname, binPath, bin);

    try {
      fs.copyFileSync(srcPath, destPath);
      console.log(`gitleaks executable copied to ${destPath}`);
    } catch (err) {
      console.error('Failed to copy gitleaks executable:', err);
      process.exitCode = 1;
    }
  }
} else {
  console.error(
    "The gitleaks CLI package doesn't ship with prebuilt binaries for your platform yet. " +
      'You can still use the CLI by cloning the gitleaks repo from GitHub, ' +
      'and follow the instructions there to build the CLI for your platform.',
  );
  process.exitCode = 1;
}
