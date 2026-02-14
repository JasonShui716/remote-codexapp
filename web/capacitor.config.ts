import type { CapacitorConfig } from '@capacitor/cli';

// iOS wrapper for the hosted app.
// Note: appId can be changed later (must match what you set in Apple).
const config: CapacitorConfig = {
  appId: 'cc.conknow.remotecodex',
  appName: 'Remote Codex',
  webDir: 'dist',
  bundledWebRuntime: false,
  server: {
    url: 'https://conknow.cc/codex',
    cleartext: false,
    allowNavigation: ['conknow.cc', 'www.conknow.app']
  }
};

export default config;
