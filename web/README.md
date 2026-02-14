# Remote Codex Web

## Web Dev

```bash
npm -w web run dev
```

The dev server proxies `/api` to `http://localhost:8800`.

## iOS (TestFlight Wrapper)

This repo includes a Capacitor iOS project under `web/ios/` that always loads:

- `https://conknow.cc/codex`

In-app switching between instances is supported (topbar `Instance` picker):

- `https://conknow.cc/codex`
- `https://www.conknow.app/codex`

### Prereqs (on your Mac)

- Xcode
- CocoaPods (`pod`)

### Build / Run

```bash
npm install
npm -w web run build
npm -w web run cap:sync
npm -w web run ios
```

Then in Xcode, select a signing team and run, or archive for TestFlight.

### Bundle ID

Current `appId` is set in `web/capacitor.config.ts`:

- `cc.conknow.remotecodex`

Change it to your real Apple bundle id before you ship.
