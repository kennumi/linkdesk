# LinkDesk

Minimal remote desktop for Windows: share your screen with a friend, or control theirs, over [Tailscale](https://tailscale.com).

## Install

Paste into PowerShell:

```powershell
irm https://raw.githubusercontent.com/kennumi/linkdesk/main/install.ps1 | iex
```

Run the same line again to update.

## Use

1. Click **Install Tailscale** (or **Sign in**) in the app. Both people must be on the same Tailscale network; invite each other at login.tailscale.com.
2. The person sharing enters a password and clicks **Share my screen**.
3. The other person enters the same password and the sharer's address, then clicks **Connect**.

Sharing only listens on your Tailscale address (encrypted) and requires the password. Close the app to stop sharing.
