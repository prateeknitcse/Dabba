# Dabba

*Dabba* is Hindi for "box": a private box your phone and laptop share over your own Wi-Fi.

Send photos and videos between your phone and laptop over your own Wi-Fi. Nothing goes through the cloud, and there are no npm packages to install.

## Start it

Works on Windows 10/11 and macOS. [Node.js](https://nodejs.org/) 18 or newer is required.

1. Start the server:
   - **Windows:** double-click `start.bat`.
   - **macOS:** double-click `start.command`. The first time, macOS may block it because it was downloaded: right-click it, choose **Open**, then **Open** again. If it says you don't have permission, run `chmod +x start.command` in Terminal once.
   - **Either:** run `node server.js` in a terminal in this folder.
2. Allow incoming connections when asked:
   - **Windows Firewall:** allow access on **Private networks** only.
   - **macOS:** click **Allow** when asked whether `node` may accept incoming network connections.
3. Your laptop browser opens `https://localhost:8443`. Accept the certificate warning, then press **Pair device**.
4. On your phone (same Wi-Fi), open the `On your phone:` address printed in the window, e.g. `https://192.168.1.20:8443`.
   Accept the warning, then enter the pairing code shown in the window (or click **Devices → Add a device** on the laptop).

Phone tip: use "Add to Home Screen" so it opens like an app.

## Use it

- **Phone → laptop:** tap the upload box, pick photos/videos. They land in the `SharedFiles` folder on the laptop (the **Open folder** button opens it).
- **Laptop → phone:** drag files onto the page, or copy them into `SharedFiles`. They appear on the phone instantly; tap **Save**.

## Security

- HTTPS only, with a certificate generated on your laptop on first run (stored in `data/`). Windows uses its built-in PowerShell for this; macOS uses the `openssl` command that comes with the system. If that fails, install OpenSSL with `brew install openssl` and start again.
- Every device must pair using an 8-character, single-use code that expires after 10 minutes and is replaced after 5 wrong guesses. Attempts are rate-limited per IP.
- Paired devices hold a random 256-bit token in an HttpOnly, Secure, SameSite=Strict cookie. Only its SHA-256 hash is stored.
- Revoke any device from **Devices**.
- Connections from public internet addresses are dropped. Do not port-forward 8443 on your router.
- Strict Content-Security-Policy, CSRF checks, filename sanitising, and path-traversal protection. Only photo, video, audio, and PDF files can be previewed in the browser; all other files are always downloaded.

The certificate warning appears because the certificate was made on your laptop instead of being issued by a public authority. To confirm you are talking to your own laptop, compare the SHA-256 fingerprint in the browser's certificate details with the `Cert SHA-256` line in the window.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8443` | Port to listen on |
| `SHARED_DIR` | `./SharedFiles` | Folder where files are stored |
| `MAX_UPLOAD_GB` | `20` | Largest single file allowed |
| `NO_OPEN` | unset | Set to `1` to skip opening the browser on start |

Delete the `data/` folder to unpair every device and create a new certificate.

## Contributing

Bug reports, ideas, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems privately as described there, not in a public issue.

## License

[MIT](LICENSE)
