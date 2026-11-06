# Contributing

Thanks for helping improve this project. It is a small, private file drop between a phone and a laptop on the same Wi-Fi, and contributions should keep it small, private, and easy to run.

## Ground rules

- **No npm dependencies.** The server uses only Node.js built-in modules and the browser code is plain JavaScript. This keeps the attack surface small and means there is nothing to install. If you believe a dependency is truly needed, open an issue to discuss it first.
- **No cloud services.** Files must never leave the local network.
- **Security first.** Don't weaken any existing protection (HTTPS, pairing, CSRF checks, Content-Security-Policy, path checks, the private-IP filter) without discussing it in an issue.
- **Keep it simple.** One server file and a few static files. Prefer clear code over clever code.

## Reporting security problems

Please **do not** open a public issue for security vulnerabilities. Report them privately through GitHub's "Report a vulnerability" button on the repository's **Security** tab. Include the steps to reproduce the problem and what an attacker could do with it. You'll get a reply as soon as possible, and you'll be credited once the problem is fixed, unless you'd rather not be.

## Reporting bugs

Open an issue and include:

- Your operating system and Node.js version (`node --version`)
- The phone and browser you used (for example "Pixel 8, Chrome 130" or "iPhone 15, Safari")
- What you did, what you expected, and what happened instead
- Any error shown in the server window or the browser console

Remove any personal information (IP addresses, file names, pairing codes) before posting.

## Suggesting features

Open an issue describing the problem you want solved before writing code, so we can agree on the approach. Features that need a dependency, an account, or an internet connection are unlikely to be accepted.

## Development setup

1. Install [Node.js](https://nodejs.org/) 18 or newer.
2. Fork and clone the repository.
3. Run the server:

   ```bash
   node server.js
   ```

   Set `NO_OPEN=1` to stop it from opening a browser, and `PORT=8450` to use a different port.
4. Open `https://localhost:8443` and pair using the code printed in the terminal.

Runtime data is written to `data/` (certificate and paired devices) and `SharedFiles/` (transferred files). Both are in `.gitignore`. **Never commit them**: `data/` contains your private certificate key.

## Project layout

| Path | What it does |
|---|---|
| `server.js` | HTTPS server, pairing, authentication, uploads, downloads, live updates |
| `public/index.html` | Page markup |
| `public/app.js` | Browser logic (pairing, upload queue, file grid, previews, devices) |
| `public/style.css` | Styles |
| `start.bat` | Double-click launcher for Windows |

## Making a change

1. Create a branch from `main`: `git checkout -b fix-upload-progress`.
2. Make your change. Match the existing style: 2-space indentation, single quotes, semicolons, `'use strict'`.
3. Check syntax:

   ```bash
   node --check server.js
   node --check public/app.js
   ```

4. Test by hand on a laptop **and** a real phone if your change affects the page. At minimum, check that:
   - Pairing works, and a wrong code is rejected
   - Uploading a photo and a large video works from the phone
   - Files sent from the laptop appear on the phone without refreshing
   - Preview, Save, and Delete work
   - Revoking a device logs it out
5. Update `README.md` if you changed behaviour, settings, or security properties.
6. Open a pull request that explains what changed and why, and how you tested it. Keep each pull request focused on one change.

## Browser code rules

- Never insert file names or device names with `innerHTML`. Use `textContent` or the `el()` helper in `app.js`.
- No inline scripts or styles. The Content-Security-Policy blocks them.
- Send the `X-Dabba: 1` header on every request that changes data.

## Code of conduct

Be respectful and constructive. Harassment or personal attacks are not tolerated, and maintainers may remove comments or contributors that break this rule.
