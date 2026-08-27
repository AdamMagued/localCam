# localCam

A tiny password-protected camera stream for devices on the same private Wi‑Fi. The camera laptop broadcasts JPEG frames over HTTPS; viewers need the password.

## Run

Requires Python 3 and OpenSSL (both are already available on macOS).

```sh
python3 server.py
```

1. Enter a password of at least 8 characters.
2. On the laptop, open the printed **Broadcast** URL. Accept the one-time self-signed certificate warning, sign in, choose the camera, and click **Start camera**.
3. On another device connected to the same Wi‑Fi, open the printed **Viewer** URL, accept the certificate warning, and enter the same password.
4. Keep the terminal and broadcast page open. Press `Ctrl+C` to stop.

The server refuses public bind addresses and public client IPs. Do not configure router port-forwarding for port 8443.
