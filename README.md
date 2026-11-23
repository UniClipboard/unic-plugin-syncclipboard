# SyncClipboard plugin for UniClipboard

`unic.syncclipboard` runs a SyncClipboard-compatible HTTP server as a separate
`unicd` plugin process. Enable it explicitly. It uses UniClipboard's external
channels and does not confer native device trust.

## Setup

1. Use a `unicd` build that supports `backend.authorize_channel` and
   `unic device channel-add`.
2. Install the prebuilt plugin. The installer verifies its SHA-256 digest.

   ```sh
   unic plugin install https://github.com/UniClipboard/unic-plugin-syncclipboard --ref v0.1.1
   ```

3. Generate a 32-byte random key as 64 hexadecimal characters. Save the
   following JSON in a file readable only by the current user. Use the generated
   key for `credential_key`.

   ```json
   {
     "values": {
       "listen": "127.0.0.1:42720",
       "credential_key": "<64 hexadecimal characters>"
     }
   }
   ```

4. Run `unic plugin settings save unic.syncclipboard SETTINGS.json`. Remove the
   temporary settings file after the command succeeds. Run
   `unic plugin enable unic.syncclipboard` and restart `unicd`.
5. Keep `unicd` running. Run
   `unic device channel-add unic.syncclipboard "Client name"`. The returned channel
   ID is the Basic Auth username. Repeat with a distinct name for each client.
6. Run `unic-plugin-syncclipboard credential CHANNEL_ID` with the key on standard
   input. Use the output as the client's password. Build the helper with
   `go build ./cmd/unic-plugin-syncclipboard` if needed. Keep the derivation key
   private. Clients receive only their own password.
7. Point the client at the listener. To use the server on another device, expose
   the loopback listener through an HTTPS reverse proxy that forwards the
   Authorization header and preserves request paths and methods. Set the proxy's
   request size limit for the payload limits below.

Use `unic device list --json` for current channel IDs and revisions. Run
`unic device channel pause|resume|remove CHANNEL_ID REVISION` to manage access.
To replace a client's credential, remove the channel and register a new one.
Changing plugin settings invalidates the instance's existing channels on restart.

## Protocol scope

The server accepts inline or externally stored UTF-8 text and PNG, JPEG, GIF and
WebP images up to 2 MiB. It implements `GET/PUT /SyncClipboard.json` and
`GET/PUT /file/{name}`. An upload stages at most one body per channel for one
minute. The document commit checks a supplied SHA-256 hash and gives the content
to Engine. It does not publish that upload to another channel.

A successful outbound target means that the plugin published a snapshot for
pull. The plugin retains the latest two snapshots per channel for up to 30
minutes, with a maximum of 32 channels holding snapshots or staging. Files,
directories, Group documents, SSE, history extensions, remote-server client mode
and automatic gateway forwarding are outside this version. Exact echoes of the
current publication are acknowledged without creating a new history item.

The listener accepts loopback addresses. It checks Engine authorization for each
HTTP operation. Requests that have already received authorization can finish
during revocation. Neither published snapshots nor staging survive a plugin
restart.

See the upstream [SyncClipboard API](https://github.com/Jeric-X/SyncClipboard#api)
and [content hashes](https://github.com/Jeric-X/SyncClipboard/blob/master/docs/Hash.md).

## Build with a local v2 SDK checkout

The required host SDK revision is `87afcda15ab75234679bb8b8aa0992104f8cfb6c`.
Source installation from GitHub requires that this revision be reachable
from the upstream module repository. Use a temporary Go workspace when the
matching host source is available locally:

```sh
work=$(mktemp -d)
(cd "$work" && go work init /absolute/path/to/UniClipboard "$OLDPWD")
GOWORK="$work/go.work" go build ./cmd/unic-plugin-syncclipboard
```

Run the installed-process acceptance from the matching host source with
`UNIC_E2E_SYNCCLIPBOARD` set to this checkout. See the host's
`docs/exec/0029-extensible-sync-backend-integration.md` for the replay command.
