# BeMyGuest

A single-file, passphrase-gated file drop for your LAN. Guests upload; the host
lists, previews, downloads, renames and deletes.

Everything — router, JSON API, HTML, CSS and JavaScript — lives in one
`bmg.php`. No composer, no build step, no database, no dependencies.

![Be My Guest landing page](uploads/screenshot.webp)

## Requirements

**PHP 8.5 or newer.** The code uses the pipe operator (`|>`), `#[\NoDiscard]`,
property hooks, and `new Foo()->bar()` — it will not parse on older versions.

## Run

```sh
PHP_CLI_SERVER_WORKERS=8 php -S 0.0.0.0:8000 bmg.php
```

Then open `http://<host>:8000/`.

The `PHP_CLI_SERVER_WORKERS` env var matters. Without it `php -S` is
single-threaded, so every media Range request queues behind the previous one —
video playback stutters and the whole UI freezes while anything streams.

## Passphrases

Two roles, each a shared passphrase — no accounts, no sign-up:

| Role  | Can do                                                        |
|-------|---------------------------------------------------------------|
| guest | Upload files                                                  |
| admin | Everything guest can, plus list, download, stream, rename, delete |

The shipped defaults are `guest` and `admin`. **Change them before you expose
this to anyone.** Passphrases are stored as SHA-256 hashes in `Cfg`:

```sh
echo -n 'yourpass' | sha256sum
```

Paste the hash into `Cfg::$guestHash` / `Cfg::$adminHash` near the top of
`bmg.php`.

## Configuration

All tunables are constructor defaults on the `Cfg` class:

| Property     | Default                    | Notes                              |
|--------------|----------------------------|------------------------------------|
| `$site`      | `Be My Guest`              | Title and branding                 |
| `$tagline`   | `File sharing, the friendly way` |                              |
| `$guestHash` | sha256 of `guest`          | Change this                        |
| `$adminHash` | sha256 of `admin`          | Change this                        |
| `$uploadDir` | `./uploads`                | Must be writable by the PHP user   |
| `$maxSize`   | 4 GB                       | Enforced per file, in-app          |
| `$maxExec`   | `600`                      | `max_execution_time`               |
| `$memLimit`  | `512M`                     | `memory_limit`                     |
| `$sessKey`   | `bmg_role`                 | Session key holding the role       |

### Upload limits

`upload_max_filesize` and `post_max_size` are `PHP_INI_PERDIR` — they **cannot**
be set from script code. Raise them in `php.ini`, or pass them on the command
line:

```sh
PHP_CLI_SERVER_WORKERS=8 php -S 0.0.0.0:8000 \
    -d upload_max_filesize=4G -d post_max_size=4G bmg.php
```

`Cfg::$maxSize` only rejects oversize files *after* PHP has accepted the POST,
so it needs the ini values to be at least as large to be meaningful.

## Features

- Drag-and-drop or browse multi-file upload, with a live progress bar
- In-browser preview: video, audio and images open in a lightbox
- Range-aware chunked streaming, so `<video>` seeking works on multi-GB files
- Copy-link, rename and delete from the file list (admin only)
- Light/dark theme, remembered in `localStorage`
- Automatic de-duplication — an uploaded name that already exists gets a
  `-1`, `-2`, … suffix rather than overwriting

## API

Every endpoint is `?action=…` against the same file, and returns JSON.

| Action     | Method | Role  | Params            |
|------------|--------|-------|-------------------|
| `auth`     | POST   | —     | `passphrase`      |
| `logout`   | POST   | —     |                   |
| `status`   | GET    | —     |                   |
| `upload`   | POST   | guest | `files[]`         |
| `list`     | GET    | admin |                   |
| `download` | GET    | admin | `file`            |
| `stream`   | GET    | admin | `file` (Range-aware) |
| `rename`   | POST   | admin | `old`, `new`      |
| `delete`   | POST   | admin | `file`            |

## Deployment notes

The `/uploads` guard at the top of `bmg.php` only runs under `php -S`
(`PHP_SAPI === 'cli-server'`). Behind any other server you must block direct
access yourself:

- **Apache** — the bundled `uploads/.htaccess` (`Require all denied`) handles it,
  provided `AllowOverride` permits it.
- **FrankenPHP / Caddy / nginx** — deny `/uploads/*` in the server config.

Uploads are meant to be reachable only through `?action=download` and
`?action=stream`, both of which require the admin role.

## Security

This is a LAN convenience tool, not a hardened public service. Known limits,
stated plainly:

- **No CSRF tokens.** A logged-in admin visiting a hostile page could be made to
  delete or rename files.
- **No rate limiting** on the passphrase form — brute force is unthrottled.
- **No TLS of its own.** Over plain HTTP the passphrase crosses the wire in the
  clear. Put it behind a reverse proxy with TLS if it leaves your LAN.
- Passphrases are plain SHA-256, not a slow password hash.
- Filenames are sanitised to `[\w.\-]` on upload and rename, and lookups use
  `basename()`, so path traversal is blocked — but uploaded *content* is never
  scanned or validated.

Anyone with the guest passphrase can fill your disk.

## Licence

MIT — see [LICENSE](LICENSE).
