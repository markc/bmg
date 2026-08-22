# BeMyGuest — project context

Single-file PHP file-drop for the LAN. See [README.md](README.md) for what it
does and how to run it; this file is the working brief for agents.

## The one rule

**Everything lives in `bmg.php`.** Router, config, JSON API, HTML, CSS and JS.
No composer, no build step, no vendor dir, no separate `.css`/`.js` assets.
If a change would add a second source file, it's the wrong change — fold it in
or say why the constraint should break.

`index.php` is a symlink to `bmg.php`, so a bare `/` works under any SAPI.

## Layout of bmg.php

| Lines  | What                                                    |
|--------|---------------------------------------------------------|
| 18–28  | `cli-server` router — blocks `/uploads`, passes static files through |
| 31–50  | `Cfg` — every tunable, as constructor defaults          |
| 52–84  | `Role` and `Act` enums                                  |
| 87–104 | `Session` — role stored via a property hook over `$_SESSION` |
| 107–375| `Api` — one private method per `Act` case               |
| 378–…  | `Page` — a `Stringable` returning the whole document    |
| 600–947| `css()` — heredoc, CSS custom properties, `[data-theme]` |
| 949–…  | `js()` — heredoc, one IIFE                              |
| 1526–  | Entry: no `action` → render `Page`; else `Api::dispatch` |

Line numbers drift — grep for the `// ── Section ──` banners rather than
trusting them.

## PHP 8.5 idioms in use

Deliberate, not accidental. Keep the style; don't "modernise" it backwards.

- Pipe operator `|>` (`safeName()`, `files()`)
- `#[\NoDiscard]` on results that must be checked
- Property hooks (`Session::$role`)
- `new Api($cfg)->dispatch(...)` without wrapping parens
- `final readonly class`, backed enums, `match`, `never` return types
- `$cond ?: $this->fail(...)` as a guard idiom throughout `Api`

Anything below 8.5 will not parse. `php -l bmg.php` after every edit.

## Gotchas that have already bitten

- **`PHP_CLI_SERVER_WORKERS=8`** — without it `php -S` is single-threaded and
  media Range requests serialise; the UI freezes while anything streams.
- **The `/uploads` guard only runs under `php -S`.** Behind FrankenPHP, Caddy
  or nginx it never fires — the server config must deny `/uploads/*`.
  `uploads/.htaccess` covers Apache.
- **MIME is extension-first** (`Api::mime()`). libmagic reports FLAC as
  `audio/x-flac`, which Firefox refuses to play over HTTP even though it
  decodes the file fine. Don't "fix" it back to `mime_content_type()` first.
- **`safeName()` vs `path()`** — `safeName()` sanitises *new* names
  (upload/rename). Lookups go through `path()`, which only does `basename()`.
  Re-sanitising on lookup would 404 files dropped into `uploads/` by hand with
  spaces or quotes in the name.
- **`send()` must `session_write_close()` before streaming.** PHP holds the
  session lock for the whole request, so an open stream blocked every other
  request from the same browser — the next Range, the file list — and video
  stuttered. Measured: 3.5 s vs 7 ms for a status call behind an open stream.
- **`send()` must flush the output buffers** before streaming. `readfile()`
  buffers the whole file under the built-in server, and `<video>` seeking
  needs real 206 partial responses.
- **`upload_max_filesize` / `post_max_size` are `PHP_INI_PERDIR`** — `ini_set()`
  cannot touch them. `Cfg::$maxSize` is only a post-hoc check.

## Testing a change

There is no test suite. Verify by hand:

```sh
PHP_CLI_SERVER_WORKERS=8 php -S 0.0.0.0:8000 bmg.php
```

Then exercise the path you touched: unlock as guest and as admin, upload a
multi-file batch, open a video in the lightbox and **seek** (that's the Range
path), rename, copy-link, delete. Check both light and dark themes.

## Never commit

- **Real passphrase hashes.** `Cfg::$guestHash` / `$adminHash` ship as sha256 of
  `guest` / `admin` — demo values, and they stay that way in git. A hash with
  its plaintext in a comment is a plaintext password in a public repo.
- Anything under `uploads/` except `.htaccess` (already gitignored).
