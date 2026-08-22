<?php declare(strict_types=1);
// Copyright (C) 2026 Mark Constable <markc@renta.net> (MIT License)
//
// BeMyGuest (bmg.php) — a single-file, passphrase-gated LAN file drop.
// Guests upload; the host lists, downloads, renames and deletes.
//
// Run:   PHP_CLI_SERVER_WORKERS=8 php -S 0.0.0.0:8000 bmg.php
//
// The workers env var matters: without it php -S is single-threaded and
// every media Range request queues behind the previous one — video
// playback stutters and the UI freezes while anything streams.
//
// Upload limits (upload_max_filesize / post_max_size) are PHP_INI_PERDIR and
// CANNOT be set from script code — raise them in php.ini or via -d flags.
// Behind FrankenPHP/Caddy the /uploads guard below never runs (cli-server
// only) — deny /uploads/* in the server config instead.

// ── Router (php -S only; top-level `return false` hands file to the SAPI) ──
if (PHP_SAPI === 'cli-server') {
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
    if (str_starts_with($uri, '/uploads')) {
        http_response_code(403);
        exit('Forbidden');
    }
    if ($uri !== '/' && !str_ends_with($uri, '.php') && is_file(__DIR__ . $uri)) {
        return false;
    }
}

// ── Config — everything tunable lives here ──────────────────────────────
final readonly class Cfg
{
    public function __construct(
        public string $site      = 'Be My Guest',
        public string $tagline   = 'File sharing, the friendly way',
        // SHA-256 passphrase hashes (generate with: echo -n 'yourpass' | sha256sum)
        public string $guestHash = '84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec', // "guest" — CHANGE THIS
        public string $adminHash = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', // "admin" — CHANGE THIS
        public string $uploadDir = __DIR__ . '/uploads',
        public int    $maxSize   = 4 * 1024 ** 3,
        public string $maxExec   = '600',
        public string $memLimit  = '512M',
        public string $sessKey   = 'bmg_role',
    ) {}

    public function maxSizeGb(): int
    {
        return intdiv($this->maxSize, 1024 ** 3);
    }
}

enum Role: string
{
    case Guest = 'guest';
    case Admin = 'admin';

    #[\NoDiscard('authentication result must be checked')]
    public static function fromPass(string $pass, Cfg $cfg): ?self
    {
        return match (hash('sha256', $pass)) {
            $cfg->adminHash => self::Admin,
            $cfg->guestHash => self::Guest,
            default         => null,
        };
    }

    public function covers(self $need): bool
    {
        return $this === self::Admin || $this === $need;
    }
}

enum Act: string
{
    case Auth     = 'auth';
    case Logout   = 'logout';
    case Status   = 'status';
    case Upload   = 'upload';
    case Files    = 'list';
    case Download = 'download';
    case Stream   = 'stream';
    case Rename   = 'rename';
    case Delete   = 'delete';
}

// ── Session — the stored role, as a property hook over $_SESSION ────────
final class Session
{
    public function __construct(private readonly Cfg $cfg)
    {
        session_start();
    }

    public ?Role $role {
        get => Role::tryFrom($_SESSION[$this->cfg->sessKey] ?? '');
        set {
            if ($value === null) {
                unset($_SESSION[$this->cfg->sessKey]);
            } else {
                $_SESSION[$this->cfg->sessKey] = $value->value;
            }
        }
    }
}

// ── Api — JSON endpoints, dispatched off ?action=… ──────────────────────
final class Api
{
    private readonly Session $sess;

    public function __construct(private readonly Cfg $cfg)
    {
        ini_set('max_execution_time', $cfg->maxExec);
        ini_set('memory_limit', $cfg->memLimit);
        $this->sess = new Session($cfg);
    }

    public function dispatch(string $action): never
    {
        match (Act::tryFrom($action)) {
            Act::Auth     => $this->auth(),
            Act::Logout   => $this->logout(),
            Act::Status   => $this->status(),
            Act::Upload   => $this->upload(),
            Act::Files    => $this->files(),
            Act::Download => $this->download(),
            Act::Stream   => $this->stream(),
            Act::Rename   => $this->rename(),
            Act::Delete   => $this->delete(),
            null          => $this->fail('Unknown action', 400),
        };
    }

    // ── helpers ──

    private function json(mixed $data, int $code = 200): never
    {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    private function fail(string $msg, int $code = 400): never
    {
        $this->json(['error' => $msg], $code);
    }

    private function need(Role $role): void
    {
        $this->sess->role?->covers($role) ?: $this->fail('Not authenticated', 401);
    }

    private function safeName(string $name): string
    {
        return $name
            |> basename(...)
            |> (static fn(string $n) => preg_replace('/[^\w.\-]/', '_', $n) ?? $n)
            |> (static fn(string $n) => $n === '' ? 'unnamed' : $n);
    }

    // Lookup by the name as stored — basename() alone blocks traversal.
    // safeName() is only for NEW names (upload/rename); re-sanitising here
    // would 404 files dropped into uploads/ by hand with spaces/quotes.
    private function path(string $name): string
    {
        $path = $this->cfg->uploadDir . '/' . basename($name);
        is_file($path) ?: $this->fail('File not found: ' . basename($path), 404);
        return $path;
    }

    #[\NoDiscard]
    private function info(string $name): array
    {
        $path = $this->cfg->uploadDir . '/' . $name;
        return [
            'name'     => $name,
            'size'     => filesize($path),
            'modified' => date('c', filemtime($path)),
            'type'     => $this->mime($path),
        ];
    }

    // Extension-first for media: libmagic reports e.g. audio/x-flac, which
    // Firefox refuses to play over HTTP even though it decodes FLAC fine.
    private function mime(string $path): string
    {
        return match (strtolower(pathinfo($path, PATHINFO_EXTENSION))) {
            'flac'         => 'audio/flac',
            'mp3'          => 'audio/mpeg',
            'm4a'          => 'audio/mp4',
            'aac'          => 'audio/aac',
            'ogg', 'oga'   => 'audio/ogg',
            'opus'         => 'audio/ogg; codecs=opus',
            'wav'          => 'audio/wav',
            'mp4', 'm4v'   => 'video/mp4',
            'mkv'          => 'video/x-matroska',
            'webm'         => 'video/webm',
            'mov'          => 'video/quicktime',
            'png'          => 'image/png',
            'jpg', 'jpeg'  => 'image/jpeg',
            'gif'          => 'image/gif',
            'webp'         => 'image/webp',
            'svg'          => 'image/svg+xml',
            default        => mime_content_type($path) ?: 'application/octet-stream',
        };
    }

    // ── handlers ──

    private function auth(): never
    {
        $role = Role::fromPass($_POST['passphrase'] ?? '', $this->cfg)
            ?? $this->fail('Incorrect passphrase', 401);
        $this->sess->role = $role;
        $this->json(['role' => $role->value]);
    }

    private function logout(): never
    {
        $this->sess->role = null;
        $this->json(['ok' => true]);
    }

    private function status(): never
    {
        $this->json(['role' => $this->sess->role?->value]);
    }

    private function upload(): never
    {
        $this->need(Role::Guest);

        $f = $_FILES['files'] ?? $this->fail('No files provided');

        $batch = is_array($f['name'])
            ? array_map(
                static fn($n, $t, $e, $s) => ['name' => $n, 'tmp' => $t, 'error' => $e, 'size' => $s],
                $f['name'], $f['tmp_name'], $f['error'], $f['size'],
            )
            : [['name' => $f['name'], 'tmp' => $f['tmp_name'], 'error' => $f['error'], 'size' => $f['size']]];

        $uploaded = [];
        foreach ($batch as ['name' => $name, 'tmp' => $tmp, 'error' => $error, 'size' => $size]) {
            $error === UPLOAD_ERR_OK
                ?: $this->fail("Upload error for {$name}: code {$error}");
            $size <= $this->cfg->maxSize
                ?: $this->fail("File too large: {$name} (" . round($size / 1024 / 1024, 1) . " MB)");

            $safe = $this->safeName($name);

            // Avoid overwrites — append counter
            $dest = $this->cfg->uploadDir . '/' . $safe;
            if (is_file($dest)) {
                $ext  = pathinfo($safe, PATHINFO_EXTENSION);
                $base = pathinfo($safe, PATHINFO_FILENAME);
                $n = 1;
                do {
                    $safe = $base . '-' . $n . ($ext ? '.' . $ext : '');
                    $dest = $this->cfg->uploadDir . '/' . $safe;
                    $n++;
                } while (is_file($dest));
            }

            move_uploaded_file($tmp, $dest);
            $uploaded[] = $this->info($safe);
        }

        $this->json(['uploaded' => $uploaded]);
    }

    private function files(): never
    {
        $this->need(Role::Admin);

        $dir   = $this->cfg->uploadDir;
        $files = (scandir($dir) ?: [])
            |> (static fn(array $fs) => array_filter(
                $fs,
                static fn(string $f) => $f[0] !== '.' && is_file("$dir/$f"),
            ))
            |> array_values(...);

        // Sort newest first
        usort($files, static fn($a, $b) => filemtime("$dir/$b") <=> filemtime("$dir/$a"));

        $this->json(['files' => array_map($this->info(...), $files)]);
    }

    private function download(): never
    {
        $this->need(Role::Admin);
        $this->send($this->path($_GET['file'] ?? ''), inline: false);
    }

    private function stream(): never
    {
        $this->need(Role::Admin);
        $this->send($this->path($_GET['file'] ?? ''), inline: true);
    }

    // Chunked, Range-aware sender — readfile() buffers the whole file under
    // the built-in server, and <video> seeking needs 206 partial responses.
    private function send(string $path, bool $inline): never
    {
        $size = filesize($path);
        [$start, $end] = [0, $size - 1];

        if ($inline
            && preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'] ?? '', $m)
            && $m[1] . $m[2] !== ''
        ) {
            [$start, $end] = $m[1] === ''
                ? [max(0, $size - (int) $m[2]), $size - 1]
                : [(int) $m[1], $m[2] === '' ? $size - 1 : min((int) $m[2], $size - 1)];
            if ($start > $end || $start >= $size) {
                header("Content-Range: bytes */{$size}");
                $this->fail('Range not satisfiable', 416);
            }
            http_response_code(206);
            header("Content-Range: bytes {$start}-{$end}/{$size}");
        }

        header('Content-Type: ' . $this->mime($path));
        header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment')
            . '; filename="' . basename($path) . '"');
        header('Accept-Ranges: bytes');
        header('Content-Length: ' . ($end - $start + 1));

        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        $fh = fopen($path, 'rb') ?: $this->fail('Cannot open file', 500);
        fseek($fh, $start);
        for ($left = $end - $start + 1; $left > 0; $left -= strlen($buf)) {
            $buf = fread($fh, min($left, 1 << 20));
            if ($buf === false || $buf === '') {
                break;
            }
            echo $buf;
            flush();
        }
        fclose($fh);
        exit;
    }

    private function rename(): never
    {
        $this->need(Role::Admin);

        $new = $_POST['new'] ?? '';
        $new !== '' ?: $this->fail('New name is required');

        $oldPath = $this->path($_POST['old'] ?? '');
        $newSafe = $this->safeName($new);
        $newPath = $this->cfg->uploadDir . '/' . $newSafe;

        if ($oldPath === $newPath) {
            $this->json($this->info($newSafe));
        }
        !is_file($newPath) ?: $this->fail('A file with that name already exists');

        rename($oldPath, $newPath);
        $this->json($this->info($newSafe));
    }

    private function delete(): never
    {
        $this->need(Role::Admin);

        $path = $this->path($_POST['file'] ?? '');
        unlink($path);
        $this->json(['ok' => true, 'deleted' => basename($path)]);
    }
}

// ── Page — the whole UI as one Stringable ────────────────────────────────
final readonly class Page implements \Stringable
{
    public function __construct(private Cfg $cfg) {}

    #[\Override]
    public function __toString(): string
    {
        $site = $this->cfg->site;
        $tag  = $this->cfg->tagline;
        $gb   = $this->cfg->maxSizeGb();
        $css  = $this->css();
        $js   = $this->js();

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="{$site} — {$tag}.">
<meta name="theme-color" content="#04121c">
<title>{$site} — {$tag}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%93%81%3C/text%3E%3C/svg%3E">
<script>(function(){var t=localStorage.getItem("bmg-theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark");document.documentElement.setAttribute("data-theme",t);})();</script>
<style>
{$css}
</style>
</head>
<body>

<canvas id="stars" aria-hidden="true"></canvas>
<div class="aurora" aria-hidden="true"><span></span><span></span><span></span></div>
<div class="grain" aria-hidden="true"></div>

<div class="shell">

<header>
    <div class="wrap bar">
        <a href="/" class="brand">
            <span class="mark">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7h-3a2 2 0 0 1-2-2V2"/><path d="M9 18a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h7l4 4v10a2 2 0 0 1-2 2Z"/><path d="M3 7.6v12.8A1.6 1.6 0 0 0 4.6 22h9.8"/></svg>
            </span>
            Be&nbsp;My&nbsp;<em>Guest</em>
        </a>
        <nav>
            <a href="#features">Features</a>
            <a href="#upload">Upload</a>
            <span class="auth-badge-text" id="authBadge"></span>
            <button class="lock-btn" id="lockBtn" title="Lock/Unlock">
                <svg id="lockIcon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <span id="lockLabel">Unlock</span>
            </button>
            <button class="lock-btn" id="themeBtn" title="Toggle light/dark theme">🌙</button>
        </nav>
    </div>
</header>

<!-- Auth Modal -->
<div class="overlay hidden" id="authOverlay">
    <div class="modal-card">
        <div class="auth-icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>
        <h2>Enter passphrase</h2>
        <p>This site is protected. Enter the shared passphrase to upload and manage files.</p>
        <form id="authForm">
            <input type="password" class="modal-input" id="authInput" placeholder="Passphrase" autocomplete="off" autofocus>
            <p class="auth-error" id="authError">Incorrect passphrase. Try again.</p>
            <button type="submit" class="btn btn-primary auth-submit">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 5-5 5 5 0 0 1 5 5v4"/></svg>
                Unlock
            </button>
        </form>
    </div>
</div>

<main>
    <!-- Hero -->
    <div class="wrap hero">
        <div class="eyebrow rise"><span class="dot"></span> Simple · Secure · Shareable</div>
        <h1 class="rise">File sharing,<br><span class="grad">the friendly way.</span></h1>
        <p class="lede rise">
            {$site} makes it effortless to upload, store, and share your files.
            One passphrase, no sign-up, no fuss.
        </p>
        <div class="cta rise">
            <a href="#upload" class="btn btn-primary" id="heroUploadBtn">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m17 8-5-5-5 5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/></svg>
                Start Uploading
            </a>
            <a href="#features" class="btn btn-ghost">Learn more</a>
        </div>
    </div>

    <!-- Features -->
    <section id="features" class="wrap">
        <h2 class="h2 rise">Why {$site}?</h2>
        <p class="sub rise">A no-nonsense file sharing tool for people who value simplicity.</p>
        <div class="grid">
            <article class="card rise">
                <div class="ico">🔑</div>
                <h3>Passphrase-protected</h3>
                <p>A single shared passphrase keeps your uploads private without complex user management.</p>
            </article>
            <article class="card rise">
                <div class="ico">⚡</div>
                <h3>Blazing fast</h3>
                <p>Files are stored locally and streamed directly — no external dependencies, no bottlenecks.</p>
            </article>
            <article class="card rise">
                <div class="ico">🔗</div>
                <h3>Easy sharing</h3>
                <p>Every uploaded file gets a direct link you can share instantly with anyone who has access.</p>
            </article>
        </div>
    </section>

    <!-- Stats -->
    <section class="wrap">
        <div class="stats rise">
            <div class="stat"><b data-count="{$gb}" data-suffix="GB">0GB</b><span>Max file size</span></div>
            <div class="stat"><b data-count="100" data-suffix="%">0%</b><span>Self-hosted</span></div>
            <div class="stat"><b data-count="1" data-suffix="">0</b><span>Passphrase</span></div>
            <div class="stat"><b data-count="0" data-suffix="">0</b><span>Sign-ups</span></div>
        </div>
    </section>

    <!-- Upload -->
    <section id="upload">
        <div class="wrap upload-wrap">
            <h2 class="h2 rise">Your Files</h2>
            <p class="sub rise">Upload new files or manage existing ones below.</p>

            <!-- Locked state (shown when not authenticated) -->
            <div class="upload-locked card" id="uploadLocked">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <p><strong>Authentication required</strong></p>
                <p>Enter the passphrase to upload and manage files.</p>
                <button class="btn btn-primary" onclick="showAuthModal()">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 5-5 5 5 0 0 1 5 5v4"/></svg>
                    Unlock
                </button>
            </div>

            <!-- Unlocked upload UI (hidden until authenticated) -->
            <div id="uploadUnlocked" style="display: none;">
            <div class="dropzone" id="dropzone">
                <div class="dropzone-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m17 8-5-5-5 5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/></svg>
                </div>
                <div class="dropzone-text">
                    <p>Drag files here</p>
                    <p>or <span class="browse">browse your computer</span></p>
                </div>
                <input type="file" id="fileInput" multiple>
            </div>

            <div class="upload-progress" id="uploadProgress">
                <div class="progress-info">
                    <span class="filename" id="progressFilename"></span>
                    <span class="percent" id="progressPercent">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-bar-fill" id="progressFill"></div>
                </div>
            </div>

            <!-- File list: admin only -->
            <div class="file-list" id="fileListSection" style="display: none;">
                <h3>Uploaded Files</h3>
                <div id="fileListContent">
                    <div class="file-list-empty" id="emptyState">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>
                        <p>No files uploaded yet</p>
                        <p>Use the uploader above to add your first file.</p>
                    </div>
                </div>
            </div>
            </div><!-- /uploadUnlocked -->
        </div>
    </section>
</main>

<footer>
    <div class="wrap foot">
        <span>&copy; <span id="yr">2026</span> {$site} — {$tag}.</span>
        <span>One file. One passphrase. Zero fuss.</span>
    </div>
</footer>

</div><!-- /shell -->

<!-- Rename Modal -->
<div class="overlay hidden" id="renameOverlay">
    <div class="modal-card">
        <h3>Rename file</h3>
        <input type="text" class="modal-input" id="renameInput" placeholder="New filename">
        <input type="hidden" id="renameOld">
        <div class="rename-actions">
            <button class="btn btn-ghost btn-sm" id="renameCancel">Cancel</button>
            <button class="btn btn-primary btn-sm" id="renameSave">Rename</button>
        </div>
    </div>
</div>

<!-- Lightbox -->
<div class="overlay hidden" id="lightbox">
    <button class="lb-close" id="lightboxClose" title="Close">✕</button>
    <div class="lb-body" id="lightboxBody"></div>
</div>

<div class="toast" id="toast"></div>

<script>
{$js}
</script>

</body>
</html>
HTML;
    }

    private function css(): string
    {
        return <<<'CSS'
  :root{
    --bg:#04121c;
    --bg-2:#071c2b;
    --ink:#eaf4fb;
    --ink-dim:#9fbdd0;
    --ink-faint:#6b8ba0;
    --gold:#ffc94d;
    --teal:#4fd1c5;
    --azure:#4aa8ff;
    --danger:#ff6b6b;
    --success:#3ddc97;
    --line:rgba(255,255,255,.10);
    --card:rgba(255,255,255,.045);
    --card-hi:rgba(255,255,255,.075);
    --header-bg:rgba(4,18,28,.6);
    --stat-bg:rgba(4,18,28,.72);
    --overlay-bg:rgba(2,10,16,.7);
    --maxw:1080px;
    --ease:cubic-bezier(.22,.61,.36,1);
  }
  :root[data-theme="light"]{
    --bg:#eef4f9;
    --bg-2:#ffffff;
    --ink:#0d2233;
    --ink-dim:#3d5e77;
    --ink-faint:#64809a;
    --line:rgba(6,30,48,.13);
    --card:rgba(255,255,255,.6);
    --card-hi:rgba(255,255,255,.9);
    --header-bg:rgba(238,244,249,.7);
    --stat-bg:rgba(255,255,255,.75);
    --overlay-bg:rgba(10,30,45,.45);
  }
  :root[data-theme="light"] .aurora span{opacity:.35}
  :root[data-theme="light"] .grain{opacity:.03}
  *{margin:0;padding:0;box-sizing:border-box}
  html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
  body{
    font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    background:var(--bg);
    color:var(--ink);
    line-height:1.6;
    overflow-x:hidden;
    min-height:100vh;
    -webkit-font-smoothing:antialiased;
  }

  /* ---------- animated backdrop ---------- */
  #stars{position:fixed;inset:0;width:100%;height:100%;z-index:0;display:block}
  .aurora{position:fixed;inset:0;z-index:1;pointer-events:none;overflow:hidden}
  .aurora span{
    position:absolute;border-radius:50%;filter:blur(90px);opacity:.5;
    animation:drift 26s var(--ease) infinite alternate;
  }
  .aurora span:nth-child(1){width:52vmax;height:52vmax;left:-16vmax;top:-20vmax;
    background:radial-gradient(circle at 35% 35%,rgba(74,168,255,.55),transparent 62%)}
  .aurora span:nth-child(2){width:46vmax;height:46vmax;right:-16vmax;top:6vmax;
    background:radial-gradient(circle at 60% 40%,rgba(79,209,197,.42),transparent 62%);animation-duration:32s;animation-delay:-8s}
  .aurora span:nth-child(3){width:40vmax;height:40vmax;left:22vmax;bottom:-20vmax;
    background:radial-gradient(circle at 50% 50%,rgba(255,201,77,.26),transparent 62%);animation-duration:38s;animation-delay:-16s}
  @keyframes drift{
    from{transform:translate3d(0,0,0) scale(1)}
    to{transform:translate3d(6vmax,-4vmax,0) scale(1.16)}
  }
  .grain{
    position:fixed;inset:0;z-index:2;pointer-events:none;opacity:.05;
    background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.8' numOctaves='3'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  }

  /* ---------- shell ---------- */
  .shell{position:relative;z-index:3;display:flex;flex-direction:column;min-height:100vh}
  .wrap{max-width:var(--maxw);margin-inline:auto;padding-inline:clamp(1.25rem,4vw,2.5rem);width:100%}

  header{padding-block:clamp(1rem,2.5vw,1.5rem);position:sticky;top:0;z-index:50;
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    background:var(--header-bg);border-bottom:1px solid var(--line)}
  .bar{display:flex;align-items:center;justify-content:space-between;gap:1rem}
  .brand{display:flex;align-items:center;gap:.6rem;font-weight:700;letter-spacing:-.02em;font-size:1.15rem;
    text-decoration:none;color:var(--ink)}
  .mark{
    width:34px;height:34px;flex:none;border-radius:10px;display:grid;place-items:center;
    background:linear-gradient(145deg,var(--azure),var(--teal));
    color:#04121c;box-shadow:0 6px 22px rgba(74,168,255,.34);
  }
  .mark svg{width:1rem;height:1rem}
  .brand em{font-style:normal;
    background:linear-gradient(100deg,var(--azure),var(--teal) 45%,var(--gold));
    -webkit-background-clip:text;background-clip:text;color:transparent}
  nav{display:flex;align-items:center;gap:.4rem;font-size:.93rem}
  nav a{color:var(--ink-dim);text-decoration:none;transition:color .2s;padding:.4rem .6rem;border-radius:.5rem}
  nav a:hover,nav a:focus-visible{color:var(--ink)}
  .auth-badge-text{font-size:.8rem;padding-inline:.4rem}
  .auth-badge-text.granted{color:var(--success)}
  .auth-badge-text.admin{color:var(--gold)}
  .lock-btn{
    display:inline-flex;align-items:center;gap:.4rem;font-size:.875rem;
    color:var(--ink-dim);background:var(--card);border:1px solid var(--line);
    padding:.45rem .85rem;border-radius:999px;cursor:pointer;
    transition:background .2s,color .2s,border-color .2s;
  }
  .lock-btn:hover{background:var(--card-hi);color:var(--ink);border-color:rgba(79,209,197,.32)}
  .lock-btn svg{width:1rem;height:1rem}
  @media(max-width:620px){nav a[href^="#"]{display:none}}

  /* ---------- hero ---------- */
  .hero{padding-block:clamp(3.5rem,11vh,7rem) clamp(2.5rem,7vh,4.5rem);text-align:center}
  .eyebrow{
    display:inline-flex;align-items:center;gap:.5rem;
    font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;
    color:var(--teal);border:1px solid var(--line);border-radius:999px;
    padding:.4rem .85rem;background:var(--card);margin-bottom:1.5rem;
  }
  .dot{width:6px;height:6px;border-radius:50%;background:var(--teal);
    box-shadow:0 0 0 0 rgba(79,209,197,.6);animation:pulse 2.4s infinite}
  @keyframes pulse{
    70%{box-shadow:0 0 0 9px rgba(79,209,197,0)}
    100%{box-shadow:0 0 0 0 rgba(79,209,197,0)}
  }
  h1{
    font-size:clamp(2.6rem,7.5vw,4.6rem);
    line-height:1.03;letter-spacing:-.035em;font-weight:800;margin-bottom:1.1rem;
  }
  h1 .grad{
    background:linear-gradient(100deg,var(--azure),var(--teal) 45%,var(--gold));
    -webkit-background-clip:text;background-clip:text;color:transparent;
  }
  .lede{font-size:clamp(1.05rem,2.1vw,1.3rem);color:var(--ink-dim);max-width:56ch;margin:0 auto 2.25rem}
  .cta{display:flex;flex-wrap:wrap;gap:.85rem;justify-content:center}

  .btn{
    display:inline-flex;align-items:center;gap:.5rem;
    padding:.8rem 1.5rem;border-radius:999px;font-weight:600;font-size:.98rem;
    text-decoration:none;cursor:pointer;
    transition:transform .18s var(--ease),box-shadow .18s var(--ease),background .18s;
    border:1px solid transparent;
  }
  .btn svg{width:1.1rem;height:1.1rem}
  .btn-primary{background:linear-gradient(135deg,var(--azure),var(--teal));color:#04121c;
    box-shadow:0 10px 30px rgba(74,168,255,.3)}
  .btn-primary:hover{transform:translateY(-2px);box-shadow:0 16px 40px rgba(74,168,255,.42)}
  .btn-ghost{border-color:var(--line);color:var(--ink);background:var(--card)}
  .btn-ghost:hover{background:var(--card-hi);transform:translateY(-2px)}
  .btn-sm{padding:.5rem 1rem;font-size:.8rem}

  /* ---------- sections / cards ---------- */
  section{padding-block:clamp(2.5rem,7vh,4.5rem)}
  .h2{font-size:clamp(1.5rem,3.4vw,2.1rem);letter-spacing:-.025em;font-weight:700;margin-bottom:.6rem;text-align:center}
  .sub{color:var(--ink-faint);margin:0 auto 2.25rem;max-width:52ch;text-align:center}
  .grid{display:grid;gap:1.1rem;grid-template-columns:repeat(auto-fit,minmax(255px,1fr))}
  .card{
    position:relative;padding:1.6rem;border-radius:16px;
    background:var(--card);border:1px solid var(--line);
    backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
    transition:transform .25s var(--ease),background .25s,border-color .25s;
    overflow:hidden;
  }
  .card::before{
    content:"";position:absolute;inset:0;opacity:0;transition:opacity .3s;
    background:radial-gradient(420px circle at var(--mx,50%) var(--my,50%),rgba(79,209,197,.14),transparent 42%);
    pointer-events:none;
  }
  .card:hover{transform:translateY(-4px);background:var(--card-hi);border-color:rgba(79,209,197,.32)}
  .card:hover::before{opacity:1}
  .card .ico{
    width:40px;height:40px;border-radius:11px;display:grid;place-items:center;
    background:linear-gradient(145deg,rgba(74,168,255,.22),rgba(79,209,197,.14));
    border:1px solid var(--line);margin-bottom:1rem;font-size:1.15rem;
  }
  .card h3{font-size:1.06rem;font-weight:650;margin-bottom:.4rem;letter-spacing:-.01em}
  .card p{font-size:.94rem;color:var(--ink-dim)}

  /* ---------- stats ---------- */
  .stats{
    display:grid;gap:1px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    background:var(--line);border:1px solid var(--line);border-radius:16px;overflow:hidden;
  }
  .stat{background:var(--stat-bg);padding:1.6rem 1.25rem;text-align:center}
  .stat b{display:block;font-size:clamp(1.8rem,4vw,2.5rem);font-weight:800;letter-spacing:-.03em;
    background:linear-gradient(135deg,var(--teal),var(--azure));
    -webkit-background-clip:text;background-clip:text;color:transparent}
  .stat span{font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-faint)}

  /* ---------- upload ---------- */
  .upload-wrap{max-width:42rem;margin:0 auto}
  .upload-locked{text-align:center;padding:3rem 1rem;color:var(--ink-dim)}
  .upload-locked svg{width:3rem;height:3rem;margin:0 auto .75rem;opacity:.4}
  .upload-locked p{margin-bottom:.5rem}
  .upload-locked .btn{margin-top:1rem}

  .dropzone{
    position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;
    gap:1rem;padding:3rem;border:2px dashed var(--line);border-radius:16px;
    background:var(--card);cursor:pointer;
    backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
    transition:border-color .2s,background .2s;
  }
  .dropzone:hover,.dropzone.drag-over{border-color:var(--teal);background:var(--card-hi)}
  .dropzone-icon{
    width:4rem;height:4rem;border-radius:16px;display:grid;place-items:center;
    background:linear-gradient(145deg,rgba(74,168,255,.22),rgba(79,209,197,.14));
    border:1px solid var(--line);
  }
  .dropzone-icon svg{width:2rem;height:2rem;color:var(--teal)}
  .dropzone-text{text-align:center}
  .dropzone-text p:first-child{font-weight:600;font-size:1.125rem}
  .dropzone-text .browse{color:var(--azure);text-decoration:underline;text-underline-offset:2px}
  .dropzone input[type="file"]{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer}

  .upload-progress{
    display:none;margin-top:1rem;padding:1rem 1.25rem;
    background:var(--card);border:1px solid var(--line);border-radius:12px;
  }
  .upload-progress.active{display:block}
  .progress-info{display:flex;justify-content:space-between;font-size:.875rem;margin-bottom:.5rem}
  .progress-info .filename{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%}
  .progress-info .percent{color:var(--ink-dim)}
  .progress-bar{width:100%;height:.375rem;background:rgba(255,255,255,.08);border-radius:999px;overflow:hidden}
  .progress-bar-fill{height:100%;background:linear-gradient(90deg,var(--azure),var(--teal));
    border-radius:999px;width:0%;transition:width .3s}

  /* ---------- file list ---------- */
  .file-list{margin-top:2rem}
  .file-list h3{font-size:1.125rem;font-weight:600;margin-bottom:1rem}
  .file-list-empty{text-align:center;padding:3rem 1rem;color:var(--ink-faint)}
  .file-list-empty svg{width:3rem;height:3rem;margin:0 auto .75rem;opacity:.3}
  .file-list-empty p:first-of-type{font-weight:500;color:var(--ink-dim)}
  .file-list-empty p:last-of-type{font-size:.875rem;margin-top:.25rem}

  .file-item{
    display:flex;align-items:center;justify-content:space-between;gap:1rem;
    padding:.875rem 1rem;background:var(--card);border:1px solid var(--line);
    border-radius:12px;margin-bottom:.5rem;
    transition:background .2s,border-color .2s;
  }
  .file-item:hover{background:var(--card-hi);border-color:rgba(79,209,197,.32)}
  .file-item-info{display:flex;align-items:center;gap:.75rem;min-width:0}
  .file-item-icon{
    width:2.25rem;height:2.25rem;border-radius:.5rem;flex-shrink:0;
    display:grid;place-items:center;
    background:linear-gradient(145deg,rgba(74,168,255,.22),rgba(79,209,197,.14));
    border:1px solid var(--line);
  }
  .file-item-icon svg{width:1rem;height:1rem;color:var(--teal)}
  .file-item-name{font-weight:500;font-size:.875rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .file-item-size{color:var(--ink-faint);font-size:.75rem}
  .file-item-actions{display:flex;gap:.375rem;flex-shrink:0}
  .file-item-actions button{
    width:2rem;height:2rem;border:none;background:transparent;border-radius:.375rem;
    cursor:pointer;display:grid;place-items:center;color:var(--ink-faint);
    transition:background .15s,color .15s;
  }
  .file-item-actions button:hover{background:var(--card-hi);color:var(--ink)}
  .file-item-actions button.delete:hover{background:rgba(255,107,107,.12);color:var(--danger)}
  .file-item-actions button.rename:hover{background:rgba(255,201,77,.12);color:var(--gold)}
  .file-item-actions button svg{width:1rem;height:1rem}

  /* ---------- modals ---------- */
  .overlay{
    position:fixed;inset:0;z-index:200;background:var(--overlay-bg);
    backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
    display:flex;align-items:center;justify-content:center;
    opacity:0;transition:opacity .2s;padding:1rem;
  }
  .overlay.show{opacity:1}
  .overlay.hidden{display:none}
  .modal-card{
    background:var(--bg-2);border:1px solid var(--line);border-radius:20px;
    padding:2.5rem;width:100%;max-width:24rem;
    box-shadow:0 20px 60px rgba(0,0,0,.5);text-align:center;
  }
  .modal-card .auth-icon{
    width:3.5rem;height:3.5rem;border-radius:16px;margin:0 auto 1.25rem;
    display:grid;place-items:center;
    background:linear-gradient(145deg,rgba(74,168,255,.22),rgba(79,209,197,.14));
    border:1px solid var(--line);
  }
  .modal-card .auth-icon svg{width:1.5rem;height:1.5rem;color:var(--teal)}
  .modal-card h2{font-size:1.5rem;font-weight:700;margin-bottom:.5rem}
  .modal-card h3{font-size:1.125rem;font-weight:700;margin-bottom:1rem;text-align:left}
  .modal-card p{color:var(--ink-dim);font-size:.875rem;margin-bottom:1.5rem}
  .modal-input{
    width:100%;padding:.75rem 1rem;border:1px solid var(--line);border-radius:12px;
    font-size:.875rem;outline:none;background:var(--card);color:var(--ink);
    transition:border-color .15s;
  }
  .modal-input::placeholder{color:var(--ink-faint)}
  .modal-input:focus{border-color:var(--teal)}
  .modal-input.error{border-color:var(--danger);animation:shake .4s}
  @keyframes shake{
    0%,100%{transform:translateX(0)}
    25%{transform:translateX(-6px)}
    75%{transform:translateX(6px)}
  }
  .auth-error{color:var(--danger);font-size:.8rem;margin-top:.5rem;display:none;text-align:left}
  .auth-error.show{display:block}
  .auth-submit{width:100%;margin-top:1rem;justify-content:center}
  .rename-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:1rem}

  /* ---------- lightbox ---------- */
  .lb-close{
    position:absolute;top:1rem;right:1rem;width:2.5rem;height:2.5rem;z-index:2;
    border-radius:50%;border:1px solid var(--line);background:var(--card);
    color:var(--ink);font-size:1.05rem;cursor:pointer;
    transition:background .2s;
  }
  .lb-close:hover{background:var(--card-hi)}
  .lb-body{display:grid;place-items:center;max-width:min(94vw,1100px);max-height:88vh}
  .lb-body video,.lb-body img{
    max-width:min(94vw,1100px);max-height:88vh;border-radius:12px;
    background:#000;box-shadow:0 20px 80px rgba(0,0,0,.55);
  }
  .lb-audio{
    background:var(--bg-2);border:1px solid var(--line);border-radius:16px;
    padding:2rem;width:min(90vw,28rem);text-align:center;
  }
  .lb-audio p{font-weight:600;margin-bottom:1rem;word-break:break-all;color:var(--ink)}
  .lb-audio audio{width:100%}

  /* ---------- toast ---------- */
  .toast{
    position:fixed;bottom:1.5rem;right:1.5rem;z-index:300;
    padding:.875rem 1.25rem;border-radius:12px;font-size:.875rem;font-weight:500;
    color:var(--ink);background:var(--bg-2);border:1px solid var(--line);
    box-shadow:0 8px 30px rgba(0,0,0,.4);
    transform:translateY(120%);opacity:0;transition:transform .3s var(--ease),opacity .3s;
  }
  .toast.show{transform:translateY(0);opacity:1}
  .toast.success{border-color:rgba(61,220,151,.4);color:var(--success)}
  .toast.error{border-color:rgba(255,107,107,.4);color:var(--danger)}

  footer{padding-block:2.5rem 3rem;border-top:1px solid var(--line);margin-top:auto}
  .foot{display:flex;flex-wrap:wrap;gap:.75rem 1.5rem;justify-content:space-between;
    font-size:.86rem;color:var(--ink-faint)}

  /* ---------- reveal ---------- */
  .rise{opacity:0;transform:translateY(22px);transition:opacity .7s var(--ease),transform .7s var(--ease)}
  .rise.in{opacity:1;transform:none}

  @media (prefers-reduced-motion:reduce){
    *{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}
    html{scroll-behavior:auto}
    .rise{opacity:1;transform:none}
  }
CSS;
    }

    private function js(): string
    {
        return <<<'JS'
/* ─── ambience: starfield, reveals, glow, count-up ─────── */
(function(){
  "use strict";
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* year */
  document.getElementById("yr").textContent = new Date().getFullYear();

  /* ---- starfield / constellation ---- */
  var cv = document.getElementById("stars"), ctx = cv.getContext("2d");
  var pts = [], w = 0, h = 0, dpr = Math.min(window.devicePixelRatio || 1, 2), raf = 0;
  var pointer = {x:-9999, y:-9999};

  /* star colours per theme */
  var THEMES = {
    dark:  { dot:"rgba(180,215,235,.55)", line:"rgba(120,190,220,", link:"rgba(79,209,197," },
    light: { dot:"rgba(30,70,100,.45)",   line:"rgba(50,100,140,",  link:"rgba(11,120,110," }
  };
  var P = THEMES[document.documentElement.getAttribute("data-theme")] || THEMES.dark;

  function size(){
    w = cv.clientWidth; h = cv.clientHeight;
    cv.width = Math.floor(w * dpr); cv.height = Math.floor(h * dpr);
    ctx.setTransform(dpr,0,0,dpr,0,0);
    var target = Math.round(Math.min(110, Math.max(28, (w*h)/16000)));
    pts = [];
    for (var i=0;i<target;i++){
      pts.push({
        x: Math.random()*w, y: Math.random()*h,
        vx: (Math.random()-.5)*.16, vy: (Math.random()-.5)*.16,
        r: Math.random()*1.5 + .5
      });
    }
  }

  function frame(){
    ctx.clearRect(0,0,w,h);
    for (var i=0;i<pts.length;i++){
      var p = pts[i];
      p.x += p.vx; p.y += p.vy;
      if (p.x < -20) p.x = w+20; if (p.x > w+20) p.x = -20;
      if (p.y < -20) p.y = h+20; if (p.y > h+20) p.y = -20;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
      ctx.fillStyle = P.dot;
      ctx.fill();

      for (var j=i+1;j<pts.length;j++){
        var q = pts[j], dx = p.x-q.x, dy = p.y-q.y, d2 = dx*dx + dy*dy;
        if (d2 < 15000){
          ctx.beginPath();
          ctx.moveTo(p.x,p.y); ctx.lineTo(q.x,q.y);
          ctx.strokeStyle = P.line + (0.16 * (1 - d2/15000)).toFixed(3) + ")";
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      }

      var mdx = p.x - pointer.x, mdy = p.y - pointer.y, md2 = mdx*mdx + mdy*mdy;
      if (md2 < 26000){
        ctx.beginPath();
        ctx.moveTo(p.x,p.y); ctx.lineTo(pointer.x,pointer.y);
        ctx.strokeStyle = P.link + (0.30 * (1 - md2/26000)).toFixed(3) + ")";
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }
    raf = requestAnimationFrame(frame);
  }

  function start(){ if(!raf) frame(); }
  function stop(){ if(raf){ cancelAnimationFrame(raf); raf = 0; } }

  size();
  if (reduced){ frame(); stop(); } else { start(); }

  var rt;
  window.addEventListener("resize", function(){
    clearTimeout(rt);
    rt = setTimeout(function(){ size(); if(reduced){ ctx.clearRect(0,0,w,h); frame(); stop(); } }, 160);
  });

  window.addEventListener("pointermove", function(e){ pointer.x = e.clientX; pointer.y = e.clientY; }, {passive:true});
  window.addEventListener("pointerleave", function(){ pointer.x = pointer.y = -9999; });

  /* pause when tab hidden — don't burn cycles in a background tab */
  document.addEventListener("visibilitychange", function(){
    if (document.hidden) stop(); else if (!reduced) start();
  });

  /* ---- theme toggle ---- */
  var themeBtn = document.getElementById("themeBtn");
  function themeLabel(t){ themeBtn.textContent = t === "light" ? "☀️" : "🌙"; }
  themeLabel(document.documentElement.getAttribute("data-theme"));
  themeBtn.addEventListener("click", function(){
    var t = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem("bmg-theme", t);
    P = THEMES[t] || THEMES.dark;
    themeLabel(t);
    if (reduced){ frame(); stop(); }
  });

  /* ---- reveal on scroll ---- */
  var rises = document.querySelectorAll(".rise");
  if ("IntersectionObserver" in window && !reduced){
    var io = new IntersectionObserver(function(entries){
      entries.forEach(function(en, i){
        if (en.isIntersecting){
          var el = en.target;
          setTimeout(function(){ el.classList.add("in"); }, i * 70);
          io.unobserve(el);
        }
      });
    }, {rootMargin:"0px 0px -8% 0px", threshold:.12});
    rises.forEach(function(el){ io.observe(el); });
  } else {
    rises.forEach(function(el){ el.classList.add("in"); });
  }

  /* ---- cursor glow on cards ---- */
  document.querySelectorAll(".card").forEach(function(card){
    card.addEventListener("pointermove", function(e){
      var r = card.getBoundingClientRect();
      card.style.setProperty("--mx", (e.clientX - r.left) + "px");
      card.style.setProperty("--my", (e.clientY - r.top) + "px");
    }, {passive:true});
  });

  /* ---- count-up stats ---- */
  var nums = document.querySelectorAll("[data-count]");
  function countUp(el){
    var end = parseFloat(el.getAttribute("data-count"));
    var suffix = el.getAttribute("data-suffix") || "";
    if (reduced || end === 0){ el.textContent = end + suffix; return; }
    var dur = 1100, t0 = performance.now();
    (function tick(now){
      var p = Math.min(1, (now - t0)/dur);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(end * eased) + suffix;
      if (p < 1) requestAnimationFrame(tick);
    })(t0);
  }
  if ("IntersectionObserver" in window){
    var io2 = new IntersectionObserver(function(entries){
      entries.forEach(function(en){
        if (en.isIntersecting){ countUp(en.target); io2.unobserve(en.target); }
      });
    }, {threshold:.5});
    nums.forEach(function(el){ io2.observe(el); });
  } else {
    nums.forEach(countUp);
  }
})();

/* ─── app: auth, upload, file management ───────────────── */
(function() {
    const API = ''; // same file — requests go to ?action=…

    // ── DOM refs ─────────────────────────────────────────
    const authOverlay = document.getElementById('authOverlay');
    const authForm = document.getElementById('authForm');
    const authInput = document.getElementById('authInput');
    const authError = document.getElementById('authError');
    const authBadge = document.getElementById('authBadge');
    const lockBtn = document.getElementById('lockBtn');
    const lockLabel = document.getElementById('lockLabel');
    const uploadLocked = document.getElementById('uploadLocked');
    const uploadUnlocked = document.getElementById('uploadUnlocked');
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const fileListSection = document.getElementById('fileListSection');
    const fileListContent = document.getElementById('fileListContent');
    const emptyState = document.getElementById('emptyState');
    const uploadProgress = document.getElementById('uploadProgress');
    const progressFilename = document.getElementById('progressFilename');
    const progressPercent = document.getElementById('progressPercent');
    const progressFill = document.getElementById('progressFill');
    const toastEl = document.getElementById('toast');
    const renameOverlay = document.getElementById('renameOverlay');
    const renameInput = document.getElementById('renameInput');
    const renameOld = document.getElementById('renameOld');

    let role = null; // null | 'guest' | 'admin'
    let files = [];

    // ── Helpers ──────────────────────────────────────────

    function showToast(message, type = '') {
        toastEl.textContent = message;
        toastEl.className = 'toast ' + type;
        requestAnimationFrame(() => toastEl.classList.add('show'));
        setTimeout(() => toastEl.classList.remove('show'), 3000);
    }

    function esc(s) {
        return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    }

    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    async function api(action, opts = {}) {
        const url = opts.params
            ? `${API}?action=${action}&${new URLSearchParams(opts.params)}`
            : `${API}?action=${action}`;
        const res = await fetch(url, {
            method: opts.method || 'GET',
            body: opts.body || undefined,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Request failed');
        return data;
    }

    // ── Auth ─────────────────────────────────────────────

    function updateAuthUI() {
        if (role) {
            uploadLocked.style.display = 'none';
            uploadUnlocked.style.display = '';
            lockLabel.textContent = 'Lock';
            if (role === 'admin') {
                authBadge.textContent = 'Admin';
                authBadge.className = 'auth-badge-text admin';
                fileListSection.style.display = '';
            } else {
                authBadge.textContent = 'Access granted';
                authBadge.className = 'auth-badge-text granted';
                fileListSection.style.display = 'none';
            }
        } else {
            uploadLocked.style.display = '';
            uploadUnlocked.style.display = 'none';
            fileListSection.style.display = 'none';
            authBadge.textContent = '';
            authBadge.className = 'auth-badge-text';
            lockLabel.textContent = 'Unlock';
        }
    }

    window.showAuthModal = function() {
        authOverlay.classList.remove('hidden');
        requestAnimationFrame(() => authOverlay.classList.add('show'));
        authInput.value = '';
        authError.classList.remove('show');
        authInput.classList.remove('error');
        setTimeout(() => authInput.focus(), 100);
    };

    function hideAuthModal() {
        authOverlay.classList.remove('show');
        setTimeout(() => authOverlay.classList.add('hidden'), 200);
    }

    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const body = new FormData();
            body.append('passphrase', authInput.value);
            const data = await api('auth', { method: 'POST', body });
            role = data.role;
            hideAuthModal();
            updateAuthUI();
            showToast(role === 'admin' ? 'Admin access granted' : 'Access granted', 'success');
            if (role === 'admin') loadFiles();
        } catch {
            authInput.classList.add('error');
            authError.classList.add('show');
            setTimeout(() => authInput.classList.remove('error'), 400);
        }
    });

    authOverlay.addEventListener('click', (e) => {
        if (e.target === authOverlay) hideAuthModal();
    });

    lockBtn.addEventListener('click', async () => {
        if (role) {
            await api('logout', { method: 'POST', body: new FormData() }).catch(() => {});
            role = null;
            files = [];
            updateAuthUI();
            renderFiles();
            showToast('Session locked', '');
        } else {
            showAuthModal();
        }
    });

    // ── File list ────────────────────────────────────────

    async function loadFiles() {
        try {
            const data = await api('list');
            files = data.files || [];
            renderFiles();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }

    function renderFiles() {
        fileListContent.querySelectorAll('.file-item').forEach(el => el.remove());

        if (files.length === 0) {
            emptyState.style.display = '';
            return;
        }
        emptyState.style.display = 'none';

        files.forEach((file) => {
            const item = document.createElement('div');
            item.className = 'file-item';

            // Admin gets rename + delete; guests get download + copy link
            const adminBtns = role === 'admin' ? `
                <button title="Rename" class="rename" data-name="${esc(file.name)}">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/></svg>
                </button>
                <button title="Delete" class="delete" data-name="${esc(file.name)}">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                </button>
            ` : '';

            const previewBtn = /^(video|audio|image)\//.test(file.type) ? `
                <button title="Preview" class="preview" data-name="${esc(file.name)}">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>
                </button>
            ` : '';

            item.innerHTML = `
                <div class="file-item-info">
                    <div class="file-item-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/></svg>
                    </div>
                    <div>
                        <div class="file-item-name">${esc(file.name)}</div>
                        <div class="file-item-size">${formatSize(file.size)}</div>
                    </div>
                </div>
                <div class="file-item-actions">
                    ${previewBtn}
                    <button title="Download" class="download" data-name="${esc(file.name)}">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"/><path d="m7 10 5 5 5-5"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/></svg>
                    </button>
                    <button title="Copy link" class="copy" data-name="${esc(file.name)}">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                    </button>
                    ${adminBtns}
                </div>
            `;
            fileListContent.appendChild(item);
        });

        // Event listeners
        fileListContent.querySelectorAll('.preview').forEach(btn => {
            btn.addEventListener('click', () => {
                const f = files.find(x => x.name === btn.dataset.name);
                if (f) openLightbox(f);
            });
        });

        fileListContent.querySelectorAll('.download').forEach(btn => {
            btn.addEventListener('click', () => {
                const a = document.createElement('a');
                a.href = `?action=download&file=${encodeURIComponent(btn.dataset.name)}`;
                a.download = btn.dataset.name;
                a.click();
            });
        });

        fileListContent.querySelectorAll('.copy').forEach(btn => {
            btn.addEventListener('click', () => {
                const link = `?action=download&file=${encodeURIComponent(btn.dataset.name)}`;
                const fullLink = new URL(link, window.location.href).href;
                navigator.clipboard.writeText(fullLink).then(
                    () => showToast('Link copied', 'success'),
                    () => showToast('Failed to copy', 'error')
                );
            });
        });

        fileListContent.querySelectorAll('.rename').forEach(btn => {
            btn.addEventListener('click', () => showRenameModal(btn.dataset.name));
        });

        fileListContent.querySelectorAll('.delete').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!confirm(`Delete "${btn.dataset.name}"?`)) return;
                try {
                    const body = new FormData();
                    body.append('file', btn.dataset.name);
                    await api('delete', { method: 'POST', body });
                    showToast('Deleted', 'success');
                    loadFiles();
                } catch (err) {
                    showToast(err.message, 'error');
                }
            });
        });
    }

    // ── Upload ───────────────────────────────────────────

    function handleFiles(fileList) {
        const formData = new FormData();
        Array.from(fileList).forEach(f => formData.append('files[]', f));

        const xhr = new XMLHttpRequest();
        uploadProgress.classList.add('active');
        progressFilename.textContent = fileList.length === 1
            ? fileList[0].name
            : `${fileList.length} files`;
        progressPercent.textContent = '0%';
        progressFill.style.width = '0%';

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const pct = Math.round((e.loaded / e.total) * 100);
                progressPercent.textContent = pct + '%';
                progressFill.style.width = pct + '%';
            }
        });

        xhr.addEventListener('load', () => {
            progressPercent.textContent = '100%';
            progressFill.style.width = '100%';
            try {
                const data = JSON.parse(xhr.responseText);
                if (xhr.status >= 400) {
                    showToast(data.error || 'Upload failed', 'error');
                } else {
                    const count = data.uploaded?.length || 0;
                    showToast(`Thank you! ${count} file${count !== 1 ? 's' : ''} uploaded successfully.`, 'success');
                    loadFiles();
                }
            } catch {
                showToast('Upload failed', 'error');
            }
            setTimeout(() => uploadProgress.classList.remove('active'), 1000);
        });

        xhr.addEventListener('error', () => {
            showToast('Upload failed', 'error');
            uploadProgress.classList.remove('active');
        });

        xhr.open('POST', '?action=upload');
        xhr.send(formData);
    }

    ['dragenter', 'dragover'].forEach(evt => {
        dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add('drag-over'); });
    });
    ['dragleave', 'drop'].forEach(evt => {
        dropzone.addEventListener(evt, () => dropzone.classList.remove('drag-over'));
    });
    dropzone.addEventListener('drop', (e) => { e.preventDefault(); handleFiles(e.dataTransfer.files); });
    fileInput.addEventListener('change', (e) => { handleFiles(e.target.files); e.target.value = ''; });

    // ── Lightbox ─────────────────────────────────────────

    const lightbox = document.getElementById('lightbox');
    const lightboxBody = document.getElementById('lightboxBody');

    function openLightbox(file) {
        const src = `?action=stream&file=${encodeURIComponent(file.name)}`;
        lightboxBody.innerHTML = file.type.startsWith('video/')
            ? `<video controls autoplay playsinline src="${src}"></video>`
            : file.type.startsWith('audio/')
                ? `<div class="lb-audio"><p>${esc(file.name)}</p><audio controls autoplay src="${src}"></audio></div>`
                : `<img src="${src}" alt="${esc(file.name)}">`;
        lightbox.classList.remove('hidden');
        requestAnimationFrame(() => lightbox.classList.add('show'));
    }

    function closeLightbox() {
        lightbox.classList.remove('show');
        setTimeout(() => {
            lightbox.classList.add('hidden');
            lightboxBody.innerHTML = ''; // removes the element = stops playback
        }, 200);
    }

    document.getElementById('lightboxClose').addEventListener('click', closeLightbox);
    lightbox.addEventListener('click', (e) => { if (e.target === lightbox) closeLightbox(); });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !lightbox.classList.contains('hidden')) closeLightbox();
    });

    // ── Rename modal ─────────────────────────────────────

    function showRenameModal(name) {
        renameOld.value = name;
        renameInput.value = name;
        renameOverlay.classList.remove('hidden');
        requestAnimationFrame(() => renameOverlay.classList.add('show'));
        setTimeout(() => { renameInput.focus(); renameInput.select(); }, 100);
    }

    function hideRenameModal() {
        renameOverlay.classList.remove('show');
        setTimeout(() => renameOverlay.classList.add('hidden'), 200);
    }

    document.getElementById('renameCancel').addEventListener('click', hideRenameModal);
    renameOverlay.addEventListener('click', (e) => { if (e.target === renameOverlay) hideRenameModal(); });

    document.getElementById('renameSave').addEventListener('click', async () => {
        const oldName = renameOld.value;
        const newName = renameInput.value.trim();
        if (!newName || newName === oldName) { hideRenameModal(); return; }
        try {
            const body = new FormData();
            body.append('old', oldName);
            body.append('new', newName);
            await api('rename', { method: 'POST', body });
            hideRenameModal();
            showToast('Renamed', 'success');
            loadFiles();
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    renameInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') document.getElementById('renameSave').click();
        if (e.key === 'Escape') hideRenameModal();
    });

    // ── Hero button ──────────────────────────────────────

    document.getElementById('heroUploadBtn').addEventListener('click', (e) => {
        if (!role) { e.preventDefault(); showAuthModal(); }
    });

    // ── Smooth scroll ────────────────────────────────────

    document.querySelectorAll('a[href^="#"]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = document.querySelector(link.getAttribute('href'));
            if (target) target.scrollIntoView({ behavior: 'smooth' });
        });
    });

    // ── Init: check session ──────────────────────────────

    (async () => {
        try {
            const data = await api('status');
            if (data.role) {
                role = data.role;
                updateAuthUI();
                if (role === 'admin') loadFiles();
            } else {
                updateAuthUI();
            }
        } catch {
            updateAuthUI();
        }
    })();
})();
JS;
    }
}

// ── Entry ────────────────────────────────────────────────
$cfg = new Cfg();

match ($_GET['action'] ?? $_POST['action'] ?? '') {
    ''      => print new Page($cfg),
    default => new Api($cfg)->dispatch($_GET['action'] ?? $_POST['action']),
};
