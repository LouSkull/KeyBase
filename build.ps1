$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = 'KeyBase Builder -- Build'

# ── helpers ───────────────────────────────────────────────────────────────────
function cw($text, $color) { Write-Host $text -ForegroundColor $color -NoNewline }
function cl($text = '', $color = 'White') { Write-Host $text -ForegroundColor $color }

function fmt-time([int]$s) {
    if ($s -ge 60) { "{0}m {1}s" -f [int]($s/60), ($s % 60) } else { "${s}s" }
}

function fmt-size([string]$path) {
    if (-not (Test-Path $path)) { return '?' }
    $b = (Get-Item $path).Length
    if ($b -ge 1MB) { "{0:F1} MB" -f ($b / 1MB) }
    elseif ($b -ge 1KB) { "{0:F0} KB" -f ($b / 1KB) }
    else { "$b B" }
}

function box-line([string]$msg, [string]$fill = '-') {
    cl ("  " + $fill * 58) DarkGray
}

function run-build([string]$label, [string[]]$args_list, [string]$src, [string]$dst) {
    cl ""
    cw "  [ " DarkCyan; cw $label Cyan; cl " ]" DarkCyan
    box-line ''
    cl ""

    $t0 = [int](Get-Date).TimeOfDay.TotalSeconds

    # run cargo/cross — output flows directly to console
    & $args_list[0] $args_list[1..($args_list.Length-1)]
    $ec = $LASTEXITCODE

    $elapsed = fmt-time ([int](Get-Date).TimeOfDay.TotalSeconds - $t0)

    cl ""
    box-line ''

    if ($ec -ne 0) {
        cw "  [FAILED] " Red; cl "$label failed in $elapsed" Red
        cl ""
        return @{ ok = $false; time = $elapsed; size = '?' }
    }

    Copy-Item -Force $src $dst
    $sz = fmt-size $dst

    cw "  [  OK  ] " Green
    cw "$label" White
    cw "  in $elapsed" Green
    cw "   $(Split-Path $dst -Leaf)" DarkGray
    cw "  [$sz]" DarkGray
    cl ""
    cl ""

    return @{ ok = $true; time = $elapsed; size = $sz }
}

# ── main ──────────────────────────────────────────────────────────────────────
$root  = Split-Path $MyInvocation.MyCommand.Path
$dist  = Join-Path $root 'dist'
$bdir  = Join-Path $root 'Builder'
if (-not (Test-Path $dist)) { New-Item -ItemType Directory $dist | Out-Null }

cl ""
cl "  +------------------------------------------+" Cyan
cl "  |   KeyBase Builder  --  Build All         |" Cyan
cl "  +------------------------------------------+" Cyan
cl ""
cl "  Targets : Windows (GUI)  +  Linux (TUI via cross)" DarkGray
cl "  Output  : dist\" DarkGray
cl ""

$T_START = [int](Get-Date).TimeOfDay.TotalSeconds

# ── Windows ───────────────────────────────────────────────────────────────────
Push-Location $bdir
$win = run-build `
    "Windows  x86_64-pc-windows-msvc  GUI" `
    @('cargo','build','--release') `
    (Join-Path $bdir 'target\release\keybase-builder.exe') `
    (Join-Path $dist 'keybase-builder-windows.exe')
Pop-Location

# ── Linux ─────────────────────────────────────────────────────────────────────
Push-Location $bdir
$lin = run-build `
    "Linux  x86_64-unknown-linux-musl  TUI" `
    @('cross','build','--release','--target','x86_64-unknown-linux-musl') `
    (Join-Path $bdir 'target\x86_64-unknown-linux-musl\release\keybase-builder') `
    (Join-Path $dist 'keybase-builder-linux')
Pop-Location

# ── summary ───────────────────────────────────────────────────────────────────
$total = fmt-time ([int](Get-Date).TimeOfDay.TotalSeconds - $T_START)
$all_ok = $win.ok -and $lin.ok

cl ""
cl "  +----------------------------------------------------------+" Cyan
cl "  |                    Build  Summary                        |" Cyan
cl "  +----------------------------------------------------------+" Cyan

# Windows row
cw "  |  " Cyan
if ($win.ok) {
    cw " OK " Green; cw "  Windows  GUI   " White
    cw $win.time Green; cw "   keybase-builder-windows.exe   " DarkGray
    cl ("[" + $win.size + "]") DarkGray
} else {
    cw " XX " Red; cw "  Windows  GUI   " White
    cl ("FAILED (" + $win.time + ")") Red
}

# Linux row
cw "  |  " Cyan
if ($lin.ok) {
    cw " OK " Green; cw "  Linux   TUI    " White
    cw $lin.time Green; cw "   keybase-builder-linux          " DarkGray
    cl ("[" + $lin.size + "]") DarkGray
} else {
    cw " XX " Red; cw "  Linux   TUI    " White
    cl ("FAILED (" + $lin.time + ")") Red
}

cl "  +----------------------------------------------------------+" Cyan
cw "  |  Total time:  " Cyan; cl $total White
cl "  +----------------------------------------------------------+" Cyan
cl ""

if ($all_ok) {
    cl "  All targets built successfully.  Binaries in dist\" Green
} else {
    cl "  Build failed -- check output above." Red
}
cl ""

Read-Host "  Press Enter to exit" | Out-Null
exit $(if ($all_ok) { 0 } else { 1 })
