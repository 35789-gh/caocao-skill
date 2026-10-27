# snapdual.ps1 - dual-window evidence capture in one shot (RF-IMG-15 form, RF-IMG-18 procedure).
# Browser maximized as base + cmd terminal as side window pressed to an edge; every other window
# minimized; optional cursor park so the native title tooltip (full text) renders; region capture
# of the work area (taskbar excluded); then un-top the cmd window and restore ZCode.
#
# ASCII-only on purpose: PowerShell 5.1 reads a BOM-less ps1 as ANSI, and multi-byte CJK comments
# there swallow newlines, producing fake ParserError ("empty pipe element" / unexpected token).
# Keep ps1 tools UTF-8 WITH BOM or pure ASCII (vis-tools README, 2026-10-15 r14 lesson).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File snapdual.ps1 -Out <png> `
#     -CmdTitle <exact console title> [-CmdX 556 -CmdY 400 -CmdW 980 -CmdH 416] `
#     [-CursorX 330 -CursorY 405] [-CapW 1536 -CapH 816] [-HoverMs 1600]
#   CursorX/Y < 0 skips the hover step. Gate the shot immediately (RF-GATE-01):
#   py -3 vision_gate.py --image <png> --kind dual --claim "<key values>"
# Any third window in frame is a one-vote veto (RF-IMG-15); fix the desktop, not the caption.
#
# Constraints (2026-10-15 tool-constraint test batch, both gate-confirmed):
#  - The console viewport is NOT managed by this tool: the transcript must FIT the side window
#    (RF-CMD-08: set mode con BEFORE running the commands). If the tail (final responses /
#    read-back) is cut by the window bottom edge, vision_gate --kind dual WILL fail - re-shoot
#    with a taller window or a shorter transcript. Defaults fit a ~22-line transcript.
#  - Chrome is force-activated before the hover: the native title tooltip only renders while
#    Chrome is the ACTIVE window (a no-activate layout alone is not enough).
#  - A gate fail can be EVIDENCE-level, not form-level: if the transcript itself shows a
#    failed/pending read-back (e.g. an in-script read that lost a race with async execution),
#    the gate is right to refuse - fix the RUN (poll-retry read-back, RF-PKG-07), not the
#    layout. This tool captures the console honestly; judge the frame before re-shooting.
param(
  [string]$Out = 'E:\Temp\dual.png',
  [string]$CmdTitle = 'CMDPHOTO',
  [int]$CmdX = 556, [int]$CmdY = 340, [int]$CmdW = 980, [int]$CmdH = 476,
  [int]$CursorX = -1, [int]$CursorY = -1,
  [int]$CapW = 1536, [int]$CapH = 816,
  [int]$HoverMs = 1600
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class SD {
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
'@

$chrome = Get-Process chrome -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
$cmdP = Get-Process cmd -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle.Trim() -eq $CmdTitle } | Select-Object -First 1
if (-not $chrome) { Write-Output 'ERR no chrome window'; exit 1 }
if (-not $cmdP) { Write-Output ('ERR no cmd window with title=' + $CmdTitle); exit 2 }
$zc = Get-Process ZCode -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1

$TOPMOST = [IntPtr](-1); $NOTOPMOST = [IntPtr](-2); $NOACT = 0x0010

# 1) cmd side window into place: TOPMOST but do NOT steal focus (browser tooltip survives)
[SD]::ShowWindow($cmdP.MainWindowHandle, 9) | Out-Null
[SD]::SetWindowPos($cmdP.MainWindowHandle, $TOPMOST, $CmdX, $CmdY, $CmdW, $CmdH, $NOACT) | Out-Null
Start-Sleep -Milliseconds 400

# 2) Chrome maximized as the base layer (no focus steal)
[SD]::ShowWindow($chrome.MainWindowHandle, 3) | Out-Null
[SD]::SetWindowPos($chrome.MainWindowHandle, [IntPtr]::Zero, -7, -7, $CapW + 14, $CapH + 21, $NOACT) | Out-Null
Start-Sleep -Milliseconds 600

# 3) minimize every other visible window (shell hosts whitelisted)
$others = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.Id -ne $chrome.Id -and $_.Id -ne $cmdP.Id -and $_.ProcessName -notmatch '^(explorer|ApplicationFrameHost|SearchHost|TextInputHost|ShellExperienceHost|StartMenuExperienceHost)$' }
foreach ($p in $others) { [SD]::ShowWindow($p.MainWindowHandle, 6) | Out-Null }
Start-Sleep -Milliseconds 500

# 3.5) force Chrome active (ALT-tap unlocks SetForegroundWindow): the native title tooltip
#      only renders while Chrome is the active window; TOPMOST cmd stays on top regardless.
[System.Windows.Forms.SendKeys]::SendWait('%')
[SD]::SetForegroundWindow($chrome.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 400

# 4) park the cursor for the native title tooltip (move away first so hover re-triggers)
if ($CursorX -ge 0 -and $CursorY -ge 0) {
  [SD]::SetCursorPos([Math]::Max(0, $CapW - 300), [Math]::Max(0, $CapH - 150)) | Out-Null
  Start-Sleep -Milliseconds 300
  [SD]::SetCursorPos($CursorX, $CursorY) | Out-Null
  Start-Sleep -Milliseconds $HoverMs
}

# 5) region capture (work area; taskbar excluded by CapH)
#    r16 fix: capture used to run bare under ErrorActionPreference=Stop - any exception
#    there (CapW 0, locked screen, GDI failure) aborted the script BEFORE step 6, leaving
#    the cmd window TOPMOST and every other window minimized with no artifact. Capture is
#    now wrapped in try/catch (rethrow after the note) and the restore block moved into
#    finally so it runs on BOTH the success and the failure path.
$bmp = $null
try {
  $bmp = New-Object System.Drawing.Bitmap($CapW, $CapH)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
  $g.Dispose()
  $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
  Write-Output ('saved ' + $Out + ' ' + $CapW + 'x' + $CapH)
} catch {
  Write-Output ('ERR capture failed: ' + $_.Exception.Message)
  throw
} finally {
  if ($bmp) { $bmp.Dispose() }
  # 6) restore: un-top the cmd window, bring ZCode back (runs even when capture threw)
  [SD]::SetWindowPos($cmdP.MainWindowHandle, $NOTOPMOST, $CmdX, $CmdY, $CmdW, $CmdH, $NOACT) | Out-Null
  if ($zc) { [SD]::ShowWindow($zc.MainWindowHandle, 9) | Out-Null }
}
Write-Output 'DONE'
