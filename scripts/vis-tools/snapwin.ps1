# 窗口截屏 v5（㊴/㊵ + 半屏分家）：按 title 找 cmd 窗口 → 摆到指定槽位 → 客户区截屏
# 槽位：-Slot left（A 批，屏幕左半）/ right（B 批，屏幕右半）/ full（最大化铺满，默认）
#   left/right 模式两会话可同时拍图互不遮挡——免锁；full 模式会铺满全屏，须持 shotlock
param([string]$Out, [string]$Title = 'CMDPHOTO', [string]$Slot = 'full')
# 2026-10-16 r16：$Out 前置校验——旧版空 $Out / 父目录不存在时窗口照摆照置顶，
# 最后 Save('') 才炸，遗留已摆位/TOPMOST 窗口。现在动窗口之前就拒绝。
if (-not $Out) { throw 'Out path required (use -Out <png>)' }
$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { throw ("Out dir does not exist: " + $outDir) }
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WR6 {
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
  public struct RECT { public int L, T, R, B; }
  public struct POINT { public int X, Y; }
}
"@
$cands = @(Get-Process cmd -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle.Trim() -eq $Title })
# 批六十一⑩（r38 B-5）：同名窗口多开时任取 First=截错窗当证据——唯一性 throw（谁开谁关，
# 要么换 title 要么先关多余窗；RF-SCREEN-04 分家靠不同 title，重名本身就是违规态）
if ($cands.Count -gt 1) { throw "window title='$Title' matches $($cands.Count) windows - ambiguous, close extras or use unique -Title" }
$cand = $cands | Select-Object -First 1
if (-not $cand) { throw "window title='$Title' not found" }
$h = $cand.MainWindowHandle
[WR6]::ShowWindow($h, 9) | Out-Null   # SW_RESTORE（从最大化/最小化回到正常，才能自由摆位）
if ($Slot -eq 'full') {
  [WR6]::ShowWindow($h, 3) | Out-Null # SW_MAXIMIZE：铺满整屏（须持锁）
} elseif ($Slot -eq 'left') {
  [WR6]::SetWindowPos($h, [IntPtr]::new(-1), -6, -31, 770, 880, 0x0040) | Out-Null  # 左半屏，TOPMOST
} elseif ($Slot -eq 'right') {
  [WR6]::SetWindowPos($h, [IntPtr]::new(-1), 772, -31, 770, 880, 0x0040) | Out-Null # 右半屏，TOPMOST
} else { throw "Slot must be left|right|full" }
[WR6]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 500
$r = New-Object WR6+RECT
[WR6]::GetClientRect($h, [ref]$r) | Out-Null
$pt = New-Object WR6+POINT
$pt.X = 0; $pt.Y = 0
[WR6]::ClientToScreen($h, [ref]$pt) | Out-Null
$pad = 2
$x = $pt.X + $pad; $y = $pt.Y + $pad
$w = ($r.R - $r.L) - 2*$pad; $ht = ($r.B - $r.T) - 2*$pad
if ($w -lt 300 -or $ht -lt 300) {
  # r16：throw 前先还原——此时窗口已被摆位/TOPMOST，裸 throw 会遗留现场
  [WR6]::SetWindowPos($h, [IntPtr]::new(-2), 0, 0, 0, 0, 0x0013) | Out-Null  # NOTOPMOST|NOSIZE|NOMOVE|NOACTIVATE
  throw "bad client rect ${w}x${ht}"
}
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($x, $y, 0, 0, $bmp.Size)
$g.Dispose()
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "saved $Out ($w x $ht slot=$Slot)"
