# Chrome 窗口区域截屏（㊵配套）：弹窗阻塞 CDP 时用屏幕截屏
param([string]$Out)
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WC {
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  public struct RECT { public int L, T, R, B; }
  public struct POINT { public int X, Y; }
}
"@
$cands = @(Get-Process chrome -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 })
# 批六十一⑩（r38 B-5）：多 Chrome 窗任取 First=截错窗——唯一性 throw（多开时先关多余实例，
# CDP 9222 会话本应单窗；同名歧义就是废片前兆）
if ($cands.Count -gt 1) { throw "$($cands.Count) chrome windows - ambiguous, close extras before evidence shot" }
$cand = $cands | Select-Object -First 1
if (-not $cand) { throw 'chrome window not found' }
$h = $cand.MainWindowHandle
[WC]::ShowWindow($h, 9) | Out-Null
[WC]::ShowWindow($h, 3) | Out-Null
[WC]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 800
$r = New-Object WC+RECT
[WC]::GetClientRect($h, [ref]$r) | Out-Null
$pt = New-Object WC+POINT
$pt.X = 0; $pt.Y = 0
[WC]::ClientToScreen($h, [ref]$pt) | Out-Null
$pad = 2
$x = $pt.X + $pad; $y = $pt.Y + $pad
$w = ($r.R - $r.L) - 2*$pad; $ht = ($r.B - $r.T) - 2*$pad
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($x, $y, 0, 0, $bmp.Size)
$g.Dispose()
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output "saved $Out ($w x $ht chrome-client)"
