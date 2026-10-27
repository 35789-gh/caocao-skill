param([string]$File, [string]$Title = 'CMDPHOTO', [string]$Owner = $env:SHOTLOCK_OWNER)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinC {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
}
"@
$text = [System.IO.File]::ReadAllText($File)

# ---- shotlock 闸（2026-10-16 r16）：终端/屏幕是双会话共抢资源。锁在别人名下时
# 拒绝发送（exit 3）；无锁 = 单会话老用法，warning 后继续。-Owner 默认取环境变量
# SHOTLOCK_OWNER，与 shotlock.py 的 E:\Temp\vis-lock\lock.json 同一锁。
$lockPath = 'E:\Temp\vis-lock\lock.json'
if (Test-Path -LiteralPath $lockPath) {
  $lockOwner = $null
  try { $lockOwner = (Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json).owner } catch { $lockOwner = '<unreadable>' }
  $who = if ($Owner) { $Owner } else { '<unknown>' }
  if (-not $Owner -or $lockOwner -ne $Owner) {
    Write-Output ('ERR shotlock held by owner=' + $lockOwner + ', caller=' + $who + '; acquire the lock first (py -3 shotlock.py acquire --owner <you>) or wait')
    exit 3
  }
} else {
  Write-Output 'WARN no shotlock held (single-session legacy mode); proceeding'
}

# ---- 唯一性闸（2026-10-16 r16）：精确匹配 title 的窗口必须唯一——双会话各有
# CMDPHOTO 时旧版 Select -First 1 任意选窗，可能把命令敲进对方会话执行
# （跨会话命令注入面）。同名多窗直接拒绝并报数量。
$all = @(Get-Process cmd -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle.Trim() -eq $Title })
if ($all.Count -eq 0) { throw ('window title=' + $Title + ' not found') }
if ($all.Count -gt 1) { throw ('ambiguous window title=' + $Title + ': ' + $all.Count + ' cmd windows match; each session must use a unique title (e.g. CMDPHOTO-B)') }
$h = $all[0].MainWindowHandle
Set-Clipboard -Value $text
[WinC]::SetWindowPos($h, [IntPtr]::new(-1), 120, 140, 1030, 690, 0x0040) | Out-Null
[WinC]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
[WinC]::SetForegroundWindow($h) | Out-Null
[WinC]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
Start-Sleep -Milliseconds 300
if ([WinC]::GetForegroundWindow() -ne $h) {
  # r16：fg 失败也要还原——此时窗口已 TOPMOST 摆位、ALT 已注入；剪贴板已被
  # Set-Clipboard 覆盖，原内容保不回来，输出里注明
  [WinC]::SetWindowPos($h, [IntPtr]::new(-2), 120, 140, 1030, 690, 0x0040) | Out-Null
  Write-Output 'NOTE clipboard was already overwritten with the command text; original clipboard content is NOT preserved'
  throw 'fg failed'
}
[System.Windows.Forms.SendKeys]::SendWait('{ESC}')
Start-Sleep -Milliseconds 120
[System.Windows.Forms.SendKeys]::SendWait('+{INS}')
Start-Sleep -Milliseconds 400
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
Start-Sleep -Milliseconds 200
Write-Output ("sent: " + $text.Trim())
