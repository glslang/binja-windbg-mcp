$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class HevdE2E {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
 public static int OpenOnce() {
  using (var handle=CreateFileW(@"\\.\HackSysExtremeVulnerableDriver",0,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
   return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
  }
 }
}
'@
$result=[HevdE2E]::OpenOnce()
[pscustomobject]@{Operation='open-close';Win32Error=$result;IoctlsSent=0} | ConvertTo-Json -Compress
if($result -ne 0){exit 1}
