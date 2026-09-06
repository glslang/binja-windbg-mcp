# Opt-in: run elevated on the disposable debuggee. Creates and deletes one standard user.
$ErrorActionPreference = 'Stop'
$hash = (Get-FileHash ($env:SystemRoot + '\System32\drivers\mountmgr.sys') -Algorithm SHA256).Hash
if ($hash -ne '734b4a45381ca6850d827f895e86e50ad03a882689483510402d96757fe15497') {throw 'Expected the pinned mountmgr build'}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public class AccessRow {
 public string Device, User, Sid, Sddl;
 public bool Administrator, Opened, QuerySucceeded;
 public uint DesiredAccess, Code, Returned;
 public int Error, QueryError;
 public string Data;
}
public static class BnAccessProbe {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUser(string user,string domain,string password,int type,int provider,out IntPtr token);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint sharing,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint code,IntPtr input,uint inSize,byte[] output,uint outSize,out uint returned,IntPtr overlapped);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(SafeFileHandle h,uint info,byte[] descriptor,uint length,out uint needed);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(byte[] sd,uint revision,uint info,out IntPtr text,out uint count);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 static AccessRow Row(string device,uint access) {
  var id=WindowsIdentity.GetCurrent();return new AccessRow {Device=device,DesiredAccess=access,User=id.Name,Sid=id.User.Value,Administrator=new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator)};
 }
 static List<AccessRow> Probe() {
  var rows=new List<AccessRow>();
  foreach(string device in new[]{@"\\.\MountPointManager",@"\\.\HackSysExtremeVulnerableDriver"}) {
   foreach(uint access in new uint[]{0,0x80,0x20000,0x80000000,0x40000000,0xc0000000}) {
    var row=Row(device,access);
    using(var h=CreateFile(device,access,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
     row.Opened=!h.IsInvalid;row.Error=h.IsInvalid?Marshal.GetLastWin32Error():0;
     if(row.Opened && access==0x20000) {
      uint length;GetKernelObjectSecurity(h,4,null,0,out length);var data=new byte[length];
      if(!GetKernelObjectSecurity(h,4,data,length,out length))throw new Win32Exception();
      IntPtr sddl;uint chars;if(!ConvertSecurityDescriptorToStringSecurityDescriptor(data,1,4,out sddl,out chars))throw new Win32Exception();
      row.Sddl=Marshal.PtrToStringUni(sddl);LocalFree(sddl);
     }
    }
    rows.Add(row);
   }
  }
  // Both codes are query operations in this identified mountmgr build. HEVD receives no IOCTL.
  foreach(uint code in new uint[]{0x6d003c,0x6d4008}) {
   var row=Row(@"\\.\MountPointManager",0);row.Code=code;
   using(var h=CreateFile(row.Device,0,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
    row.Opened=!h.IsInvalid;row.Error=h.IsInvalid?Marshal.GetLastWin32Error():0;
    if(row.Opened) {var output=new byte[4];uint returned;row.QuerySucceeded=DeviceIoControl(h,code,IntPtr.Zero,0,output,4,out returned,IntPtr.Zero);row.QueryError=row.QuerySucceeded?0:Marshal.GetLastWin32Error();row.Returned=returned;row.Data=BitConverter.ToString(output).Replace("-","").ToLowerInvariant();}
   }
   rows.Add(row);
  }
  return rows;
 }
 public static List<AccessRow> SystemProbe() {return Probe();}
 public static List<AccessRow> UserProbe(string name,string password) {
  IntPtr token;if(!LogonUser(name,".",password,2,0,out token))throw new Win32Exception();
  try {using(var identity=new WindowsIdentity(token))using(var context=identity.Impersonate()) {return Probe();}}
  finally {CloseHandle(token);}
 }
}
'@
$name = 'bnmcp_' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$password = 'Bn9!' + [Guid]::NewGuid().ToString('N')
$created = $false
try {
 $null = New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -Description 'Temporary Binary Ninja MCP access verification'
 $created = $true
 $group = Get-LocalGroup -SID 'S-1-5-32-545'
 Add-LocalGroupMember -Group $group -Member $name
 $system = [BnAccessProbe]::SystemProbe()
 $user = [BnAccessProbe]::UserProbe($name,$password)
 if (@($user | Where-Object {$_.Administrator}).Count -ne 0) {throw 'Expected a standard user token'}
 [pscustomobject]@{System=$system;StandardUser=$user;AccountTemporary=$true} | ConvertTo-Json -Depth 6 -Compress
} finally {
 if ($created) {Remove-LocalUser -Name $name}
 $password = $null
}
