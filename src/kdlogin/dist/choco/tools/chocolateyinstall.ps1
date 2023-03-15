$ErrorActionPreference = 'Stop'

$packageName = 'kubectl-login'

$toolsPath = Split-Path $MyInvocation.MyCommand.Definition

$packageArgs = @{
  PackageName    = $packageName
  FileFullPath64 = Get-Item $toolsPath\kubectl-login_windows.zip
  Destination    = $toolsPath
}
Get-ChocolateyUnzip @packageArgs

Remove-Item "$toolsPath\kubectl-login_windows.zip"