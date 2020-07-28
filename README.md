# Get-ServiceCertificate
Script to Create/Renew any service certificate with a domain Certificate Authority. Originally created mainly for LDAPS, but expanded to be used for any service certificate.

Also allows for checking the expiry date on the current certificate and generate a new one if within the defined parameters

Requires the "Get-Certificate" command via powershell, so requires a compatible CA and Windows Version, which I think is 2012R2
