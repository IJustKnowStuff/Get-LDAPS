param(
	
# You can set the default here, or override them when passing script in command line
# Require the Template Short and Long/Display name. 
# Can be found when looking at the properties of the certifcate template.
# These can be the same string.
[Parameter(Mandatory=$FALSE)]
[String]
$LDAPTemplate="LDAPSAuthentication",
[String]
$LDAPTemplateDisplayName="LDAPS Authentication",


#In process of implementing this. Allows this script to be used for any service.
[Parameter(Mandatory=$FALSE)]
[String]
$ServiceName="NTDS",

# You can set the default here, or override them when passing script in command line
# Variable used for the name of the certificate store used while moving around Certificates. Default "(New-Guid).Guid" to generate a new unique name.
# This TempCertStore is deleted at the end of the script.
[Parameter(Mandatory=$FALSE)]
[String]
$TempCertStore=(New-Guid).Guid,

# You can set the default here, or override them when passing script in command line
# If the expirey of the current certificate is less that this (DAYS), then a new certificate will be requested.
[Parameter(Mandatory=$FALSE)]
[int]
$RenewPeriod=30,

# You can set the default here, or override them when passing script in command line
# Value controls how many days a certificate can be expired in the Service Certificate store before it is removed.
[Parameter(Mandatory=$FALSE)]
[int]
$ExpiredDays=14,

# You can set the default here, or override them when passing script in command line
# This isn't really used anymore. Event logs are generated when actions occur. Better for large scale monitoring.
[Parameter(Mandatory=$FALSE)]
[String]
$LogFile="C:\WindowsLDAPSAuthentication",

# You can set the default here, or override them when passing script in command line
# Configures the name of the SOURCE in the event log generated.
[Parameter(Mandatory=$FALSE)]
[String]
$EventLogSource = "CheckSecureLDAPSchedTask"



)


BEGIN{

    
    Function ConfirmServiceExists
    {
        IF($null -eq (Get-Service "$($script:ServiceName)" -ErrorAction SilentlyContinue)){Throw "The Service '$($script:ServiceName)' does not exist on this computer."}
    }
	
	Function RequestCertificate
	{
		$NewCertificate = try{Get-Certificate -Template $Script:LDAPTemplate -CertStoreLocation cert:\localmachine\my -url ldap:}catch{$NewCertificateError = $_}
		IF($NewCertificateError)
		{
			Write-EventLog -LogName "System" -Source $EventLogSource -EventID 1006 -EntryType Information -Message "Requested the Certificate '$($NewCertificate.Thumbprint)' which expires $(Get-Date -date ($NewCertificate.notafter) -format G) using certificate Template $($LDAPTemplate).`
		[RESULT]:`
		$NewCertificate"
		}
		ELSE{Write-EventLog -LogName "System" -Source $EventLogSource -EventID 1006 -EntryType Information -Message "Requested the Certificate '$($NewCertificate.Thumbprint)' which expires $(Get-Date -date ($NewCertificate.notafter) -format G) using certificate Template $($LDAPTemplate).`
		[RESULT]:`
		$NewCertificate"}
	}

	Function MoveToServiceStore
	{
		param ([string]$FROM = "$($Script:TempCertStore)")
		#Then this will move any certificates from the specified store to the SERVICE Certificate store (e.g. Service Certificate store)
		$Certificates = Get-ChildItem Cert:\LocalMachine\$($FROM) | Select-Object Thumbprint,@{N="Template";E={($_.Extensions | where-object{$_.oid.Friendlyname -match "Certificate Template Information"}).Format(0) -replace "(.+)?=(.+)\((.+)?", '$2'}},@{N="Subject";E={$_.SubjectName.name}}
		
		#If the Template Display Name is just and OID number (Always starts with "Template=") due to the template name not being cached, then use a different filter to look for certificates
		IF($LDAPTemplateDisplayName -match "^Template="){$Certs = $Certificates | where-object{$_.template -match "^Template="} | where-object{$_.template.split(",")[0] -match "$Script:LDAPTemplateDisplayName"}}
		ELSE{$Certs = $Certificates | where-object{$_.template -eq "$Script:LDAPTemplateDisplayName"}}
		
		ForEach($Cert in $Certs)
		{
			Write-Verbose $Cert

			#Check that Cert is not null and that it is actually a key and not the parent Certificates folder. (This can occur when no matching template name is found. Really messes things up) 
			IF(($Cert) -and ($null -ne $cert) -and ((Get-Item "HKLM:\SOFTWARE\Microsoft\SystemCertificates\$($FROM)\Certificates\$($Cert.Thumbprint)").name -ne "Certificates"))
			{
				try{
					Move-item "HKLM:\SOFTWARE\Microsoft\SystemCertificates\$($FROM)\Certificates\$($Cert.Thumbprint)" "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\$($ServiceName)\SystemCertificates\MY\Certificates\"
					Write-EventLog -LogName "System" -Source $EventLogSource -EventID 1003 -EntryType Information -Message "Moved the Certificate '$($Cert.Thumbprint)' from the '$FROM' certificate store to the '$ServiceName' service certificate store"
				}
				catch{
					Write-EventLog -LogName "System" -Source $EventLogSource -EventID 1004 -EntryType Error -Message "Attempted and failed to move a certificate from the '$FROM' certificate store to the '$ServiceName' service certificate store.`
					[RESULT]:`
					$_"
				}
				
				
			}
		}
	}

	Function MoveFromServiceStore
	{
		param ([string]$To = "$($Script:TempCertStore)")

	}
	
	#############################
	# FUNCTIONS END
	#############################

	#Create Temp Cert Store if it doesn't already exist
	IF(Test-Path "Cert:\LocalMachine\$Script:TempCertStore")
	{
		$TempFolderAlreadyExist = $TRUE
	}
	ELSE
	{
		$TempFolderAlreadyExist = $FALSE
		New-Item -Path Cert:\LocalMachine\ -Name "$Script:TempCertStore" -ItemType directory
	}

	#Register this script as a source in the event logs
	New-EventLog -LogName System -Source $EventLogSource -ErrorAction SilentlyContinue

	


}


PROCESS{

    #Run Function: Checks the service exists on the computer. It will throw an error and exit the script if it's not found.
    ConfirmServiceExists
    
    #Move any matching certificates from the default MY store to the Service certificate store
	MoveToServiceStore -From "MY"
	
	#Enumerate the certiciates in the Service (Active Directory Domain Services) certificate store
	$ServiceCerts = get-childitem "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\$($ServiceName)\SystemCertificates\MY\Certificates\"

	IF($ServiceCerts.count -eq 0)
	{
		#No Certificates exist in the Service Certificate store.
		RequestCertificate
		MoveToServiceStore -From "MY"

	}
	ELSEIF($ServiceCerts.count -ge 1)
	{
		#Move any Service Certificates to the temp store to allow powershell to check values
		ForEach($ServiceCert in $ServiceCerts)
		{
			$ServiceCertName = Split-Path -path $ServiceCert.name -leaf
			
			#Check the name matches the format of a certificate Thumbprint. Used to prevent copying parent folder if no certificates exist.
			IF($ServiceCertname -match "([a-f0-9]{40})")
			{
				Copy-Item "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\$($ServiceName)\SystemCertificates\MY\Certificates\$($ServiceCertName)" "HKLM:\SOFTWARE\Microsoft\SystemCertificates\$($TempCertStore)\Certificates\"
			}
		}	
		
		#Now that the certificates are in a store we can read with powershell, check the latest expiry
		$Expiry = (get-childitem "Cert:\LocalMachine\$($TempCertStore)\" | Sort-Object NotAfter -Descending)[0].notafter
		IF($Expiry -le (Get-Date).AddDays($RenewPeriod))
		{
			#Certificate Expiry is less than renew period. Request a new certificate
			RequestCertificate
			MoveToServiceStore -From "MY"
		}

		#Now remove any certificates that have expired from the Service Certificate store
		$ExpiredCertificates = Get-ChildItem "Cert:\LocalMachine\$($TempCertStore)\" | where-object{$_.notafter -le (Get-Date).AddDays(-$ExpiredDays)}
		ForEach($Certificate in $ExpiredCertificates)
		{
			Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\$($ServiceName)\SystemCertificates\MY\Certificates\$($Certificate.Thumbprint)" -Recurse -Force
			Write-EventLog -LogName "System" -Source $EventLogSource -EventID 1004 -EntryType Information -Message "CheckSecureLDAPSchedTask has deleted the Certificate '$($Certificate.Thumbprint)' which expired $(Get-Date -date ($Certificate.notafter) -format G) " #-Category 1 -RawData 10,20
		}



	}

}
END{
	
	#once everything is done, clean up by removing the Temporary Certificate Store created in the script.
	Remove-Item -Path "Cert:\LocalMachine\$Script:TempCertStore" -Recurse -Force
	
}


