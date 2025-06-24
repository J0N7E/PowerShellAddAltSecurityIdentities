<#
 .SYNOPSIS
    PowerShell AD Strong Certificate Mapping

 .DESCRIPTION
    Checks security log for missing strong mappings from specific issuer
    Add certificate serial number from event to users altSecurityIdentities attribute

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

param
(
    $IssuerCN = "Certezza Issuing CA v2",
    $DaysBack = 7
)

#############
# Initialize
#############

# Set reversed BaseDN
$BaseDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
$BaseDNArray = $BaseDN -split ','
[array]::Reverse($BaseDNArray)
$ReversedBaseDN = $BaseDNArray -join ','

# Days to miliseconds
$EventTime = $DaysBack * 86400000

# Event XML
$KdcsvcQuery =
@"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
        *[System[(Level=2 or Level=3) and (band(Keywords,36028797018963968)) and (EventID=39) and TimeCreated[timediff(@SystemTime) &lt;= $EventTime]]] and
        *[EventData[Data[@Name='Issuer'] and (Data='$IssuerCN')]]
    </Select>
  </Query>
</QueryList>
"@

#######
# Main
#######

# Get events
$SystemKdcsvcEvents = Get-WinEvent -FilterXml $KdcsvcQuery

foreach ($Event in $SystemKdcsvcEvents)
{
    # Get xml
    $EventXml = ([xml]$Event.ToXml()).Event

    # Get username
    $Username = $EventXml.EventData.Data.Item(0).'#Text'

    # Get serialnumber
    $SerialNumber = $EventXml.EventData.Data.Item(3).'#Text'

    if ($Username -and $SerialNumber)
    {
        # Get user from AD
        $AdUser = Get-ADUser -Identity $Username -Properties altSecurityIdentities

        if ($ADUser)
        {
            # Set reversed serialnummer
            $SerialNumberArray =  $SerialNumber -split "(..)"
            [array]::Reverse($SerialNumberArray)
            $ReversedSerialNumber = $SerialNumberArray -join ''

            # Set mapping
            $X509IssuerSerialNumberMapping = "x509:<I>$ReversedBaseDN,CN=$Issuer<SR>$ReversedSerialNumber"

            # Check if altSecurityIdentities contains mapping
            if (-not $AdUser.altSecurityIdentities.Contains($X509IssuerSerialNumberMapping))
            {
                Write-Verbose -Message "Adding $X509IssuerSerialNumberMapping -> $($AdUser.Name) ($Username)" -Verbose
                Set-ADUser -Identity $Username -Add @{altSecurityIdentities=$X509IssuerSerialNumberMapping}
            }
        }
    }
}
