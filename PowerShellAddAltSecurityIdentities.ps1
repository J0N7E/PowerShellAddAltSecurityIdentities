<#
 .SYNOPSIS
    PowerShell Strong Certificate Mapping (altSecurityIdentities)

 .DESCRIPTION
    Checks security log for missing strong mappings from a specific issuer
    Add certificate serial number from event to users altSecurityIdentities attribute
    View all users with set altSecurityIdentities and their mapped serial numbers

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E
#>

[cmdletbinding(DefaultParameterSetName='Set')]

param
(
    [Parameter(ParameterSetName='Set')]
    [String]$IssuerCN,

    [Parameter(ParameterSetName='Set')]
    [Int]$DaysBack = 7,

    [Parameter(ParameterSetName='Get')]
    [Switch]$Get
)

#######
# Func
#######

function Reverse-String
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$InputObject,
        [Switch]$ByteOrder
    )

    if ($ByteOrder.IsPresent)
    {
        $BaseArray = $InputObject -split '(..)'
    }
    else
    {
        $BaseArray = $InputObject -split ','
    }

    [array]::Reverse($BaseArray)

    if ($ByteOrder.IsPresent)
    {
        Write-Output -InputObject ($BaseArray -join '')
    }
    else
    {
        Write-Output -InputObject ($BaseArray -join ',')
    }
}

#######
# Init
#######

# Get BaseDN
$BaseDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName

#######
# Main
#######

switch ($PsCmdlet.ParameterSetName)
{
    'Get'
    {
        $ADUsers = Get-ADUser -Filter "altSecurityIdentities -like '*'" -Properties altSecurityIdentities

        foreach ($ADUser in $ADUsers)
        {
            Write-Host "$($ADUser.Name) ($($ADUser.SamAccountName))"

            foreach ($Binding in ($ADUser.altSecurityIdentities))
            {
                $Output = [String]::Empty

                $SerialNumber = [regex]::Match($Binding, ".*<SR>(.*)", 2)

                if ($SerialNumber.Success)
                {
                    $Output = Reverse-String -InputObject ($SerialNumber.Groups.Item(1).Value) -ByteOrder
                }

                $IssuerCN = [regex]::Match($Binding, ".*CN=(.*)<SR>.*", 2)

                if ($IssuerCN.Success)
                {
                    $Output += " ($($IssuerCN.Groups.Item(1).Value))"
                }

                if ($SerialNumber.Success -or $IssuerCN.Success)
                {
                    Write-Host -Object $Output -ForegroundColor DarkCyan
                }
            }
        }
    }

    'Set'
    {
        # Set reversed BaseDN
        $ReversedBaseDN = Reverse-String -InputObject $BaseDN

        # Days to miliseconds
        $EventTime = $DaysBack * 86400000

        # Get
        if (-not $IssuerCN)
        {
            # Get Issuer CN
            $IssuerCN = (certutil) | Where-Object {
                $_ -match "^  (?:Name|Namn):.*(?:``|`")(.*)(?:'|`")$"
            } | Select-Object -Last 1 | ForEach-Object { $Matches[1] }

            if (-not $IssuerCN)
            {
                Write-Warning -Message "Unable to find Issuer CN, please use the -IssuerCN parameter."
                return
            }

            Write-Verbose -Message "Looking for events with Issuer = `"$IssuerCN`"" -Verbose
        }

        # Event XML
        $KdcsvcQuery =
        @(
            "<QueryList>",
                "<Query Id=`"0`" Path=`"System`">",
                "<Select Path=`"System`">",
                    "*[System[(Level=2 or Level=3) and (band(Keywords,36028797018963968)) and (EventID=39) and TimeCreated[timediff(@SystemTime) &lt;= $EventTime]]] and",
                    "*[EventData[Data[@Name='Issuer'] and (Data='$IssuerCN')]]",
                "</Select>",
                "</Query>",
            "</QueryList>"
        )

        # Get events
        $SystemKdcsvcEvents = Get-WinEvent -FilterXml ($KdcsvcQuery -join '') -ErrorAction SilentlyContinue

        foreach ($Event in $SystemKdcsvcEvents)
        {
            # Get xml
            $EventXml = ([xml]$Event.ToXml()).Event

            # Get username
            $Username = $EventXml.EventData.Data[0].'#Text'

            # Get serialnumber
            $SerialNumber = $EventXml.EventData.Data[3].'#Text'

            if ($Username -and $SerialNumber)
            {
                # Get user from AD
                $AdUser = Get-ADUser -Identity $Username -Properties altSecurityIdentities

                if ($ADUser)
                {
                    # Set reversed serialnummer
                    $ReversedSerialNumber = Reverse-String -InputObject $SerialNumber -ByteOrder

                    # Set mapping
                    $X509IssuerSerialNumberMapping = "x509:<I>$ReversedBaseDN,CN=$IssuerCN<SR>$ReversedSerialNumber"

                    # Check if altSecurityIdentities contains mapping
                    if (-not $AdUser.altSecurityIdentities.Contains($X509IssuerSerialNumberMapping))
                    {
                        Write-Verbose -Message "Adding $X509IssuerSerialNumberMapping -> $($AdUser.Name) ($Username)" -Verbose
                        Set-ADUser -Identity $Username -Add @{altSecurityIdentities=$X509IssuerSerialNumberMapping}
                    }
                }
            }
        }
    }
}

# SIG # Begin signature block
# MIIejQYJKoZIhvcNAQcCoIIefjCCHnoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUy7zQdrEhO6v6gfwa/BEdqfXy
# 2SOgghgOMIIFBzCCAu+gAwIBAgIQdFzLNL2pfZhJwaOXpCuimDANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMzA5MDcxODU5NDVaFw0yODA5MDcx
# OTA5NDRaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA0cNYCTtcJ6XUSG6laNYH7JzFfJMTiQafxQ1dV8cjdJ4ysJXAOs8r
# nYot9wKl2FlKI6eMT6F8wRpFbqKqmTpElxzM+fzknD933uEBLSAul/b0kLlr6PY2
# oodJC20VBAUxthFUYh7Fcni0dwz4EjXJGxieeDDLZYRT3IR6PzewaWhq1LXY3fhe
# fYQ1Q2nqHulVWD1WgucgIFEfUJCWcOvfmJBE+EvkNPVoKAqFxJ61Z54z8y6tIjdK
# 3Ujq4bgROQqLsFMK+mII1OqcLRKMgWkVIS9nHfFFy81VIMvfgaOpoSVLatboxAnO
# mn8dusJA2DMH6OL03SIBb/FwE7671sjtGuGRp+nlPnkvoVqFET9olZWDxlGOeeRd
# Tc3jlcEPb9XLpiGjlQfMfk4ycSwraJqn1cYDvSXh3K6lv0OeSLa/VQRlEpOmttKB
# EI/eFMK76DZpGxFvv1xOg1ph3+01hCboOXePu9qSNk5hnIrBEb9eqks3r5ZDfrlE
# wjFUhd9kLe2UKEaHK7HI9+3x1WhTgNRKWzKzqUcF9aVlpDQRplqbUMJEzMxzRUIk
# 01NDqw46gjUYet6VnIPqnQAe2bLWqDMeL3X6P7cAHxw05yONN51MqyBFdYC1MieY
# uU4MOoIfIN6M6vEGn7avjw9a4Xpfgchtty2eNgIRg+KuJ3Xxtd1RDjUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFFjQBHg94o+OtZeRxQoH0mKFzMApMA0G
# CSqGSIb3DQEBCwUAA4ICAQBSglLs0PCn7g36iGRvqXng/fq+6nL3ZSLeLUXSDoFX
# KhJ3K6wFSiHBJtBYtWc7OnHIbIg1FFFAi5GIP56MMwmN4NoY0DrBN0Glh4Jq/lhu
# iah5zs/9v/aUvtwvBD4NVX0G/wJuRuX697UQZrtkWninB46BMPU+gEg1ctn0V4zQ
# 3fazrcmJqD9xIwKlOXsvxOAO5OJ51ucdsubD6QkJa++4bGd5HhoC8/O18mxz6YYa
# gOnXWJObybkwdkDC9MUjy5wZNAv48DkUM+OArbfM3ZpfcAVTnDrfuzpoOKTkcdgb
# N+4VXJC/ly1D98f+IpEOw1UItX8Hg67WfU9sXcIY+fghzHPHF864vp2F/G75i02M
# oqeRpeO3guwum3DbKCkKts5S1QXnE7pmeqe4U595jCVhELeB6ifrvj0ulSlOU5GE
# twNY5VL0T3cHegBmtQXFfQoT6vboF6m9I7kVlKGT4WI8M/UQYCQ2ZP3HTjdSHt9U
# cJslGMqDxhbkGLH49ESP5ghbRddll24dsw0dF96lOIEmhB01UNIz40TonraK3cku
# Jdnrh/2fHYbycGHjkowiMUJQaihbZBRKvBHhrM7OuQ96M9g8Gk2RCIqdX0lO8n2y
# S8fnzEoWe8FVwE5bgA5Nwl6iYdoszubYgh+siVMe2EFaUh0DXXpbQ3JxjMGe5qVK
# 1zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwgga8MIIEpKADAgECAhALrma8Wrp/lYfG+ekE
# 4zMEMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjQwOTI2MDAwMDAwWhcNMzUxMTI1
# MjM1OTU5WjBCMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxIDAeBgNV
# BAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDI0MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvmpzn/aVIauWMLpbbeZZo7Xo/ZEfGMSIO2qZ46XB/QowIEMS
# vgjEdEZ3v4vrrTHleW1JWGErrjOL0J4L0HqVR1czSzvUQ5xF7z4IQmn7dHY7yijv
# oQ7ujm0u6yXF2v1CrzZopykD07/9fpAT4BxpT9vJoJqAsP8YuhRvflJ9YeHjes4f
# duksTHulntq9WelRWY++TFPxzZrbILRYynyEy7rS1lHQKFpXvo2GePfsMRhNf1F4
# 1nyEg5h7iOXv+vjX0K8RhUisfqw3TTLHj1uhS66YX2LZPxS4oaf33rp9HlfqSBeP
# ejlYeEdU740GKQM7SaVSH3TbBL8R6HwX9QVpGnXPlKdE4fBIn5BBFnV+KwPxRNUN
# K6lYk2y1WSKour4hJN0SMkoaNV8hyyADiX1xuTxKaXN12HgR+8WulU2d6zhzXomJ
# 2PleI9V2yfmfXSPGYanGgxzqI+ShoOGLomMd3mJt92nm7Mheng/TBeSA2z4I78Jp
# wGpTRHiT7yHqBiV2ngUIyCtd0pZ8zg3S7bk4QC4RrcnKJ3FbjyPAGogmoiZ33c1H
# G93Vp6lJ415ERcC7bFQMRbxqrMVANiav1k425zYyFMyLNyE1QulQSgDpW9rtvVcI
# H7WvG9sqYup9j8z9J1XqbBZPJ5XLln8mS8wWmdDLnBHXgYly/p1DhoQo5fkCAwEA
# AaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUn1cs
# A3cOKBWQZqVjXu5Pkh92oFswWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRp
# bWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAPa0eH3aZW+M4hBJH
# 2UOR9hHbm04IHdEoT8/T3HuBSyZeq3jSi5GXeWP7xCKhVireKCnCs+8GZl2uVYFv
# Qe+pPTScVJeCZSsMo1JCoZN2mMew/L4tpqVNbSpWO9QGFwfMEy60HofN6V51sMLM
# XNTLfhVqs+e8haupWiArSozyAmGH/6oMQAh078qRh6wvJNU6gnh5OruCP1QUAvVS
# u4kqVOcJVozZR5RRb/zPd++PGE3qF1P3xWvYViUJLsxtvge/mzA75oBfFZSbdakH
# Je2BVDGIGVNVjOp8sNt70+kEoMF+T6tptMUNlehSR7vM+C13v9+9ZOUKzfRUAYSy
# yEmYtsnpltD/GWX8eM70ls1V6QG/ZOB6b6Yum1HvIiulqJ1Elesj5TMHq8CWT/xr
# W7twipXTJ5/i5pkU5E16RSBAdOp12aw8IQhhA/vEbFkEiF2abhuFixUDobZaA0Vh
# qAsMHOmaT3XThZDNi5U2zHKhUs5uHHdG6BoQau75KiNbh0c+hatSF+02kULkftAR
# jsyEpHKsF7u5zKRbt5oK5YGwFvgc4pEVUNytmB3BpIiowOIIuDgP5M9WArHYSAR1
# 6gc0dP2XdkMEP5eBsX7bf/MGN4K3HP50v/01ZHo/Z5lGLvNwQ7XHBx1yomzLP8lx
# 4Q1zZKDyHcp4VQJLu2kWTsKsOqQxggXpMIIF5QIBATAkMBAxDjAMBgNVBAMMBUow
# TjdFAhB0XMs0val9mEnBo5ekK6KYMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQ/HD2Pl0pASNki
# Uu/NXTfC2SSvQjANBgkqhkiG9w0BAQEFAASCAgA0JnQ/4/ex1hnNd2RCAau0KAFb
# 5cScSn2LfXpN1EB1sjB11836jR1KmizecUu4FYH3tzcnbDBg7kcu8syeMoEP+Uxx
# h8LVkFUrLDeOoBSfT3+oGiP12/x/8ZHKGgqIjWIEFyxIaUCGcV5KGe3E5TqTZblR
# JejL0lSrYiQxUzT3rizk+0VtLDoF7MNQskDQsptN2rrxhQzUQ1XTdlAky7cwBtql
# Wo8xJcQ/3SEhLDKsgVIU1Vy6JdJQkKcLml+86uX4E+R3AhMGfhy38LONzAs5kEgN
# cTa5KWtVV84Ql9hxBoJiagaW+JbfdEcEXdoX7CXC3bOuFzEvfU8IESXbA2dafoXE
# wMTx3mG4KcVUJRkUsoBoi8yqUQHTrqvQTGC+u4aFOe/I1I0FuRIZGvZYn3MCmarf
# PFleRkQbc9Fl07EXNmZrOemQh9MNiWTYqNq4vh6wS2DO60JjgOuhAp4LMEeQygXL
# DG0M4MCgPj+YUOni2wJrDYvqU7GQtUCtOIeMGEChan76zTKUlnyII4mMf3RdXppt
# t6ry3DvnkA0b3XkNrriKQkK2HenVLXz3G0SNDHYD5eSSsAMY8yehRjqNNolaWwj9
# 5SlCnH1lvJxJne98YciP71xC9FzyWV1OBcOjsNg7n769tT1t0wnK04gvlB1wB0N7
# KV4cFSAqoFSRf8EP2aGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0ECEAuuZrxaun+Vh8b56QTjMwQwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTA2MjUxNzAwMDJaMC8G
# CSqGSIb3DQEJBDEiBCDKnrhlnHKobRJyPT8PfYmkF+VP6D2aZq9a75c7z2z/ezAN
# BgkqhkiG9w0BAQEFAASCAgCsVU9qhLc4M5ySFxEirSRrP+fZZmFTvjsSO1EimEgn
# C6Y43r8PL81ksCKfdDSYddByzwyPCcuRUHUNv+uxw1TxmiR3JNq8yTwfaN7ULqXn
# 44EstUfzCzybyu/s1E/j7MClWvYRJnTWRxZXb05eulKiKDl+7MdL9O/eN1wjf0VR
# HozJPfIsI4i1SZ3lrYoq2S9YH/Y2vUiW+vfKzfLzCb8mBCoidZh8BEV+V/q6eT7x
# khMuSMXke+r/DxmiqYRfC5E/MIpljng887tyBs5Pk/UnepLgb9E5f7uqbs3/QJUJ
# MuLOEayM+JM6F5FQfyOa4+FfGu5VrA7c/qrIDe+/db79xDAdF9nNWRhKU0MaX73m
# sXc8Q7OuBWcmGFJ+3cQRTpHdGIcmJ/IeANwf23Cw0PjT1ZGrkuWnT71SJlw1o2uO
# fTaEOmNdRxU17F0umX7ztT1BOiyWWIyahr8/vfNUeN9kaQh+VS1mrYAcDoAoncqs
# l6kO4ShhvwjNO01I1UGzKF3TgwfP/ZcwAx61VuKLCKEF1oZ+tKHEgOqyqZGMweb1
# hzIjpjH+mnimilMFpaly3v0YHhj/FCBqQd0vzQt7Zv03vWbtCOgQco1u1VNOu/Wy
# /EJ5hDiWLDfKxdGAbSZfauyVuiTDLW+9Lp4Sr8Hgt2UrmMT19dcKOjgT2lZCClaa
# mg==
# SIG # End signature block
