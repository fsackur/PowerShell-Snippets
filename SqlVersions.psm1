

function Get-SqlFriendlyVersion {
    <#
        .PARAMETER Version
        Enter the SQL version that you wish to derive the friendly version from
    #>
    param(
        [System.Version]$Version
    )

    #A web query might hit this page: https://support.microsoft.com/en-gb/kb/321185
    #However it's very script-heavy. Not that easy to web scrape.



    $FriendlyVersion = switch ($Version.Major) {
        13              {"2016 " + $(
                                switch ($Version.Build) {
                                    {$_ -eq 4100}      {"SP1"; continue}
                                    {$_ -eq 1601}      {"RTM"; continue}
                                })
                        }


        12              {"2014 " + $(
                                switch ($Version.Build) {
                                    {$_ -eq 5000}      {"SP2"; continue}
                                    {$_ -eq 4100}      {"SP1"; continue}
                                    {$_ -eq 2000}      {"RTM"; continue}
                                })
                        }  #SP1: 12.0.4100.1
                
        11              {"2012 " + $(
                                switch ($Version.Build) {
                                    {$_ -eq 6020}      {"SP3"; continue}
                                    {$_ -eq 5058}      {"SP2"; continue}
                                    {$_ -eq 3000}      {"SP1"; continue}
                                    {$_ -eq 2100}      {"RTM"; continue}
                                })
                        }  #SP2: 11.0.5058.0  SP1: 11.0.3000.00
                
        10              {"2008 " + $(
                                if ($Version.Minor -ge 50) {
                                    "R2 " + $(
                                        switch ($Version.Build) {
                                            {$_ -eq 6000}      {"SP3"; continue}
                                            {$_ -eq 4000}      {"SP2"; continue}
                                            {$_ -eq 2500}      {"SP1"; continue}
                                            {$_ -eq 1600}      {"RTM"; continue}
                                        })   # SP2: 10.50.4000.0  SP1: 10.50.2500.0
                                } else {
                                    $(
                                        switch ($Version.Build) {
                                            {$_ -eq 6000}      {"SP4"; continue}
                                            {$_ -eq 5500}      {"SP3"; continue}
                                            {$_ -eq 4000}      {"SP2"; continue}
                                            {$_ -eq 2531}      {"SP1"; continue}
                                            {$_ -eq 1600}      {"RTM"; continue}
                                        })
                                })
                        }  #SP3 10.00.5500.00   SP2 10.00.4000.00   SP1 10.00.2531.00
                
        9               {"2005" + $(
                                switch ($Version.Build) {
                                    {$_ -eq 5000}      {"SP4"; continue}
                                    {$_ -eq 4035}      {"SP3"; continue}
                                    {$_ -eq 3042}      {"SP2"; continue}
                                    {$_ -eq 2047}      {"SP1"; continue}
                                    {$_ -eq 1399}      {"RTM"; continue}
                                })
                        }
    }
    return $FriendlyVersion
}
    
    
    
#Get versions of all installed instances
$SqlVersions = Get-WmiObject -Query "SELECT PathName FROM Win32_Service WHERE Name LIKE '%sql%' AND PathName LIKE '%sqlservr.exe%'" | foreach {
    $ExePath = $_.PathName.Split('"',3)[1]
    [version](Get-Command $ExePath).FileVersionInfo.ProductVersion
}
        
        
       
function Get-InstalledSqlSupportsTls12 {
    <#
        Returns true if SQL is not installed, or if all installed instances support TLS1.2. Returns false if any installed instances do not support TLS1.2.
    #>
    
    $SqlVersions = Get-WmiObject -Query "SELECT PathName FROM Win32_Service WHERE Name LIKE '%sql%' AND PathName LIKE '%sqlservr.exe%'" | foreach {
        $ExePath = $_.PathName.Split('"',3)[1]
        [version](Get-Command $ExePath).FileVersionInfo.ProductVersion
    }

    $AllSqlVersionsSupportTls = $true

    foreach ($Version in $SqlVersions) {

        #sometimes 2008R2 shows up as 10.52
        if ($Version.Minor -gt 50) {$Version = [version]($Version.ToString() -replace $Version.Minor, '50')}

        #https://support.microsoft.com/en-gb/help/3135244/tls-1.2-support-for-microsoft-sql-server
        $AllSqlVersionsSupportTls = $AllSqlVersionsSupportTls -and $(
            switch ($Version.Major) {

                10
                    {($Version -ge [version]"10.50.6542.0")}

                11
                    {($Version -ge [version]"11.0.6542.0") -or
                        ($Version -lt [version]"11.0.6020.0" -and $Version -ge [version]"11.0.5352.0")}

                12
                    {($Version -ge [version]"12.0.4219.0") -or
                        ($Version -lt [version]"12.0.4100.0" -and $Version -ge [version]"12.0.2564.0")}

                {$_ -ge 13}
                    {$true}

                default
                    {$false}

            }
        )
    }

    return $AllSqlVersionsSupportTls

}
