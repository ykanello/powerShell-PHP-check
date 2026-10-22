
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the input CSV file")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "output.csv",

    # Minimum PHP version considered actively supported (PHP < 8.2 is EOL)
    [version]$MinimumSupportedVersion = "8.2.0"
)

# Read input CSV
$rows = Import-Csv -Path $CsvPath

if (-not $rows) {
    Write-Warning "Input CSV '$CsvPath' is empty or could not be parsed."
    exit
}

$results = foreach ($row in $rows) {
    # Extract and clean URL
    $rawUrl = $row.'URL / Access'
    if ($rawUrl) { $rawUrl = $rawUrl.Trim() }

    $phpDetected        = "No"
    $detectedVersionStr = $null
    $upgradeRecommended = "N/A"
    $detectionSource    = @()
    $scanStatus         = "Skipped (No URL)"

    if (-not [string]::IsNullOrWhiteSpace($rawUrl)) {
        # Normalize protocol if omitted
        $targetUrl = if ($rawUrl -match '^https?://') { $rawUrl } else { "https://$rawUrl" }

        try {
            # Inspect HTTP headers and response body
            $response = Invoke-WebRequest -Uri $targetUrl -Method Get -MaximumRedirection 3 -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            $headers  = $response.Headers
            $scanStatus = "Scanned"

            # 1. Inspect X-Powered-By header
            if ($headers['X-Powered-By']) {
                $poweredBy = [string]$headers['X-Powered-By']
                if ($poweredBy -match 'PHP(?:/([0-9.]+))?') {
                    $phpDetected = "Yes"
                    $detectionSource += "Header: X-Powered-By"
                    if ($matches[1]) { $detectedVersionStr = $matches[1] }
                }
            }

            # 2. Inspect Server banner
            if ($headers['Server']) {
                $serverHeader = [string]$headers['Server']
                if ($serverHeader -match 'PHP(?:/([0-9.]+))?') {
                    $phpDetected = "Yes"
                    $detectionSource += "Header: Server"
                    if (-not $detectedVersionStr -and $matches[1]) { $detectedVersionStr = $matches[1] }
                }
            }

            # 3. Inspect Session Cookie
            $cookies = $headers['Set-Cookie']
            if ($cookies -and ($cookies -match 'PHPSESSID')) {
                $phpDetected = "Yes"
                $detectionSource += "Cookie: PHPSESSID"
            }

            # 4. Inspect HTML markers if version not found in headers
            if (-not $detectedVersionStr -and $response.Content) {
                if ($response.Content -match 'name="generator"\s+content="[^"]*PHP\s*([0-9.]+)?' -or
                    $response.Content -match 'powered by\s+PHP(?:\s+([0-9.]+))?') {
                    $phpDetected = "Yes"
                    $detectionSource += "Body marker"
                    if ($matches[1]) { $detectedVersionStr = $matches[1] }
                }
            }

            # Evaluate upgrade status
            if ($detectedVersionStr) {
                # Format to a standard 3-part version string (e.g., '8.1' -> '8.1.0') for [version] parsing
                $parts = $detectedVersionStr.Split('.')
                $normalizedVerStr = switch ($parts.Count) {
                    1 { "$($parts[0]).0.0" }
                    2 { "$($parts[0]).$($parts[1]).0" }
                    default { $detectedVersionStr }
                }

                if ([version]::TryParse($normalizedVerStr, [ref][version]$parsedVersion)) {
                    if ($parsedVersion -lt $MinimumSupportedVersion) {
                        $upgradeRecommended = "Yes (EOL / Outdated)"
                    } else {
                        $upgradeRecommended = "No (Supported)"
                    }
                } else {
                    $upgradeRecommended = "Manual Review Required"
                }
            } elseif ($phpDetected -eq "Yes") {
                $upgradeRecommended = "Version Masked (Check Host)"
            } else {
                $upgradeRecommended = "No"
            }

        } catch {
            $scanStatus = "Failed: $($_.Exception.Message)"
            $upgradeRecommended = "Unreachable"
        }
    }

    # Combine original record with scan findings
    [PSCustomObject]@{
        "Application Name"    = $row.'Application Name'
        "URL / Access"        = $rawUrl
        "Business Owner"      = $row.'Business Owner'
        "IT Owner"            = $row.'IT Owner'
        "PHP Detected"        = $phpDetected
        "PHP Version"         = if ($detectedVersionStr) { $detectedVersionStr } elseif ($phpDetected -eq "Yes") { "Masked / Unknown" } else { "N/A" }
        "Upgrade Recommended" = $upgradeRecommended
        "Detection Method"    = if ($detectionSource.Count -gt 0) { ($detectionSource -join "; ") } else { "None" }
        "Scan Status"         = $scanStatus
    }
}

# Export the updated records to output.csv
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Scan completed. Output saved to: $OutputPath" -ForegroundColor Green
