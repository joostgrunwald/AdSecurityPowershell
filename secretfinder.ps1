Import-Module ActiveDirectory  
  
function Get-ReadableFileShares {  
    $computers = Get-ADComputer -Filter {OperatingSystem -like "Windows*"}  
  
    $readableFileShares = @()  
  
    foreach ($computer in $computers) {  
        $computerName = $computer.Name  
        Write-Host "Checking file shares on $computerName..." -ForegroundColor Yellow  
        $fileShares = Get-WmiObject -Class Win32_Share -ComputerName $computerName -ErrorAction SilentlyContinue  
  
        if ($fileShares) {  
            foreach ($fileShare in $fileShares) {  
                $shareName = $fileShare.Name  
                $shareType = $fileShare.Type  
  
                if ($shareType -ne 0x3) {  
                    continue  
                }  
  
                $uncPath = "\\$computerName\$shareName"  
                try {  
                    $acl = Get-Acl -Path $uncPath -ErrorAction Stop  
                    if ($acl.Access | Where-Object {($_.IdentityReference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read)}) {  
                        Write-Host "Readable file share: $uncPath" -ForegroundColor Green  
                        $readableFileShares += $uncPath  
                    }  
                } catch {  
                    Write-Host "Error accessing ${uncPath}: $_" -ForegroundColor Red  
                }  
            }  
        } else {  
            Write-Host "No file shares found on $computerName" -ForegroundColor Gray  
        }  
    }  
  
    return $readableFileShares  
}  
  
function Find-InterestingFiles {  
    param (  
        [Parameter(Mandatory=$true)]  
        [Array]$fileShares  
    )  
  
    $searchPatterns = @(  
        "(?i)(password|passw0rd|p@ssw0rd)",  
        "(?i)(private\s*key|BEGIN\s*RSA\s*PRIVATE\s*KEY)",  
        "(?i)(BEGIN\s*CERTIFICATE)"  
    )  
  
    foreach ($fileShare in $fileShares) {  
        Write-Host "Searching for interesting files in $fileShare..." -ForegroundColor Yellow  
        $files = Get-ChildItem -Path $fileShare -Recurse -File -ErrorAction SilentlyContinue  
  
        foreach ($file in $files) {  
            $fileContent = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue  
  
            foreach ($pattern in $searchPatterns) {  
                if ($fileContent -match $pattern) {  
                    Write-Host "Interesting file found: $($file.FullName)" -ForegroundColor Green  
                }  
            }  
        }  
    }  
}  
  
$readableFileShares = Get-ReadableFileShares  
Find-InterestingFiles -fileShares $readableFileShares  
