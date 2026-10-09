# Builds paris-traceroute for Linux and Windows (amd64, arm64) and packs
# release archives into .\dist: tar.gz for Linux, zip for Windows.
# Usage: .\build.ps1 [-Version v1.0.0] [-Test]
param([string]$Version = 'dev', [switch]$Test)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if ($Test) {
    go vet ./...
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    go test ./...
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}

if (Test-Path dist) { Remove-Item -Recurse -Force dist }
New-Item -ItemType Directory dist | Out-Null
$targets = 'linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64'
try {
    foreach ($t in $targets) {
        $os, $arch = $t.Split('/')
        $name = "paris-traceroute_${Version}_${os}_${arch}"
        $stage = "dist/$name"
        New-Item -ItemType Directory $stage | Out-Null
        $bin = if ($os -eq 'windows') { 'paris-traceroute.exe' } else { 'paris-traceroute' }
        $env:GOOS = $os; $env:GOARCH = $arch; $env:CGO_ENABLED = '0'
        go build -trimpath -ldflags "-s -w -X main.version=$Version" -o "$stage/$bin" ./cmd/paris-traceroute
        if ($LASTEXITCODE) { exit $LASTEXITCODE }
        Copy-Item README.md, LICENSE $stage
        if ($os -eq 'windows') {
            Compress-Archive -Path $stage -DestinationPath "dist/$name.zip"
        } else {
            tar -C dist -czf "dist/$name.tar.gz" $name
            if ($LASTEXITCODE) { exit $LASTEXITCODE }
        }
        Remove-Item -Recurse -Force $stage
        Write-Host "packed $name"
    }
} finally {
    $env:GOOS = $null; $env:GOARCH = $null; $env:CGO_ENABLED = $null
}
Get-ChildItem dist -Include *.zip, *.tar.gz -Recurse | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_ -Algorithm SHA256).Hash.ToLower(), $_.Name
} | Set-Content dist/checksums.txt
