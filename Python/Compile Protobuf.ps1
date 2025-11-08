# Get this script's path.
$scriptPath = Split-Path ($MyInvocation.MyCommand.Path)

# Define Temporary drive letter.
$driveLetter = "Z:"

# Map the drive if not already mapped.
if (-not (Get-PSDrive -Name $driveLetter.TrimEnd(':') -ErrorAction SilentlyContinue)) {
    net use $driveLetter $scriptPath
}

# Change directory to the mapped drive.
Set-Location (Join-Path $driveLetter "Documentation\Protobuf")

# Define proto files as an array.
$protoFiles = @(
    # Initial release.
    "tesla_api\protobuf\energy_device\v1\*.proto",
    "tesla_api\protobuf\signatures\*.proto",
    "tesla_api\protobuf\universal_message\v1\*.proto"
)

# Join the array into a single string.
$protoFileString = $protoFiles -join " "

# Clear screen.
cls

# Execute protoc.
Invoke-Expression "protoc --python_out=..\..\Python\src\ $protoFileString"

# Reset directory back to the mapped drive.
Set-Location (Join-Path $driveLetter "\")

# Pause.
#Read-Host