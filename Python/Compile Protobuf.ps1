# Get this script's directory.
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Go one directory up.
$parentPath = Split-Path -Parent $scriptPath

# Define Temporary drive letter.
$driveLetter = "Z:"

# Map the drive if not already mapped.
if (-not (Get-PSDrive -Name $driveLetter.TrimEnd(':') -ErrorAction SilentlyContinue)) {
    net use $driveLetter $parentPath
}

# Define proto files as an array.
$protoFiles = @(
    # Initial release.
    "tesla_api\protobuf\energy\command\v1\*.proto",
    "tesla_api\protobuf\energy_device\v1\*.proto",
    "tesla_api\protobuf\signatures\*.proto",
    "tesla_api\protobuf\universal_message\v1\*.proto"
)

try {
    # Change to the target directory.
    Push-Location "$driveLetter\Documentation\Protobuf"

    # Clear screen.
    cls

    # Run protoc directly.
    & protoc --python_out=..\..\Python\src\ $protoFiles
}
finally {
    # Restore location.
    Pop-Location

    # Unmap drive.
    & net use $driveLetter /delete /y
}

# Pause.
#Read-Host