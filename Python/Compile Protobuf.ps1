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
    "tesla_api\protobuf\energy_device\v1\authorized_client.proto",
    "tesla_api\protobuf\energy_device\v1\control_event_scheduling_info.proto",
    "tesla_api\protobuf\energy_device\v1\delivery_channel.proto",
    "tesla_api\protobuf\energy_device\v1\local_participant.proto",
    "tesla_api\protobuf\energy_device\v1\message_envelope.proto",
    "tesla_api\protobuf\energy_device\v1\participant.proto",
    "tesla_api\protobuf\energy_device\v1\teg_api_cancel_manual_backup_event_request.proto",
    "tesla_api\protobuf\energy_device\v1\teg_api_cancel_manual_backup_event_response.proto",
    "tesla_api\protobuf\energy_device\v1\teg_api_schedule_manual_backup_event_request.proto",
    "tesla_api\protobuf\energy_device\v1\teg_api_schedule_manual_backup_event_response.proto",
    "tesla_api\protobuf\energy_device\v1\teg_messages.proto",
    "tesla_api\protobuf\energy_device\v1\tesla_service.proto",
    "tesla_api\protobuf\signatures\aes_gcm_personalized_signature_data.proto",
    "tesla_api\protobuf\signatures\aes_gcm_response_signature_data.proto",
    "tesla_api\protobuf\signatures\hmac_personalized_signature_data.proto",
    "tesla_api\protobuf\signatures\hmac_signature_data.proto",
    "tesla_api\protobuf\signatures\key_identity.proto",
    "tesla_api\protobuf\signatures\signature_data.proto",
    "tesla_api\protobuf\universal_message\destination.proto",
    "tesla_api\protobuf\universal_message\domain.proto",
    "tesla_api\protobuf\universal_message\flags.proto",
    "tesla_api\protobuf\universal_message\message_fault_e.proto",
    "tesla_api\protobuf\universal_message\message_status.proto",
    "tesla_api\protobuf\universal_message\operation_status_e.proto",
    "tesla_api\protobuf\universal_message\routable_message.proto",
    "tesla_api\protobuf\universal_message\session_info_request.proto"

    #"tesla_api\protobuf\energy_device\v1\*.proto",
    #"tesla_api\protobuf\signatures\*.proto"
    #"tesla_api\protobuf\universal_message\*.proto",
)

# Join the array into a single string.
$protoFileString = $protoFiles -join " "

# Execute protoc.
Invoke-Expression "protoc --python_out=..\..\Python\src\ $protoFileString"

# Pause.
#Read-Host