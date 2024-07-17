$url = "http://192.168.250.146"
$file = "<Relative-path>\Testbed\client\examples\experiments_2\1.jpg"
$fileName = [System.IO.Path]::GetFileName($file)

# Request configuration
$headers = @{
    "X-File-Name" = $fileName
}

# Send the file to the server
$response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -InFile $file -UseBasicParsing

# Display the server response
$response
