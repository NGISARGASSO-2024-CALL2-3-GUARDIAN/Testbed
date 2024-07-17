$url = "http://192.168.250.146/1.jpg"
$fileName = [System.IO.Path]::GetFileName($url)
$outputFile = "C:\Users\user\Documents\downloads\$fileName"  

# Perform a GET request to obtain the image
$response = Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing

# Server response is showed
$response
