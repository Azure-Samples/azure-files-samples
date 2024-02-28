# Setup
$basePath = "X:\" 

for ($i = 1; $i -le 150; $i++) {
    $fileName = "test-$i.txt"
    $filePath = Join-Path -Path $basePath -ChildPath $fileName
    New-Item -ItemType File -Path $filePath -Force
}