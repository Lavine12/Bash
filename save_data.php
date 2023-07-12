<?php
// Retrieve the JSON data from the request
$requestPayload = file_get_contents('php://input');
$data = json_decode($requestPayload, true);

// Extract the form data
$formData = $data['data'];

// Save the form data to a text file
$fileName = 'form_data.txt';
$fileContent = $formData . "\n";

$fileHandle = fopen($fileName, 'a');
fwrite($fileHandle, $fileContent);
fclose($fileHandle);

// Send a response back to the client
$response = ['status' => 'success'];
header('Content-Type: application/json');
echo json_encode($response);

// Run the bash script
$scriptOutput = shell_exec('bash middleman.sh');
?>
