<?php
require_once __DIR__ . '/vendor/autoload.php';
$ga = new \GoogleAuthenticator\Main();
$secret = $ga->createSecret();
echo "Secret is: " . $secret . "\n\n";

$qrCodeUrl = $ga->getQRCodeGoogleUrl('Blog', $secret);
echo "Google Charts URL for the QR-Code: " . $qrCodeUrl . "\n\n";

$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

$checkResult = $ga->verifyCode($secret, $oneCode, 2);    // 2 = 2*30sec clock tolerance
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}