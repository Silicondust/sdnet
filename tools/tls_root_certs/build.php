<?php

/*
  [0]=>
  string(5) "Owner"
  [1]=>
  string(31) "Certificate Issuer Organization"
  [2]=>
  string(38) "Certificate Issuer Organizational Unit"
  [3]=>
  string(31) "Common Name or Certificate Name"
  [4]=>
  string(25) "Certificate Serial Number"
  [5]=>
  string(19) "SHA-256 Fingerprint"
  [6]=>
  string(21) "Subject + SPKI SHA256"
  [7]=>
  string(16) "Valid From [GMT]"
  [8]=>
  string(14) "Valid To [GMT]"
  [9]=>
  string(20) "Public Key Algorithm"
  [10]=>
  string(24) "Signature Hash Algorithm"
  [11]=>
  string(10) "Trust Bits"
  [12]=>
  string(16) "EV Policy OID(s)"
  [13]=>
  string(12) "Approval Bug"
  [14]=>
  string(31) "NSS Release When First Included"
  [15]=>
  string(35) "Firefox Release When First Included"
  [16]=>
  string(20) "Test Website - Valid"
  [17]=>
  string(22) "Test Website - Expired"
  [18]=>
  string(22) "Test Website - Revoked"
  [19]=>
  string(27) "Mozilla Applied Constraints"
  [20]=>
  string(15) "Company Website"
  [21]=>
  string(16) "Geographic Focus"
  [22]=>
  string(23) "Certificate Policy (CP)"
  [23]=>
  string(38) "Certification Practice Statement (CPS)"
  [24]=>
  string(14) "Standard Audit"
  [25]=>
  string(8) "BR Audit"
  [26]=>
  string(8) "EV Audit"
  [27]=>
  string(7) "Auditor"
  [28]=>
  string(19) "Standard Audit Type"
  [29]=>
  string(27) "Standard Audit Statement Dt"
  [30]=>
  string(8) "PEM Info"
*/

$key_types_valid = [];
$key_types_valid[] = 'RSA 2048 bits';
$key_types_valid[] = 'RSA 4096 bits';

$key_types_invalid = [];
$key_types_invalid[] = 'EC secp256r1';
$key_types_invalid[] = 'EC secp384r1';

function process_cert($csv_data)
{
	$name = $csv_data[3];

	/* Check key type */
	global $key_types_valid;
	global $key_types_invalid;

	$key_type = $csv_data[9];

	if (in_array($key_type, $key_types_invalid)) {
		printf("ignoring '%s' with key type '%s'\n", $name, $key_type);
		return;
	}

	if (!in_array($key_type, $key_types_valid)) {
		printf("unknown key type %s\n", $key_type);
		return;
	}

	/* Output cert file */
	$filename = $name . '.crt';
	$cert_data = trim($csv_data[30], "'") . "\n";
	file_put_contents($filename, $cert_data);

	/* Decode cert */
	$decode = [];
	exec(sprintf("openssl x509 -noout -text -in '%s'", $filename), $decode);

	$version_valid = false;
	$subject_key_identifier_valid = false;

	for ($i = 0; $i < count($decode); $i++) {
		$line = trim($decode[$i]);

		if ($line == 'Version: 3 (0x2)') {
			$version_valid = true;
			continue;
		}

		if ($line == 'X509v3 Subject Key Identifier:') {
			$subject_key_identifier = trim($decode[$i + 1]);
			$subject_key_identifier_valid = (strlen($subject_key_identifier) == 59);
			continue;
		}
	}

	if (!$version_valid) {
		printf("ignoring '%s' with unsupported version\n", $name);
		unlink($filename);
		return;
	}

	if (!$subject_key_identifier_valid) {
		printf("ignoring '%s' with unsupported subject key identifier length\n", $name);
		unlink($filename);
		return;
	}

	/* Append to public_root_certs */
	exec(sprintf("openssl x509 -outform der -in '%s' >>public_root_certs", $filename));
}

function process()
{
	unlink('public_root_certs');

	file_put_contents('public_root_certs.csv', fopen('https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV', 'r'));

	$fp = fopen('public_root_certs.csv', 'r');
	if (!$fp) {
		return;
	}

	fgetcsv($fp, 0, ',', '"');

	while (1) {
		$csv_data = fgetcsv($fp, 0, ',', '"');
		if (!$csv_data) {
			break;
		}

		process_cert($csv_data);
	}

	fclose($fp);
}

process();

?>
