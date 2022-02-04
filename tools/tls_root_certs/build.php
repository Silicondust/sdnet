<?php

$key_types_valid = [];
$key_types_valid[] = 'RSA 2048 bits';
$key_types_valid[] = 'RSA 4096 bits';

$key_types_invalid = [];
$key_types_invalid[] = 'EC secp256r1';
$key_types_invalid[] = 'EC secp384r1';

function process_cert($csv_data)
{
	$name = $csv_data['Common Name or Certificate Name'];

	/* Check key type */
	global $key_types_valid;
	global $key_types_invalid;

	$key_type = $csv_data['Public Key Algorithm'];

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
	$cert_data = trim($csv_data['PEM Info'], "'") . "\n";
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

	$headers = fgetcsv($fp, 0, ',', '"');
	$field_count = count($headers);

	while (1) {
		$fields = fgetcsv($fp, 0, ',', '"');
		if (!$fields) {
			break;
		}

		if (count($fields) != $field_count) {
			error_log("ERROR: field count miss-match");
			continue;
		}

		$csv_data = array_combine($headers, $fields);

		process_cert($csv_data);
	}

	fclose($fp);
}

process();

?>
