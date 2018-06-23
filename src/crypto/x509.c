/*
 * x509.c
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("x509");

#define X509_CURRENT_TIME_VALID 946684800

struct x509_certificate_t {
	struct slist_prefix_t slist_prefix;
	struct der_block_t top_level_block;
	struct der_block_t issuer_block;
	struct der_block_t subject_block;
	struct der_block_t validity_time_block;
	struct der_block_t public_key_block;
	struct der_block_t subject_alternative_name_block;
	struct der_block_t subject_key_identifier_block;
	struct der_block_t authority_key_identifier_block;
	struct der_block_t extended_key_usage_block;
	uint8_t *raw_data; /* NULL for no_copy mode */
	uint8_t version;
	bool key_usage_critical;
	uint32_t key_usage;
};

void x509_certificate_free(struct x509_certificate_t *cert)
{
	if (cert->raw_data) {
		heap_free(cert->raw_data);
	}

	heap_free(cert);
}

bool x509_certificate_verify_signature(struct x509_certificate_t *cert, struct rsa_key_t *key, bool block_weak_signatures)
{
	/* Copy block state for local iteration */
	struct der_block_t top_level_block = cert->top_level_block;

	uint8_t *certificate_block_raw = top_level_block.child_iterator_next;
	struct der_block_t certificate_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_SEQUENCE, &certificate_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t signature_type_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_SEQUENCE, &signature_type_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t signature_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_BIT_STRING, &signature_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	/* Check signature type */
	struct der_block_t signature_type_id_block;
	if (!der_child_iterator_next_and_verify_type(&signature_type_block, DER_TYPE_OBJECT_IDENTIFIER, &signature_type_id_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	char signature_type_id[64];
	if (!der_block_get_object_id(&signature_type_id_block, signature_type_id, signature_type_id + sizeof(signature_type_id))) {
		return false;
	}

	/* Signature */
	uint8_t *signature_ptr;
	uint8_t *signature_end;
	size_t signature_unused_bits;
	if (!der_block_get_bit_string(&signature_block, &signature_ptr, &signature_end, &signature_unused_bits)) {
		return false;
	}

	size_t signature_bit_len = (signature_end - signature_ptr) * 8 - signature_unused_bits;

	bool sha1 = false;
	bool sha256 = false;
	bool sha384 = false;
	bool sha512 = false;

	if (strcmp(signature_type_id, "1.2.840.113549.1.1.5") == 0) {
		/* RSA/PKCS1/SHA1 */
		if (block_weak_signatures) {
			DEBUG_WARN("ignoring weak signature");
			return false;
		}
		sha1 = true;
	} else if (strcmp(signature_type_id, "1.2.840.113549.1.1.11") == 0) {
		/* RSA/PKCS1/SHA256 */
		sha256 = true;
	} else if (strcmp(signature_type_id, "1.2.840.113549.1.1.12") == 0) {
		/* RSA/PKCS1/SHA384 */
		sha384 = true;
	} else if (strcmp(signature_type_id, "1.2.840.113549.1.1.13") == 0) {
		/* RSA/PKCS1/SHA512 */
		sha512 = true;
	} else {
		DEBUG_WARN("unsupported signature type %s", signature_type_id);
		return false;
	}

	uint8_t decoded_signature[4096 / 8];
	size_t decoded_signature_len = signature_bit_len / 8;

	/* Decrypt signature. */
	switch (signature_bit_len) {
	case 1024:
		if (block_weak_signatures) {
			DEBUG_WARN("ignoring weak signature");
			return false;
		}
		break;

	case 2048:
	case 4096:
		break;

	default:
		DEBUG_WARN("unexpected signature length");
		return false;
	}

	if (!rsa_exptmod_auto(signature_ptr, decoded_signature, decoded_signature_len, key)) {
		DEBUG_WARN("rsa_exptmod_auto failed");
		return false;
	}

	/* Verify hash */
	if (sha1) {
		sha1_digest_t data_hash;
		sha1_compute_digest(&data_hash, certificate_block_raw, certificate_block.end - certificate_block_raw);

		if (!pkcs1_v15_unpad_compare_sha1(&data_hash, decoded_signature, decoded_signature_len)) {
			DEBUG_WARN("signature does not match");
			return false;
		}

		return true;
	}

	if (sha256) {
		sha256_digest_t data_hash;
		sha256_compute_digest(&data_hash, certificate_block_raw, certificate_block.end - certificate_block_raw);

		if (!pkcs1_v15_unpad_compare_sha256(&data_hash, decoded_signature, decoded_signature_len)) {
			DEBUG_WARN("signature does not match");
			return false;
		}

		return true;
	}

	if (sha384) {
		sha384_digest_t data_hash;
		sha384_compute_digest(&data_hash, certificate_block_raw, certificate_block.end - certificate_block_raw);

		if (!pkcs1_v15_unpad_compare_sha384(&data_hash, decoded_signature, decoded_signature_len)) {
			DEBUG_WARN("signature does not match");
			return false;
		}

		return true;
	}

	if (sha512) {
		sha512_digest_t data_hash;
		sha512_compute_digest(&data_hash, certificate_block_raw, certificate_block.end - certificate_block_raw);

		if (!pkcs1_v15_unpad_compare_sha512(&data_hash, decoded_signature, decoded_signature_len)) {
			DEBUG_WARN("signature does not match");
			return false;
		}

		return true;
	}

	DEBUG_WARN("unsupported signature type %s", signature_type_id);
	return false;
}

bool x509_certificate_verify_validity_time(struct x509_certificate_t *cert, time64_t current_time)
{
	/* Copy block state for local iteration */
	struct der_block_t validity_time_block = cert->validity_time_block;

	struct der_block_t not_before_block;
	if (!der_child_iterator_next_and_verify_type(&validity_time_block, DER_TYPE_UTC_TIME, &not_before_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t not_after_block;
	if (!der_child_iterator_next_and_verify_type(&validity_time_block, DER_TYPE_UTC_TIME, &not_after_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	time64_t not_before_time;
	if (!der_block_get_utc_time(&not_before_block, &not_before_time)) {
		DEBUG_WARN("bad utc time");
		return false;
	}

	time64_t not_after_time;
	if (!der_block_get_utc_time(&not_after_block, &not_after_time)) {
		DEBUG_WARN("bad utc time");
		return false;
	}

	DEBUG_TRACE("x509_certificate_verify_validity_time: not before = %lld", not_before_time);
	DEBUG_TRACE("x509_certificate_verify_validity_time: not after = %lld", not_after_time);
	DEBUG_TRACE("x509_certificate_verify_validity_time: current = %lld", current_time);

	return (current_time >= not_before_time) && (current_time <= not_after_time);
}

time64_t x509_certificate_get_validity_time_not_before(struct x509_certificate_t *cert)
{
	/* Copy block state for local iteration */
	struct der_block_t validity_time_block = cert->validity_time_block;

	struct der_block_t not_before_block;
	if (!der_child_iterator_next_and_verify_type(&validity_time_block, DER_TYPE_UTC_TIME, &not_before_block)) {
		DEBUG_WARN("bad structure");
		return 0;
	}

	time64_t not_before_time;
	if (!der_block_get_utc_time(&not_before_block, &not_before_time)) {
		DEBUG_WARN("bad utc time");
		return 0;
	}

	return not_before_time;
}

time64_t x509_certificate_get_validity_time_not_after(struct x509_certificate_t *cert)
{
	/* Copy block state for local iteration */
	struct der_block_t validity_time_block = cert->validity_time_block;

	struct der_block_t not_before_block;
	if (!der_child_iterator_next_and_verify_type(&validity_time_block, DER_TYPE_UTC_TIME, &not_before_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t not_after_block;
	if (!der_child_iterator_next_and_verify_type(&validity_time_block, DER_TYPE_UTC_TIME, &not_after_block)) {
		DEBUG_WARN("bad structure");
		return 0;
	}

	time64_t not_after_time;
	if (!der_block_get_utc_time(&not_after_block, &not_after_time)) {
		DEBUG_WARN("bad utc time");
		return 0;
	}

	return not_after_time;
}

static bool x509_certificate_get_string(struct der_block_t *set_parent_block, char *id, char *buffer, char *end)
{
	/* Copy block state for local iteration */
	struct der_block_t set_parent_block_local = *set_parent_block;

	struct der_block_t object_block;
	if (!der_find_object_in_set(&set_parent_block_local, id, &object_block)) {
		return false;
	}

	if (!der_child_iterator_skip(&object_block, 1)) {
		return false;
	}

	struct der_block_t value_block;
	if (!der_child_iterator_next(&object_block, &value_block)) {
		return false;
	}
	
	return der_block_get_text_string(&value_block, buffer, end);
}

bool x509_certificate_get_subject_common_name(struct x509_certificate_t *cert, char *buffer, char *end)
{
	return x509_certificate_get_string(&cert->subject_block, "2.5.4.3", buffer, end);
}

bool x509_certificate_get_subject_organization(struct x509_certificate_t *cert, char *buffer, char *end)
{
	return x509_certificate_get_string(&cert->subject_block, "2.5.4.10", buffer, end);
}

bool x509_certificate_get_issuer_organization(struct x509_certificate_t *cert, char *buffer, char *end)
{
	return x509_certificate_get_string(&cert->issuer_block, "2.5.4.10", buffer, end);
}

bool x509_certificate_verify_subject_key_identifier(struct x509_certificate_t *cert, uint8_t identifier[20])
{
	if (cert->subject_key_identifier_block.type != DER_TYPE_OCTET_STRING) {
		return false;
	}

	uint8_t *ptr = cert->subject_key_identifier_block.payload;
	uint8_t *end = cert->subject_key_identifier_block.end;
	if (ptr + 20 != end) {
		DEBUG_WARN("bad identifier length");
		return false;
	}

	return memcmp(identifier, ptr, 20) == 0;
}

bool x509_certificate_get_authority_key_identifier(struct x509_certificate_t *cert, uint8_t identifier[20])
{
	if (cert->authority_key_identifier_block.type != DER_TYPE_SEQUENCE) {
		return false;
	}

	/* Copy block state for local iteration */
	struct der_block_t authority_key_identifier_block = cert->authority_key_identifier_block;

	struct der_block_t authority_key_identifier_data;
	if (!der_child_iterator_next_and_verify_type(&authority_key_identifier_block, DER_TYPE_80, &authority_key_identifier_data)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	uint8_t *ptr = authority_key_identifier_data.payload;
	uint8_t *end = authority_key_identifier_data.end;
	if (ptr + 20 != end) {
		DEBUG_WARN("bad identifier length");
		return false;
	}

	memcpy(identifier, ptr, 20);
	return true;
}

struct rsa_key_t *x509_certificate_get_public_key(struct x509_certificate_t *cert)
{
	/* Copy block state for local iteration */
	struct der_block_t public_key_block = cert->public_key_block;

	struct der_block_t key_type_block;
	if (!der_child_iterator_next_and_verify_type(&public_key_block, DER_TYPE_SEQUENCE, &key_type_block)) {
		DEBUG_WARN("bad structure");
		return NULL;
	}

	struct der_block_t key_type_id_block;
	if (!der_child_iterator_next_and_verify_type(&key_type_block, DER_TYPE_OBJECT_IDENTIFIER, &key_type_id_block)) {
		DEBUG_WARN("bad structure");
		return NULL;
	}

	if (!der_block_is_matching_object_id(&key_type_id_block, "1.2.840.113549.1.1.1")) {
		DEBUG_WARN("pubic key not rsa");
		return NULL;
	}

	struct der_block_t key_block;
	if (!der_child_iterator_next_and_verify_type(&public_key_block, DER_TYPE_BIT_STRING, &key_block)) {
		DEBUG_WARN("bad structure");
		return NULL;
	}

	uint8_t *key_data_ptr;
	uint8_t *key_data_end;
	size_t key_data_unused_bits;
	if (!der_block_get_bit_string(&key_block, &key_data_ptr, &key_data_end, &key_data_unused_bits)) {
		return NULL;
	}
	if (key_data_unused_bits != 0) {
		DEBUG_WARN("bad key length");
		return NULL;
	}

	return rsa_key_import_public(key_data_ptr, key_data_end - key_data_ptr);
}

bool x509_certificate_sha1_hash_signature_data(struct x509_certificate_t *cert, sha1_digest_t *digest)
{
	/* Copy block state for local iteration */
	struct der_block_t top_level_block = cert->top_level_block;

	if (!der_child_iterator_skip(&top_level_block, 2)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t signature_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_BIT_STRING, &signature_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	uint8_t *signature_ptr;
	uint8_t *signature_end;
	size_t signature_unused_bits;
	if (!der_block_get_bit_string(&signature_block, &signature_ptr, &signature_end, &signature_unused_bits)) {
		return false;
	}

	sha1_compute_digest(digest, signature_ptr, signature_end - signature_ptr);
	return true;
}

bool x509_certificate_is_key_usage_critical(struct x509_certificate_t *cert)
{
	return cert->key_usage_critical;
}

bool x509_certificate_is_usable_for_digital_signature(struct x509_certificate_t *cert)
{
	return (cert->key_usage & (1 << 0)) != 0;
}

bool x509_certificate_is_usable_for_key_encipherment(struct x509_certificate_t *cert)
{
	return (cert->key_usage & (1 << 2)) != 0;
}

bool x509_certificate_is_usable_for_certificate_signing(struct x509_certificate_t *cert)
{
	return (cert->key_usage & (1 << 5)) != 0;
}

static bool x509_certificate_is_usable_for_extended(struct x509_certificate_t *cert, char *id)
{
	if (!cert->extended_key_usage_block.payload) {
		return false;
	}

	/* Copy block state for local iteration */
	struct der_block_t extended_key_usage_block = cert->extended_key_usage_block;

	while (1) {
		struct der_block_t object_id_block;
		if (!der_child_iterator_next(&extended_key_usage_block, &object_id_block)) {
			return false;
		}

		if (object_id_block.type != DER_TYPE_OBJECT_IDENTIFIER) {
			DEBUG_WARN("bad structure");
			return false;
		}

		if (der_block_is_matching_object_id(&object_id_block, id)) {
			return true;
		}
	}
}

bool x509_certificate_is_usable_for_tls_web_server_authentication(struct x509_certificate_t *cert)
{
	return x509_certificate_is_usable_for_extended(cert, "1.3.6.1.5.5.7.3.1");
}

bool x509_certificate_is_usable_for_tls_web_client_authentication(struct x509_certificate_t *cert)
{
	return x509_certificate_is_usable_for_extended(cert, "1.3.6.1.5.5.7.3.2");
}

bool x509_certificate_is_usable_for_code_signing(struct x509_certificate_t *cert)
{
	return x509_certificate_is_usable_for_extended(cert, "1.3.6.1.5.5.7.3.3");
}

bool x509_certificate_is_valid_for_dns_name(struct x509_certificate_t *cert, const char *dns_name)
{
	const char *wildcard_name = strchr(dns_name, '.');
	if (!wildcard_name) {
		return false;
	}

	/* Check against common name */
	char common_name[256];
	if (!x509_certificate_get_subject_common_name(cert, common_name, common_name + sizeof(common_name))) {
		return false;
	}

	if (common_name[0] == '*') {
		if (strcmp(wildcard_name, common_name + 1) == 0) {
			return true;
		}
	} else {
		if (strcmp(dns_name, common_name) == 0) {
			return true;
		}
	}

	/* Check against alternative names */
	if (cert->subject_alternative_name_block.type != DER_TYPE_SEQUENCE) {
		return false;
	}

	struct der_block_t subject_alternative_name_block_local = cert->subject_alternative_name_block;
	size_t dns_name_len = strlen(dns_name);
	size_t wildcard_name_len = strlen(wildcard_name);

	while (1) {
		struct der_block_t value_block;
		if (!der_child_iterator_next_and_verify_type(&subject_alternative_name_block_local, DER_TYPE_CHOICE, &value_block)) {
			return false;
		}

		size_t len = value_block.end - value_block.payload;
		if (len == 0) {
			continue;
		}

		char *value = (char *)value_block.payload;

		if (value[0] == '*') {
			value++;
			len--;

			if (wildcard_name_len != len) {
				continue;
			}

			if (memcmp(wildcard_name, value, len) != 0) {
				continue;
			}

			return true;
		}

		if (dns_name_len != len) {
			continue;
		}

		if (memcmp(dns_name, value, len) != 0) {
			continue;
		}

		return true;
	}
}

static bool x509_cetificate_import_decode_version(struct x509_certificate_t *cert, struct der_block_t *version_block)
{
	struct der_block_t version_int_block;
	if (!der_child_iterator_next_and_verify_type(version_block, DER_TYPE_INTEGER, &version_int_block)) {
		return false;
	}

	int32_t version_int;
	if (!der_block_get_integer_int32(&version_int_block, &version_int)) {
		return false;
	}

	cert->version = (uint8_t)version_int + 1;
	if (cert->version < 3) {
		return false;
	}

	return true;
}

static bool x509_certificate_import_key_usage(struct x509_certificate_t *cert, struct der_block_t *extension_payload_block)
{
	uint8_t *ptr;
	uint8_t *end;
	if (!der_block_get_octet_string(extension_payload_block, &ptr, &end)) {
		return false;
	}

	struct der_block_t key_usage_block;
	if (!der_block_init(&key_usage_block, ptr, end)) {
		return false;
	}

	if (key_usage_block.type != DER_TYPE_BIT_STRING) {
		return false;
	}

	size_t unused_bits;
	if (!der_block_get_bit_string(&key_usage_block, &ptr, &end, &unused_bits)) {
		return false;
	}

	uint32_t key_usage_bit = 1;
	while (ptr < end) {
		uint8_t c = *ptr++;
		for (int i = 0; i < 8; i++) {
			if (c & 0x80) {
				cert->key_usage |= key_usage_bit;
			}

			c <<= 1;
			key_usage_bit <<= 1;
		}
	}

	return true;
}

static bool x509_certificate_import_extensions_octect_string_containing_der_verify_type(struct x509_certificate_t *cert, struct der_block_t *extension_payload_block, struct der_block_t *output_block, uint8_t type)
{
	uint8_t *ptr;
	uint8_t *end;
	if (!der_block_get_octet_string(extension_payload_block, &ptr, &end)) {
		DEBUG_WARN("not octet string");
		return false;
	}

	if (!der_block_init(output_block, ptr, end)) {
		return false;
	}

	if (output_block->type != type) {
		DEBUG_WARN("not expected type");
		return false;
	}

	return true;
}

static bool x509_certificate_import_extensions(struct x509_certificate_t *cert, struct der_block_t *optional_block)
{
	struct der_block_t extensions_block;
	if (!der_child_iterator_next_and_verify_type(optional_block, DER_TYPE_SEQUENCE, &extensions_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	while (1) {
		struct der_block_t extension_block;
		if (!der_child_iterator_next(&extensions_block, &extension_block)) {
			break;
		}

		if (extension_block.type != DER_TYPE_SEQUENCE) {
			DEBUG_WARN("bad structure");
			return false;
		}

		struct der_block_t object_id_block;
		if (!der_child_iterator_next_and_verify_type(&extension_block, DER_TYPE_OBJECT_IDENTIFIER, &object_id_block)) {
			DEBUG_WARN("bad structure");
			return false;
		}

		char object_id[64];
		if (!der_block_get_object_id(&object_id_block, object_id, object_id + sizeof(object_id))) {
			return false;
		}
		
		struct der_block_t extension_payload_block;
		if (!der_child_iterator_next(&extension_block, &extension_payload_block)) {
			return false;
		}

		bool critical = false;
		if (extension_payload_block.type == DER_TYPE_BOOLEAN) {
			if (!der_block_get_boolean(&extension_payload_block, &critical)) {
				return false;
			}

			if (!der_child_iterator_next(&extension_block, &extension_payload_block)) {
				return false;
			}
		}

		if (extension_payload_block.type != DER_TYPE_OCTET_STRING) {
			DEBUG_WARN("bad structure");
			return false;
		}

		if (strcmp(object_id, "2.5.29.14") == 0) {
			/* Subject Key Identifier */
			if (!x509_certificate_import_extensions_octect_string_containing_der_verify_type(cert, &extension_payload_block, &cert->subject_key_identifier_block, DER_TYPE_OCTET_STRING)) {
				return false;
			}
			continue;
		}

		if (strcmp(object_id, "2.5.29.15") == 0) {
			/* Key Usage */
			cert->key_usage_critical = critical;
			if (!x509_certificate_import_key_usage(cert, &extension_payload_block)) {
				return false;
			}
			continue;
		}

		if (strcmp(object_id, "2.5.29.17") == 0) {
			/* Subject Alternative Name */
			if (!x509_certificate_import_extensions_octect_string_containing_der_verify_type(cert, &extension_payload_block, &cert->subject_alternative_name_block, DER_TYPE_SEQUENCE)) {
				return false;
			}
			continue;
		}

		if (strcmp(object_id, "2.5.29.19") == 0) {
			/* Basic Constraints */
			continue;
		}

		if (strcmp(object_id, "2.5.29.35") == 0) {
			/* Authroity Key Identifier */
			if (!x509_certificate_import_extensions_octect_string_containing_der_verify_type(cert, &extension_payload_block, &cert->authority_key_identifier_block, DER_TYPE_SEQUENCE)) {
				return false;
			}
			continue;
		}

		if (strcmp(object_id, "2.5.29.37") == 0) {
			/* Extended Key Usage */
			if (!x509_certificate_import_extensions_octect_string_containing_der_verify_type(cert, &extension_payload_block, &cert->extended_key_usage_block, DER_TYPE_SEQUENCE)) {
				return false;
			}
			continue;
		}

		if (critical) {
			DEBUG_WARN("critical extension not supported: %s", object_id);
			return false;
		}

		DEBUG_TRACE("extension not supported: %s", object_id);
	}

	return true;
}

static bool x509_certificate_import_internal(struct x509_certificate_t *cert)
{
	/* Copy block state for local iteration */
	struct der_block_t top_level_block = cert->top_level_block;

	if (top_level_block.type != DER_TYPE_SEQUENCE) {
		DEBUG_WARN("bad structure");
		return false;
	}
	
	struct der_block_t certificate_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_SEQUENCE, &certificate_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t signature_type_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_SEQUENCE, &signature_type_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t signature_block;
	if (!der_child_iterator_next_and_verify_type(&top_level_block, DER_TYPE_BIT_STRING, &signature_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	struct der_block_t version_block;
	if (!der_child_iterator_next_and_verify_type(&certificate_block, DER_TYPE_A0, &version_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}
	if (!x509_cetificate_import_decode_version(cert, &version_block)) {
		return false;
	}

	if (!der_child_iterator_skip(&certificate_block, 2)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	if (!der_child_iterator_next_and_verify_type(&certificate_block, DER_TYPE_SEQUENCE, &cert->issuer_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}
	if (!der_child_iterator_next_and_verify_type(&certificate_block, DER_TYPE_SEQUENCE, &cert->validity_time_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}
	if (!der_child_iterator_next_and_verify_type(&certificate_block, DER_TYPE_SEQUENCE, &cert->subject_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}
	if (!der_child_iterator_next_and_verify_type(&certificate_block, DER_TYPE_SEQUENCE, &cert->public_key_block)) {
		DEBUG_WARN("bad structure");
		return false;
	}

	while (1) {
		struct der_block_t optional_block;
		if (!der_child_iterator_next(&certificate_block, &optional_block)) {
			break;
		}

		if (optional_block.type == DER_TYPE_A3) {
			if (!x509_certificate_import_extensions(cert, &optional_block)) {
				return false;
			}
		}
	}

	return true;
}

struct x509_certificate_t *x509_certificate_import(uint8_t *data, size_t length)
{
	length = x509_certificate_import_length(data, length);
	if (length == 0) {
		return NULL;
	}

	struct x509_certificate_t *cert = (struct x509_certificate_t *)heap_alloc_and_zero(sizeof(struct x509_certificate_t), PKG_OS, MEM_TYPE_OS_X509_CERTIFICATE);
	if (!cert) {
		return NULL;
	}

	cert->raw_data = (uint8_t *)heap_alloc(length, PKG_OS, MEM_TYPE_OS_X509_CERTIFICATE);
	if (!cert->raw_data) {
		heap_free(cert);
		return NULL;
	}

	memcpy(cert->raw_data, data, length);

	if (!der_block_init(&cert->top_level_block, cert->raw_data, cert->raw_data + length)) {
		x509_certificate_free(cert);
		return NULL;
	}

	if (!x509_certificate_import_internal(cert)) {
		x509_certificate_free(cert);
		return NULL;
	}

	return cert;
}

struct x509_certificate_t *x509_certificate_import_no_copy(uint8_t *data, size_t length)
{
	length = x509_certificate_import_length(data, length);
	if (length == 0) {
		return NULL;
	}
		
	struct x509_certificate_t *cert = (struct x509_certificate_t *)heap_alloc_and_zero(sizeof(struct x509_certificate_t), PKG_OS, MEM_TYPE_OS_X509_CERTIFICATE);
	if (!cert) {
		return NULL;
	}

	if (!der_block_init(&cert->top_level_block, data, data + length)) {
		x509_certificate_free(cert);
		return NULL;
	}

	if (!x509_certificate_import_internal(cert)) {
		x509_certificate_free(cert);
		return NULL;
	}

	return cert;
}

struct x509_certificate_t *x509_certificate_import_netbuf(struct netbuf *nb, size_t length)
{
#if defined(IPOS)
	size_t cert_length = x509_certificate_import_length_netbuf(nb, length);
	if (cert_length == 0) {
		return NULL;
	}

	uint8_t *data = (uint8_t *)heap_alloc(cert_length, PKG_OS, MEM_TYPE_OS_X509_CERTIFICATE);
	if (!data) {
		return NULL;
	}

	netbuf_fwd_read(nb, data, cert_length);

	struct x509_certificate_t *cert = x509_certificate_import_no_copy(data, cert_length);
	if (!cert) {
		heap_free(data);
		return NULL;
	}

	cert->raw_data = data;
	return cert;
#else
	uint8_t *data = netbuf_get_ptr(nb);
	return x509_certificate_import(data, length);
#endif
}

size_t x509_certificate_import_length(uint8_t *data, size_t length)
{
	struct der_block_t pre_test_block;
	if (!der_block_init(&pre_test_block, data, data + length)) {
		return 0;
	}

	if (pre_test_block.type != DER_TYPE_SEQUENCE) {
		return 0;
	}

	size_t cert_length = pre_test_block.end - data;
	if (cert_length > length) {
		return 0;
	}

	return cert_length;
}

size_t x509_certificate_import_length_netbuf(struct netbuf *nb, size_t length)
{
#if defined(IPOS)
	addr_t bookmark = netbuf_get_pos(nb);

	if (!netbuf_fwd_check_space(nb, 4)) {
		return 0;
	}

	if (netbuf_fwd_read_u8(nb) != 0x30) {
		netbuf_set_pos(nb, bookmark);
		return 0;
	}

	if (netbuf_fwd_read_u8(nb) != 0x82) {
		netbuf_set_pos(nb, bookmark);
		return 0;
	}

	size_t cert_length = netbuf_fwd_read_u16(nb) + 4;
	netbuf_set_pos(nb, bookmark);

	if (cert_length > length) {
		return 0;
	}

	if (!netbuf_fwd_check_space(nb, cert_length)) {
		return 0;
	}

	return cert_length;
#else
	uint8_t *data = netbuf_get_ptr(nb);
	return x509_certificate_import_length(data, length);
#endif
}

bool x509_chain_verify(struct slist_t *chain, struct slist_t *root_certs, bool block_weak_signatures)
{
	struct x509_certificate_t *child_cert = slist_get_head(struct x509_certificate_t, chain);
	if (!child_cert) {
		DEBUG_WARN("no certificates");
		return false;
	}

	if (RUNTIME_DEBUG) {
		char common_name[128];
		x509_certificate_get_subject_common_name(child_cert, common_name, common_name + sizeof(common_name));
		DEBUG_TRACE("server CN = %s", common_name);
	}

	time64_t current_time = unix_time();
	if (current_time >= X509_CURRENT_TIME_VALID) {
		if (!x509_certificate_verify_validity_time(child_cert, current_time)) {
			DEBUG_WARN("certificate has expired");
			return false;
		}
	}

	while (1) {
		uint8_t child_authority_key_identifier[20];
		if (!x509_certificate_get_authority_key_identifier(child_cert, child_authority_key_identifier)) {
			DEBUG_WARN("child does not have an authority_key_identifier");
			return false;
		}

		struct x509_certificate_t *root_cert = slist_get_head(struct x509_certificate_t, root_certs);
		while (root_cert) {
			if (!x509_certificate_verify_subject_key_identifier(root_cert, child_authority_key_identifier)) {
				root_cert = slist_get_next(struct x509_certificate_t, root_cert);
				continue;
			}

			if (RUNTIME_DEBUG) {
				char common_name[128];
				x509_certificate_get_subject_common_name(root_cert, common_name, common_name + sizeof(common_name));
				DEBUG_TRACE("root CN = %s", common_name);
			}

			if (current_time >= X509_CURRENT_TIME_VALID) {
				if (!x509_certificate_verify_validity_time(root_cert, current_time)) {
					DEBUG_WARN("root certificate has expired");
					return false;
				}
			}

			if (!x509_certificate_is_usable_for_certificate_signing(root_cert)) {
				DEBUG_WARN("root cert not valid for certificate signing");
				return false;
			}

			struct rsa_key_t *root_public_key = x509_certificate_get_public_key(root_cert);
			if (!root_public_key) {
				DEBUG_WARN("rsa import failed");
				return false;
			}

			if (!x509_certificate_verify_signature(child_cert, root_public_key, block_weak_signatures)) {
				rsa_key_free(root_public_key);
				return false;
			}

			rsa_key_free(root_public_key);
			return true;
		}

		struct x509_certificate_t *parent_cert = slist_get_next(struct x509_certificate_t, child_cert);
		if (!parent_cert) {
			DEBUG_WARN("no root cert match");
			return false;
		}

		if (RUNTIME_DEBUG) {
			char common_name[128];
			x509_certificate_get_subject_common_name(parent_cert, common_name, common_name + sizeof(common_name));
			DEBUG_TRACE("intermediate CN = %s", common_name);
		}

		if (!x509_certificate_verify_subject_key_identifier(parent_cert, child_authority_key_identifier)) {
			DEBUG_WARN("child authority_key_identifier does not match parent subject_key_identifier");
			return false;
		}

		if (current_time >= X509_CURRENT_TIME_VALID) {
			if (!x509_certificate_verify_validity_time(parent_cert, current_time)) {
				DEBUG_WARN("certificate has expired");
				return false;
			}
		}

		if (!x509_certificate_is_usable_for_certificate_signing(parent_cert)) {
			DEBUG_WARN("cert not valid for certificate signing");
			return false;
		}

		struct rsa_key_t *parent_public_key = x509_certificate_get_public_key(parent_cert);
		if (!parent_public_key) {
			DEBUG_WARN("rsa import failed");
			return false;
		}

		if (!x509_certificate_verify_signature(child_cert, parent_public_key, block_weak_signatures)) {
			rsa_key_free(parent_public_key);
			return false;
		}
		
		rsa_key_free(parent_public_key);
		child_cert = parent_cert;
	}
}

#if defined(DEBUG)
static uint8_t x509_test_upstream_public_key[] = {
	0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xaf, 0xac, 0x90, 0x9c, 0x99, 0x0c, 0x4a, 0xb8, 0x19, 0x68, 0x9d, 0x87, 0x8a, 0x89, 0x53,
	0x3c, 0xc8, 0xfa, 0xd0, 0x06, 0xef, 0xc3, 0x46, 0x09, 0x39, 0x23, 0x3d, 0x0c, 0x19, 0x4b, 0x68,
	0xa6, 0x5e, 0x54, 0x3b, 0x15, 0x1c, 0x2a, 0x1b, 0x23, 0x73, 0x62, 0x4a, 0x51, 0xb8, 0x50, 0xd9,
	0x33, 0x85, 0xd8, 0xbb, 0xf3, 0xfc, 0xed, 0xc6, 0x7a, 0x8d, 0xed, 0xc9, 0x49, 0xf6, 0x70, 0xc9,
	0xac, 0xa1, 0x5d, 0x82, 0xfa, 0xb4, 0x12, 0xca, 0x4b, 0xd2, 0x4c, 0xb8, 0xad, 0xb7, 0x30, 0x1f,
	0x0f, 0x5a, 0xf3, 0x1d, 0xaf, 0x52, 0xa8, 0x8c, 0x75, 0x83, 0x9b, 0xdd, 0x4a, 0x5b, 0x77, 0xc2,
	0x28, 0x12, 0x8b, 0x5e, 0x40, 0x9b, 0x81, 0xa4, 0x35, 0x20, 0x2c, 0xf2, 0xde, 0x88, 0xf5, 0xe1,
	0x44, 0xda, 0xd9, 0x67, 0xa4, 0xb4, 0x9f, 0x70, 0x0b, 0x07, 0x41, 0xf4, 0xd6, 0x94, 0x18, 0x46,
	0x28, 0x6c, 0xb8, 0xc4, 0x31, 0x20, 0x71, 0x50, 0xd2, 0xd9, 0xa6, 0x21, 0x86, 0xdf, 0x62, 0x88,
	0x58, 0x08, 0x29, 0x1c, 0x34, 0x28, 0x77, 0x0f, 0xe5, 0xfe, 0xf0, 0xc4, 0x1d, 0xc6, 0x22, 0xc8,
	0xc2, 0x90, 0x20, 0x8e, 0x1f, 0x7a, 0xa8, 0xd3, 0xe1, 0xd5, 0x84, 0x2e, 0x3d, 0x5b, 0x18, 0xc2,
	0x79, 0x16, 0x08, 0x0e, 0x7c, 0xaa, 0x7c, 0x53, 0x12, 0xce, 0xa1, 0x40, 0x7c, 0x19, 0xc7, 0x38,
	0x95, 0xb7, 0x6a, 0xc6, 0xfa, 0xf8, 0x1a, 0xc6, 0xbb, 0xb2, 0xe8, 0xd4, 0xab, 0xe6, 0x87, 0x89,
	0xd7, 0x13, 0x66, 0x98, 0x17, 0x83, 0xc0, 0x65, 0x3f, 0xda, 0x65, 0x59, 0x69, 0x83, 0x45, 0xcc,
	0x28, 0x22, 0xea, 0xd1, 0x8a, 0x18, 0x03, 0x4d, 0xc3, 0x72, 0xfd, 0x7d, 0x97, 0xc7, 0xf1, 0xb3,
	0xa4, 0x83, 0xe9, 0x6a, 0x3c, 0x59, 0xd9, 0x55, 0xf0, 0x8c, 0x96, 0xb8, 0x0f, 0x65, 0xf4, 0xfb,
	0x39, 0x02, 0x03, 0x01, 0x00, 0x01
};

static uint8_t x509_test_cert[] = {
	0x30, 0x82, 0x03, 0x92, 0x30, 0x82, 0x02, 0x7a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x33, 0x15, 0x4a, 0x68, 0xd6, 0x85, 0x1a, 0x92, 0xde, 0x1f, 0x63, 0x3d, 0x17, 0x2f, 0xad, 0x84, 0x30,
	0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x82, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x18,
	0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0f, 0x43, 0x61, 0x62, 0x6c, 0x65, 0x4c, 0x61, 0x62, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
	0x08, 0x13, 0x08, 0x43, 0x6f, 0x6c, 0x6f, 0x72, 0x61, 0x64, 0x6f, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0a, 0x4c, 0x6f, 0x75, 0x69, 0x73, 0x76, 0x69, 0x6c, 0x6c, 0x65,
	0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x07, 0x43, 0x41, 0x30, 0x30, 0x30, 0x30, 0x37, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x16, 0x43, 0x61, 0x62,
	0x6c, 0x65, 0x4c, 0x61, 0x62, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x20, 0x4d, 0x66, 0x67, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x31, 0x30, 0x31, 0x31, 0x38, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x34, 0x31, 0x30, 0x31, 0x31, 0x36, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0xd5, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13,
	0x03, 0x30, 0x36, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x14, 0x53, 0x69, 0x6c, 0x69,
	0x63, 0x6f, 0x6e, 0x64, 0x75, 0x73, 0x74, 0x20, 0x55, 0x53, 0x41, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66,
	0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09, 0x4c, 0x69, 0x76, 0x65, 0x72, 0x6d, 0x6f, 0x72, 0x65, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
	0x04, 0x0b, 0x13, 0x09, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x61, 0x62, 0x6c, 0x65, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x05, 0x4f, 0x43, 0x43, 0x55, 0x52, 0x31, 0x1e, 0x30,
	0x1c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x15, 0x48, 0x44, 0x48, 0x6f, 0x6d, 0x65, 0x52, 0x75, 0x6e, 0x20, 0x50, 0x72, 0x69, 0x6d, 0x65, 0x20, 0x54, 0x75, 0x6e, 0x65, 0x72, 0x31, 0x17, 0x30,
	0x15, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x0e, 0x53, 0x69, 0x6c, 0x69, 0x63, 0x6f, 0x6e, 0x64, 0x75, 0x73, 0x74, 0x20, 0x48, 0x51, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
	0x0a, 0x31, 0x30, 0x31, 0x33, 0x31, 0x30, 0x30, 0x30, 0x30, 0x33, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d,
	0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xd6, 0xf5, 0x2c, 0xf9, 0xb5, 0xc5, 0xe4, 0x7a, 0x75, 0xe7, 0x53, 0x12, 0x41, 0x30, 0xbe, 0x78, 0x27, 0xa1, 0x9f, 0x0b, 0xb6, 0xce, 0x18, 0xed,
	0x58, 0x99, 0x0d, 0x15, 0x4e, 0x43, 0x92, 0x48, 0x59, 0x39, 0xe0, 0x04, 0x91, 0x7b, 0x68, 0x35, 0x03, 0x0d, 0x24, 0x88, 0x49, 0x9d, 0xb7, 0x27, 0x0c, 0x3e, 0x57, 0xcd, 0x12, 0xa6, 0xbb, 0x01,
	0x4c, 0xca, 0x07, 0x05, 0x75, 0x43, 0xe4, 0xe6, 0x7a, 0xb8, 0x4e, 0x44, 0xba, 0xeb, 0xb1, 0x0b, 0x63, 0xae, 0x7b, 0x0d, 0x6b, 0x59, 0x5e, 0x98, 0x86, 0x9a, 0x5a, 0xce, 0x81, 0x7a, 0xe5, 0xc3,
	0x37, 0x4f, 0xbd, 0x85, 0x8c, 0x67, 0xe6, 0x54, 0xc1, 0x9b, 0xe4, 0x36, 0x57, 0xbe, 0xe2, 0x9e, 0xc7, 0xc2, 0xe7, 0xcb, 0x5e, 0x49, 0x70, 0x40, 0x57, 0xa8, 0x19, 0xd7, 0xfe, 0x5a, 0x5b, 0x1f,
	0x17, 0xc4, 0xb4, 0x17, 0x3c, 0x14, 0x73, 0x7d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x33, 0x30, 0x31, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05,
	0xa0, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x81, 0x6b, 0x11, 0x7f, 0x50, 0xf6, 0x17, 0x0b, 0x8c, 0x85, 0xb0, 0x14, 0x69, 0xa6, 0xe6, 0xcc, 0x12, 0x76,
	0x0d, 0xfb, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x6c, 0xc0, 0x50, 0x75, 0x55, 0xf4, 0xd5, 0x4c, 0xf1, 0xed,
	0x6e, 0xb0, 0x4a, 0x78, 0x3c, 0x8d, 0x30, 0xc6, 0xdd, 0xe7, 0x18, 0x42, 0xd9, 0x21, 0x04, 0x1d, 0xb8, 0x84, 0xbc, 0xf3, 0x55, 0xd9, 0xca, 0x7f, 0xc3, 0x57, 0xa5, 0x6b, 0xaf, 0x78, 0xa9, 0x30,
	0x98, 0xe4, 0x19, 0xc1, 0x46, 0x59, 0x52, 0x5c, 0x4c, 0x5d, 0x7d, 0x5f, 0x25, 0xbc, 0x30, 0x58, 0x88, 0xe6, 0xb5, 0x34, 0xf4, 0x4d, 0x17, 0xa7, 0xe4, 0x42, 0xd2, 0x3f, 0xac, 0x3e, 0x70, 0xa3,
	0x77, 0xad, 0x87, 0x1b, 0x2d, 0x85, 0xb5, 0x6e, 0xd3, 0x8d, 0x31, 0x37, 0xf5, 0x18, 0xed, 0x21, 0xee, 0x5f, 0x87, 0x9c, 0x2c, 0xa5, 0x9c, 0xa5, 0x98, 0xea, 0xf7, 0x4f, 0xd6, 0x3a, 0xe1, 0x73,
	0x3d, 0x4e, 0x07, 0x9e, 0xd0, 0xfb, 0xed, 0x86, 0x8a, 0xdf, 0x61, 0x69, 0x0b, 0x98, 0x96, 0xb9, 0xc3, 0x40, 0x50, 0x0c, 0xea, 0x83, 0x5e, 0xfd, 0xd2, 0x69, 0x9b, 0x45, 0xf9, 0xe6, 0x17, 0x9d,
	0x40, 0xab, 0xba, 0x95, 0x58, 0xde, 0x29, 0x2d, 0xb8, 0x08, 0x57, 0xb6, 0x45, 0xe5, 0x2a, 0x84, 0x84, 0x24, 0xad, 0xe8, 0x41, 0xb1, 0x28, 0x58, 0x23, 0x48, 0x3e, 0xa0, 0xac, 0xc6, 0xa9, 0x02,
	0x1f, 0x05, 0xf1, 0x53, 0x44, 0xf0, 0x0c, 0xa0, 0x97, 0x40, 0xac, 0x19, 0x38, 0x82, 0x3f, 0xc3, 0x5f, 0x86, 0x23, 0x61, 0x78, 0xd1, 0x2b, 0x60, 0x4f, 0x64, 0x46, 0xe3, 0x4a, 0xf3, 0xdd, 0x77,
	0x98, 0xf7, 0x0d, 0x8e, 0x8e, 0xf6, 0xff, 0x16, 0x75, 0x85, 0xc8, 0xcf, 0x1a, 0x37, 0x73, 0x9e, 0xa2, 0x56, 0xea, 0xc1, 0x39, 0x47, 0xec, 0xce, 0xa4, 0xb8, 0x21, 0x87, 0xb3, 0x33, 0xe7, 0xd8,
	0x23, 0xe7, 0xac, 0x43, 0xa8, 0xae, 0x7a, 0x38, 0x97, 0x2f, 0xcb, 0x6c, 0x24, 0xbd, 0x83, 0x51, 0xc1, 0xc6, 0x92, 0x85, 0x76, 0xc6
};

static uint8_t x509_test_cert2[] = {
	0x30, 0x82, 0x03, 0x52, 0x30, 0x82, 0x02, 0x3a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xb5, 0x6c, 0xad, 0x77, 0x45, 0x63, 0xdd, 0x12, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
	0x0b, 0x53, 0x69, 0x6c, 0x69, 0x63, 0x6f, 0x6e, 0x64, 0x75, 0x73, 0x74, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1b, 0x53, 0x69, 0x6c, 0x69, 0x63, 0x6f, 0x6e, 0x64, 0x75,
	0x73, 0x74, 0x20, 0x41, 0x6c, 0x74, 0x20, 0x43, 0x56, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x30, 0x31, 0x31, 0x31, 0x33, 0x31, 0x36, 0x35, 0x30,
	0x30, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x30, 0x31, 0x31, 0x31, 0x30, 0x31, 0x36, 0x35, 0x30, 0x30, 0x36, 0x5a, 0x30, 0x6f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
	0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
	0x09, 0x4c, 0x69, 0x76, 0x65, 0x72, 0x6d, 0x6f, 0x72, 0x65, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x53, 0x69, 0x6c, 0x69, 0x63, 0x6f, 0x6e, 0x64, 0x75, 0x73, 0x74,
	0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x18, 0x53, 0x69, 0x6c, 0x69, 0x63, 0x6f, 0x6e, 0x64, 0x75, 0x73, 0x74, 0x20, 0x4f, 0x43, 0x55, 0x52, 0x20, 0x41, 0x6c, 0x74, 0x20,
	0x43, 0x56, 0x43, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
	0x82, 0x01, 0x01, 0x00, 0xce, 0xa1, 0xc5, 0x54, 0x95, 0xeb, 0xec, 0x64, 0x07, 0x65, 0x8d, 0xb5, 0x12, 0xf7, 0xc0, 0x4d, 0xfe, 0x67, 0xa8, 0x61, 0x73, 0xf8, 0xf0, 0xa2, 0x61, 0x05, 0x9d, 0xc8,
	0x62, 0x4c, 0xcb, 0xef, 0xd9, 0xf0, 0x8f, 0x1c, 0x5d, 0x66, 0x05, 0x90, 0x48, 0x73, 0x34, 0x7b, 0x0a, 0xcf, 0x9d, 0x88, 0x67, 0x4f, 0x7e, 0x71, 0x93, 0xa9, 0x63, 0xe5, 0x0c, 0x68, 0xb2, 0xfd,
	0x3a, 0x6c, 0x39, 0x60, 0xfd, 0xfa, 0x35, 0x47, 0x17, 0x0e, 0xf1, 0x36, 0x9c, 0xdb, 0x0b, 0x38, 0x12, 0xc1, 0x4a, 0xd2, 0x35, 0x46, 0xf5, 0x59, 0x59, 0x19, 0x25, 0xf2, 0x15, 0xf8, 0x70, 0x3b,
	0x86, 0xb9, 0x2e, 0x04, 0x26, 0x2f, 0x1d, 0x9f, 0x78, 0x31, 0xb5, 0xed, 0x78, 0x89, 0x49, 0x83, 0xe1, 0xe9, 0xb9, 0xde, 0xbf, 0x86, 0xcb, 0x6a, 0xf3, 0xd0, 0x08, 0x62, 0xda, 0x17, 0x28, 0x29,
	0xec, 0x07, 0xda, 0x5b, 0xb8, 0xb2, 0xb2, 0x90, 0xb3, 0xda, 0x62, 0xae, 0x69, 0x1e, 0x47, 0xea, 0x81, 0x71, 0x61, 0xf4, 0xba, 0xfc, 0x6d, 0x13, 0x46, 0xa2, 0x2b, 0xc3, 0x14, 0xf5, 0x50, 0xc7,
	0xfe, 0x09, 0x42, 0x95, 0x11, 0x6f, 0x15, 0x6c, 0x43, 0x00, 0x08, 0xf1, 0x32, 0x68, 0x2a, 0x31, 0x2f, 0x59, 0x88, 0xba, 0x3c, 0x19, 0x7b, 0xab, 0x59, 0x7d, 0xd3, 0xc9, 0x85, 0xee, 0xc8, 0xbb,
	0xb5, 0x0b, 0x1d, 0xb9, 0xe7, 0xb4, 0x6b, 0xd3, 0xe7, 0xf4, 0xe9, 0x21, 0xa7, 0x20, 0x94, 0x71, 0x2f, 0x80, 0x67, 0xb9, 0x2d, 0x5f, 0x67, 0xda, 0x36, 0x55, 0xb5, 0xbe, 0xfa, 0x60, 0x5b, 0xb1,
	0x62, 0x55, 0xcd, 0x0e, 0x92, 0xfc, 0x72, 0x52, 0x0f, 0x8c, 0x24, 0x86, 0x97, 0x0d, 0x8e, 0x54, 0xb0, 0x30, 0x3b, 0x16, 0x3f, 0x81, 0x3c, 0x4f, 0x8b, 0xcb, 0x62, 0xab, 0xa1, 0xfd, 0xd3, 0x8a,
	0x43, 0x66, 0x23, 0xbb, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
	0x03, 0x03, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x8b, 0x26, 0xd6, 0xd7, 0x47, 0xb4, 0x30, 0x0c, 0xe2, 0x35,
	0x8e, 0x8c, 0x5d, 0x26, 0x62, 0x5d, 0xc7, 0x3f, 0x9b, 0xbb, 0xa0, 0x48, 0xb0, 0x45, 0xbc, 0x61, 0xfb, 0xeb, 0x0c, 0x45, 0xe3, 0x2c, 0x65, 0x1d, 0x51, 0x6f, 0xe0, 0xd2, 0x47, 0xcf, 0x1c, 0xb8,
	0x5b, 0xed, 0x62, 0x14, 0x4c, 0x78, 0xa5, 0x7d, 0x48, 0xfe, 0x09, 0x14, 0xf2, 0x60, 0xc4, 0x30, 0xdd, 0xf2, 0xa7, 0xae, 0x48, 0x6b, 0x24, 0xf1, 0x27, 0xfa, 0xc6, 0xd5, 0x68, 0xf1, 0x27, 0x0c,
	0xe6, 0xde, 0x2c, 0x95, 0x88, 0xee, 0x7e, 0x01, 0x1c, 0x8e, 0x57, 0x33, 0x26, 0x99, 0xe0, 0xd7, 0x3a, 0xab, 0xe0, 0x4a, 0x1d, 0xe0, 0x02, 0xf8, 0x9a, 0xa8, 0x3a, 0x49, 0x90, 0x30, 0xbd, 0xbe,
	0x21, 0x6d, 0x75, 0x10, 0x94, 0x3e, 0x92, 0x77, 0x95, 0xa8, 0xec, 0x47, 0x71, 0x80, 0x9b, 0x62, 0xbd, 0x2b, 0x0c, 0x79, 0x9a, 0x53, 0x02, 0x8f, 0x4c, 0x2c, 0xa9, 0x45, 0x73, 0xd0, 0x78, 0xea,
	0x9f, 0x3a, 0x2b, 0x35, 0xe8, 0x7c, 0xa0, 0x17, 0xfb, 0x9e, 0xba, 0x43, 0x1d, 0xdf, 0xc5, 0x1c, 0x9a, 0x69, 0x09, 0x33, 0xc4, 0xd3, 0xf9, 0x23, 0x25, 0xb7, 0xb9, 0xca, 0x66, 0x65, 0x13, 0x0a,
	0xe3, 0xa2, 0xab, 0xba, 0xce, 0xba, 0x39, 0x36, 0x11, 0x20, 0x26, 0xb4, 0xea, 0x15, 0xce, 0x35, 0x1c, 0xe0, 0x06, 0x0d, 0xf1, 0x55, 0x74, 0x4c, 0x65, 0xd4, 0x53, 0x81, 0x1f, 0xa2, 0x0f, 0x3e,
	0x48, 0x19, 0xc4, 0xde, 0x35, 0x94, 0xeb, 0x88, 0x88, 0xe2, 0x9f, 0xaa, 0x6d, 0x17, 0x01, 0x83, 0xbb, 0x85, 0xaa, 0xfb, 0xb8, 0x23, 0x1e, 0xed, 0xa8, 0x1d, 0x60, 0x5b, 0x60, 0x9c, 0x7e, 0x19,
	0xfd, 0x46, 0xee, 0x1f, 0xab, 0x36, 0x82, 0xee, 0xdd, 0x54, 0xea, 0xc1, 0x08, 0xdb, 0x60, 0xab, 0x05, 0x1d, 0x95, 0x6e, 0x81, 0xed
};


void x509_test(void)
{
	struct x509_certificate_t *cert = x509_certificate_import(x509_test_cert, sizeof(x509_test_cert));
	DEBUG_ASSERT(cert, "x509_certificate_import failed");

	struct rsa_key_t *upstream_key = rsa_key_import_public(x509_test_upstream_public_key, sizeof(x509_test_upstream_public_key));
	DEBUG_ASSERT(upstream_key, "rsa_key_import_public failed");

	DEBUG_ASSERT(x509_certificate_verify_signature(cert, upstream_key, false), "x509_certificate_verify_signature failed");
	rsa_key_free(upstream_key);

	DEBUG_ASSERT(x509_certificate_verify_validity_time(cert, 1510427089ULL), "x509_certificate_verify_validity_time failed");
	DEBUG_ASSERT(x509_certificate_get_validity_time_not_before(cert), "x509_certificate_get_validity_time_not_before failed");
	DEBUG_ASSERT(x509_certificate_get_validity_time_not_after(cert), "x509_certificate_get_validity_time_not_after failed");

	char str[64];
	DEBUG_ASSERT(x509_certificate_get_subject_common_name(cert, str, str + sizeof(str)), "x509_certificate_get_subject_common_name failed");
	DEBUG_ASSERT(x509_certificate_get_subject_organization(cert, str, str + sizeof(str)), "x509_certificate_get_subject_organization failed");
	DEBUG_ASSERT(x509_certificate_get_issuer_organization(cert, str, str + sizeof(str)), "x509_certificate_get_issuer_organization failed");

	struct rsa_key_t *cert_public_key = x509_certificate_get_public_key(cert);
	DEBUG_ASSERT(cert_public_key, "x509_certificate_get_public_key failed");
	rsa_key_free(cert_public_key);

	sha1_digest_t digest;
	DEBUG_ASSERT(x509_certificate_sha1_hash_signature_data(cert, &digest), "x509_certificate_sha1_hash_signature_data failed");

	DEBUG_ASSERT(x509_certificate_is_key_usage_critical(cert), "x509_certificate_is_key_usage_critical failed");
	DEBUG_ASSERT(x509_certificate_is_usable_for_digital_signature(cert), "x509_certificate_is_usable_for_digital_signature failed");
	DEBUG_ASSERT(x509_certificate_is_usable_for_key_encipherment(cert), "x509_certificate_is_usable_for_key_encipherment failed");

	x509_certificate_free(cert);

	cert = x509_certificate_import(x509_test_cert2, sizeof(x509_test_cert2));
	DEBUG_ASSERT(cert, "x509_certificate_import failed");

	DEBUG_ASSERT(x509_certificate_verify_validity_time(cert, 1510427089ULL), "x509_certificate_verify_validity_time failed");
	DEBUG_ASSERT(x509_certificate_get_validity_time_not_before(cert), "x509_certificate_get_validity_time_not_before failed");
	DEBUG_ASSERT(x509_certificate_get_validity_time_not_after(cert), "x509_certificate_get_validity_time_not_after failed");

	DEBUG_ASSERT(x509_certificate_get_subject_common_name(cert, str, str + sizeof(str)), "x509_certificate_get_subject_common_name failed");
	DEBUG_ASSERT(x509_certificate_get_subject_organization(cert, str, str + sizeof(str)), "x509_certificate_get_subject_organization failed");
	DEBUG_ASSERT(x509_certificate_get_issuer_organization(cert, str, str + sizeof(str)), "x509_certificate_get_issuer_organization failed");

	DEBUG_ASSERT(x509_certificate_is_usable_for_code_signing(cert), "x509_certificate_is_usable_for_code_signing failed");

	x509_certificate_free(cert);
}
#endif
