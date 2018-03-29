/*
 * ./src/crypto/x509.h
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct x509_certificate_t;

extern struct x509_certificate_t *x509_certificate_import(uint8_t *data, size_t length);
extern void x509_certificate_free(struct x509_certificate_t *cert);

extern bool x509_certificate_verify_signature(struct x509_certificate_t *cert, struct rsa_key_t *key);
extern bool x509_certificate_verify_validity_time(struct x509_certificate_t *cert, time64_t current_time);

extern time64_t x509_certificate_get_validity_time_not_before(struct x509_certificate_t *cert);
extern time64_t x509_certificate_get_validity_time_not_after(struct x509_certificate_t *cert);
extern bool x509_certificate_get_subject_common_name(struct x509_certificate_t *cert, char *buffer, char *end);
extern bool x509_certificate_get_subject_organization(struct x509_certificate_t *cert, char *buffer, char *end);
extern bool x509_certificate_get_issuer_organization(struct x509_certificate_t *cert, char *buffer, char *end);
extern struct rsa_key_t *x509_certificate_get_public_key(struct x509_certificate_t *cert);
extern bool x509_certificate_sha1_hash_signature_data(struct x509_certificate_t *cert, sha1_digest_t *digest);

extern bool x509_certificate_is_key_usage_critical(struct x509_certificate_t *cert);
extern bool x509_certificate_is_usable_for_digital_signature(struct x509_certificate_t *cert);
extern bool x509_certificate_is_usable_for_key_encipherment(struct x509_certificate_t *cert);
extern bool x509_certificate_is_usable_for_code_signing(struct x509_certificate_t *cert);
extern bool x509_certificate_is_authority_key_identifier_present(struct x509_certificate_t *cert);

extern void x509_test(void);

#if !defined(DEBUG)
extern inline void x509_test(void) {}
#endif
