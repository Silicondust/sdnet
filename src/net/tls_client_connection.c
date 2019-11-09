/*
 * tls_client_connection.c
 *
 * Copyright © 2015-2018 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("tls_client_connection");

#define TLS_MAX_RECORD_LENGTH 16437
#define TLS_MAX_APPLICATION_DATA_LENGTH 16384

#define TLS_CLIENT_CONNECTION_STATE_NULL 0
#define TLS_CLIENT_CONNECTION_STATE_CONNECTING 1
#define TLS_CLIENT_CONNECTION_STATE_CLIENT_HELLO_SENT_EXPECTING_SERVER_HELLO 2
#define TLS_CLIENT_CONNECTION_STATE_SERVER_HELLO_RECV_EXPECTING_CERTIFICATE 3
#define TLS_CLIENT_CONNECTION_STATE_CERTIFICATE_RECV_EXPECTING_SERVER_HELLO_DONE 4
#define TLS_CLIENT_CONNECTION_STATE_HANDSHAKE_LONG_TASK 5
#define TLS_CLIENT_CONNECTION_STATE_HANDSHAKE_FINISHED_SENT_EXPECTING_CHANGE_CIPHER_SPEC 6
#define TLS_CLIENT_CONNECTION_STATE_CHANGE_CIPHER_SPEC_RECV_EXPECTING_FINISHED 7
#define TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA 8

#define TLS_VERSION 0x0303
#define TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_RECORD_CONTENT_TYPE_ALERT 21
#define TLS_RECORD_CONTENT_TYPE_HANDSHAKE 22
#define TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA 23
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define TLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_TYPE_FINISHED 20
#define TLS_HANDSHAKE_CIPHER_TLS_RSA_WITH_AES_128_CBC_SHA 0x002f
#define TLS_ALERT_CLOSE_NOTIFY 0

#define TLS_EXTENSION_SERVER_NAME 0x0000
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS 0x000d
#define TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION 0x0010
#define TLS_EXTENSION_RENEGOTIATION_INFO 0xff01
#define TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME 0
#define TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256 0x0401
#define TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA384 0x0501
#define TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA512 0x0601

#define AES_128_SIZE 16
#define SHA1_SIZE 20

struct tls_client_connection_t {
	struct tcp_connection *conn;
	struct netbuf *partial_rxnb;
	char *host_name;
	uint8_t close_reason;
	uint8_t state;
	bool encrypt;
	int refs;

	struct netbuf *handshake_hash_data_nb;
	struct netbuf *handshake_long_task_certificate_chain_nb;
	struct netbuf *handshake_long_task_client_key_exchange_nb;
	struct netbuf *handshake_long_task_client_certificate_verify_nb;
	struct netbuf *handshake_long_task_handshake_finished_nb;
	uint8_t handshake_server_finished_verify_data[12];
	uint8_t client_random[32];
	uint8_t server_random[32];
	uint8_t master_secret[48];
	bool client_certificate_requested;

	uint8_t client_write_mac_secret[SHA1_SIZE];
	uint8_t server_write_mac_secret[SHA1_SIZE];
	aes_128_key_t client_write_key;
	aes_128_key_t server_write_key;
	aes_128_iv_t client_write_iv;
	aes_128_iv_t server_write_iv;
	uint64_t client_write_sequence;
	uint64_t server_write_sequence;

	tls_client_establish_callback_t establish_callback;
	tls_client_recv_callback_t recv_callback;
	tls_client_send_resume_callback_t send_resume_callback;
	tls_client_close_callback_t close_callback;
	void *callback_arg;
};

struct tls_client_manager_t {
	struct slist_t root_certs;
	struct slist_t client_cert_chain_optional;
	struct rsa_key_t *client_key_optional;
};

static struct tls_client_manager_t tls_client_manager;

struct tls_client_connection_t *tls_client_connection_ref(struct tls_client_connection_t *tls_conn)
{
	tls_conn->refs++;
	return tls_conn;
}

int tls_client_connection_deref(struct tls_client_connection_t *tls_conn)
{
	tls_conn->refs--;
	if (tls_conn->refs != 0) {
		return tls_conn->refs;
	}

	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_NULL) {
		DEBUG_ASSERT(0, "deref to 0 when active");
		tls_client_connection_close(tls_conn);
	}

	if (tls_conn->partial_rxnb) {
		netbuf_free(tls_conn->partial_rxnb);
		tls_conn->partial_rxnb = NULL;
	}

	if (tls_conn->host_name) {
		heap_free(tls_conn->host_name);
		tls_conn->host_name = NULL;
	}

	if (tls_conn->handshake_hash_data_nb) {
		netbuf_free(tls_conn->handshake_hash_data_nb);
		tls_conn->handshake_hash_data_nb = NULL;
	}

	if (tls_conn->handshake_long_task_certificate_chain_nb) {
		netbuf_free(tls_conn->handshake_long_task_certificate_chain_nb);
		tls_conn->handshake_long_task_certificate_chain_nb = NULL;
	}

	if (tls_conn->handshake_long_task_client_key_exchange_nb) {
		netbuf_free(tls_conn->handshake_long_task_client_key_exchange_nb);
		tls_conn->handshake_long_task_client_key_exchange_nb = NULL;
	}

	if (tls_conn->handshake_long_task_client_certificate_verify_nb) {
		netbuf_free(tls_conn->handshake_long_task_client_certificate_verify_nb);
		tls_conn->handshake_long_task_client_certificate_verify_nb = NULL;
	}

	if (tls_conn->handshake_long_task_handshake_finished_nb) {
		netbuf_free(tls_conn->handshake_long_task_handshake_finished_nb);
		tls_conn->handshake_long_task_handshake_finished_nb = NULL;
	}

	heap_free(tls_conn);
	return 0;
}

void tls_client_connection_close(struct tls_client_connection_t *tls_conn)
{
	if (tls_conn->conn) {
		tcp_connection_close(tls_conn->conn);
		tcp_connection_deref(tls_conn->conn);
		tls_conn->conn = NULL;
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_NULL;
	tls_conn->establish_callback = NULL;
	tls_conn->recv_callback = NULL;
	tls_conn->send_resume_callback = NULL;
	tls_conn->close_callback = NULL;
}

static void tls_client_connection_close_and_notify(struct tls_client_connection_t *tls_conn)
{
	tls_client_close_callback_t close_callback = tls_conn->close_callback;
	tls_client_connection_close(tls_conn);

	if (close_callback) {
		close_callback(tls_conn->callback_arg, tls_conn->close_reason);
	}
}

static void tls_client_connection_tcp_close_callback(void *arg, tcp_close_reason_t reason)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;
	tls_conn->close_reason = reason;

	tcp_connection_deref(tls_conn->conn);
	tls_conn->conn = NULL;

	tls_client_connection_close_and_notify(tls_conn);
}

static void tls_client_connection_tcp_send_resume_callback(void *arg)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;

	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA) {
		return;
	}

	if (tls_conn->send_resume_callback) {
		tls_conn->send_resume_callback(tls_conn->callback_arg);
	}
}

static bool tls_client_connection_append_hash_data(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	addr_t bookmark = netbuf_get_pos(nb);
	netbuf_set_pos_to_start(nb);

	size_t length = netbuf_get_remaining(nb);

	if (!tls_conn->handshake_hash_data_nb) {
		tls_conn->handshake_hash_data_nb = netbuf_alloc_with_fwd_space(length);
		if (!tls_conn->handshake_hash_data_nb) {
			DEBUG_WARN("out of memory");
			return false;
		}
	} else {
		netbuf_set_pos_to_end(tls_conn->handshake_hash_data_nb);

		if (!netbuf_fwd_make_space(tls_conn->handshake_hash_data_nb, length)) {
			DEBUG_WARN("out of memory");
			return false;
		}
	}

	netbuf_fwd_copy(tls_conn->handshake_hash_data_nb, nb, length);
	netbuf_set_pos(nb, bookmark);
	return true;
}

static bool tls_client_connection_record_send_encrypt(struct tls_client_connection_t *tls_conn, uint8_t record_content_type, uint8_t *override_iv, struct netbuf *txnb)
{
	if (!tls_conn->encrypt) {
		return true;
	}

	if (!netbuf_rev_make_space(txnb, AES_128_SIZE)) {
		DEBUG_WARN("out of memory");
		return false;
	}

	/* Calculate HMAC (data prepended here for the HMAC calculation is less than 16 bytes and will be overwritten by the random IV) */
	netbuf_rev_write_u16(txnb, (uint16_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u16(txnb, TLS_VERSION);
	netbuf_rev_write_u8(txnb, record_content_type);
	netbuf_rev_write_u64(txnb, tls_conn->client_write_sequence++);

	sha1_digest_t mac;
	sha1_hmac_compute_digest_netbuf(&mac, txnb, netbuf_get_remaining(txnb), tls_conn->client_write_mac_secret, sizeof(tls_conn->client_write_mac_secret));

	/* IV */
	netbuf_set_pos_to_start(txnb);

	if (UNLIKELY(override_iv)) {
		netbuf_fwd_write(txnb, override_iv, AES_128_SIZE);
	} else {
		netbuf_fwd_write_u32(txnb, random_get32());
		netbuf_fwd_write_u32(txnb, random_get32());
		netbuf_fwd_write_u32(txnb, random_get32());
		netbuf_fwd_write_u32(txnb, random_get32());
	}

	/* Write HMAC & padding */
	size_t remainder = (netbuf_get_extent(txnb) + SHA1_SIZE) % AES_128_SIZE;
	size_t padding_length = AES_128_SIZE - remainder;

	netbuf_set_pos_to_end(txnb);

	if (!netbuf_fwd_make_space(txnb, SHA1_SIZE + padding_length)) {
		DEBUG_WARN("out of memory");
		return false;
	}

	netbuf_fwd_write(txnb, mac.u8, SHA1_SIZE);

	uint8_t padding_value = (uint8_t)padding_length - 1;
	netbuf_fwd_fill_u8(txnb, padding_length, padding_value);

	/* Encrypt */
	netbuf_set_pos_to_start(txnb);

#if defined(IPOS)
	aes_lock();
	aes_cbc_encrypt_netbuf(txnb, netbuf_get_remaining(txnb), tls_conn->client_write_iv.u32be, tls_conn->client_write_key.u32be, AES_KEY_SIZE_128);
	aes_unlock();
#else
	uint8_t *ptr = netbuf_get_ptr(txnb);
	uint8_t *end = ptr + netbuf_get_remaining(txnb);
	aes_cbc_128_encrypt_inplace(ptr, end, &tls_conn->client_write_iv, &tls_conn->client_write_key);
#endif

	netbuf_set_pos_to_start(txnb);
	return true;
}

static inline void tls_client_connection_record_recv_decrypt_aes(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
#if defined(IPOS)
	aes_lock();
	aes_cbc_decrypt_netbuf(nb, netbuf_get_remaining(nb), tls_conn->server_write_iv.u32be, tls_conn->server_write_key.u32be, AES_KEY_SIZE_128);
	aes_unlock();
#else
	uint8_t *ptr = netbuf_get_ptr(nb);
	uint8_t *end = ptr + netbuf_get_remaining(nb);
	aes_cbc_128_decrypt_inplace(ptr, end, &tls_conn->server_write_iv, &tls_conn->server_write_key);
#endif
}

static bool tls_client_connection_record_recv_decrypt(struct tls_client_connection_t *tls_conn, uint8_t record_content_type, struct netbuf *nb)
{
	if (!tls_conn->encrypt) {
		return true;
	}

	/* Decrypt */
	size_t length = netbuf_get_remaining(nb);
	if ((length % AES_128_SIZE) != 0) {
		DEBUG_WARN("bad length");
		return false;
	}
	if (length < AES_128_SIZE + 1 + SHA1_SIZE + 1) { /* IV + payload(min) + MAC + pad(min) */
		DEBUG_WARN("bad length");
		return false;
	}

#if defined(DEBUG_TIMING)
	uint32_t aes_time = timer_get_fast_ticks();
	tls_client_connection_record_recv_decrypt_aes(tls_conn, nb);
	aes_time = timer_get_fast_ticks() - aes_time;
#else
	tls_client_connection_record_recv_decrypt_aes(tls_conn, nb);
#endif

	/* Remove IV */
	netbuf_set_pos_to_start(nb);
	netbuf_advance_pos(nb, AES_128_SIZE);
	netbuf_set_start_to_pos(nb);

	/* Remove padding */
	netbuf_set_pos_to_end(nb);
	netbuf_retreat_pos(nb, 1);
	uint8_t padding_value = netbuf_fwd_read_u8(nb);
	size_t padding_length = padding_value + 1;

	if (padding_length >= netbuf_get_preceding(nb)) {
		DEBUG_WARN("bad padding");
		return false;
	}

	netbuf_retreat_pos(nb, padding_length);
	for (size_t i = 0; i < padding_length; i++) {
		if (netbuf_fwd_read_u8(nb) != padding_value) {
			DEBUG_WARN("bad padding");
			return false;
		}
	}

	netbuf_retreat_pos(nb, padding_length);
	netbuf_set_end_to_pos(nb);

	/* Verify HMAC */
	netbuf_set_pos_to_start(nb);

	length = netbuf_get_remaining(nb);
	if (length < 1 + SHA1_SIZE) { /* payload(min) + MAC */
		DEBUG_WARN("bad length");
		return false;
	}

	size_t payload_length = length - SHA1_SIZE;

	if (!netbuf_rev_make_space(nb, 13)) {
		DEBUG_WARN("out of memory");
		return false;
	}

	netbuf_rev_write_u16(nb, (uint16_t)payload_length);
	netbuf_rev_write_u16(nb, TLS_VERSION);
	netbuf_rev_write_u8(nb, record_content_type);
	netbuf_rev_write_u64(nb, tls_conn->server_write_sequence++);

#if defined(DEBUG_TIMING)
	sha1_digest_t mac;
	uint32_t hmac_time = timer_get_fast_ticks();
	sha1_hmac_compute_digest_netbuf(&mac, nb, 13 + payload_length, tls_conn->server_write_mac_secret, sizeof(tls_conn->server_write_mac_secret));
	hmac_time = timer_get_fast_ticks() - hmac_time;
#else
	sha1_digest_t mac;
	sha1_hmac_compute_digest_netbuf(&mac, nb, 13 + payload_length, tls_conn->server_write_mac_secret, sizeof(tls_conn->server_write_mac_secret));
#endif

	netbuf_set_pos_to_end(nb);
	netbuf_retreat_pos(nb, SHA1_SIZE);

	if (netbuf_fwd_memcmp(nb, mac.u8, SHA1_SIZE) != 0) {
		DEBUG_WARN("bad mac");
		return false;
	}

	netbuf_set_end_to_pos(nb);
	netbuf_retreat_pos(nb, payload_length);
	netbuf_set_start_to_pos(nb);

#if defined(DEBUG_TIMING)
	DEBUG_INFO("%u byte payload (aes=%uus hamc=%uus)", netbuf_get_extent(nb), aes_time / FAST_TICK_RATE_US, hmac_time / FAST_TICK_RATE_US);
#endif

	return true;
}

static bool tls_client_connection_record_send(struct tls_client_connection_t *tls_conn, uint8_t record_content_type, struct netbuf *txnb)
{
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "pos not at start");

	switch (record_content_type) {
	case TLS_RECORD_CONTENT_TYPE_HANDSHAKE:
	case TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA:
		if (!tls_client_connection_record_send_encrypt(tls_conn, record_content_type, NULL, txnb)) {
			return false;
		}
		break;

	case TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
		break;

	default:
		DEBUG_ERROR("unexpected content type 0x%02x", record_content_type);
		return false;
	}

	if (!netbuf_rev_make_space(txnb, 5)) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	netbuf_rev_write_u16(txnb, (uint16_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u16(txnb, TLS_VERSION);
	netbuf_rev_write_u8(txnb, record_content_type);

	DEBUG_ASSERT(netbuf_get_remaining(txnb) <= TLS_MAX_RECORD_LENGTH, "over-length send");

	tcp_error_t tcp_error = tcp_connection_send_netbuf(tls_conn->conn, txnb);
	return (tcp_error == TCP_OK);
}

static bool tls_client_connection_send_client_hello(struct tls_client_connection_t *tls_conn)
{
	size_t host_name_len = strlen(tls_conn->host_name);

	struct netbuf *txnb = netbuf_alloc_with_rev_space(56 + host_name_len + 17);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	/* Extension - signature algorithms */
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA512);
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA384);
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256);
	netbuf_rev_write_u16(txnb, 6); /* list length in bytes */
	netbuf_rev_write_u16(txnb, 8); /* extension length */
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_SIGNATURE_ALGORITHMS);

	/* Extension - renegotiation info */
	netbuf_rev_write_u8(txnb, 0);
	netbuf_rev_write_u16(txnb, 1); /* extension length */
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_RENEGOTIATION_INFO);

	/* Extension - server name */
	netbuf_rev_write(txnb, tls_conn->host_name, host_name_len);
	netbuf_rev_write_u16(txnb, (uint16_t)host_name_len);
	netbuf_rev_write_u8(txnb, TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME);
	netbuf_rev_write_u16(txnb, 3 + (uint16_t)host_name_len); /* list length */
	netbuf_rev_write_u16(txnb, 5 + (uint16_t)host_name_len); /* extension length */
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_SERVER_NAME);

	/* Extensions */
	netbuf_rev_write_u16(txnb, (uint16_t)netbuf_get_remaining(txnb));

	/* Handshake - compression methods */
	netbuf_rev_write_u8(txnb, 0); /* null */
	netbuf_rev_write_u8(txnb, 1); /* length */

	/* Handshake - ciphers */
	netbuf_rev_write_u16(txnb, TLS_HANDSHAKE_CIPHER_TLS_RSA_WITH_AES_128_CBC_SHA);
	netbuf_rev_write_u16(txnb, 2); /* length */

	/* Handshake - session id */
	netbuf_rev_write_u8(txnb, 0); /* length */

	/* Handshake - random */
	uint32_t client_random[8];
	for (int i = 0; i < 8; i++) {
		client_random[i] = random_get32();
	}
	memcpy(tls_conn->client_random, client_random, 32);
	netbuf_rev_write(txnb, tls_conn->client_random, 32);

	/* Handshake - client hello */
	netbuf_rev_write_u16(txnb, TLS_VERSION);
	netbuf_rev_write_u24(txnb, (uint32_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u8(txnb, TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "length error");

	/* Send */
	if (!tls_client_connection_append_hash_data(tls_conn, txnb)) {
		netbuf_free(txnb);
		return false;
	}

	if (!tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, txnb)) {
		netbuf_free(txnb);
		return false;
	}

	netbuf_free(txnb);
	return true;
}

static bool tls_client_connection_send_client_certificate(struct tls_client_connection_t *tls_conn)
{
	struct netbuf *txnb = netbuf_alloc();
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	if (tls_client_manager.client_key_optional) {
		struct x509_certificate_t *cert = slist_get_head(struct x509_certificate_t, &tls_client_manager.client_cert_chain_optional);
		while (cert) {
			uint8_t *cert_data = x509_certificate_get_raw_data(cert);
			size_t cert_length = x509_certificate_get_raw_length(cert);

			if (!netbuf_fwd_make_space(txnb, 3 + cert_length)) {
				DEBUG_ERROR("out of memory");
				netbuf_free(txnb);
				return false;
			}

			netbuf_fwd_write_u24(txnb, (uint32_t)cert_length);
			netbuf_fwd_write(txnb, cert_data, cert_length);

			cert = slist_get_next(struct x509_certificate_t, cert);
		}

		netbuf_set_pos_to_start(txnb);
	} else {
		/* Prevent further client certificate work if there is no client certificate */
		tls_conn->client_certificate_requested = false;
	}

	if (!netbuf_rev_make_space(txnb, 7)) {
		DEBUG_ERROR("out of memory");
		netbuf_free(txnb);
		return false;
	}

	netbuf_rev_write_u24(txnb, (uint32_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u24(txnb, (uint32_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u8(txnb, TLS_HANDSHAKE_TYPE_CERTIFICATE);
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "length error");

	/* Send */
	if (!tls_client_connection_append_hash_data(tls_conn, txnb)) {
		netbuf_free(txnb);
		return false;
	}

	if (!tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, txnb)) {
		netbuf_free(txnb);
		return false;
	}

	netbuf_free(txnb);
	return true;
}

static bool tls_client_connection_send_change_cipher_spec(struct tls_client_connection_t *tls_conn)
{
	struct netbuf *txnb = netbuf_alloc_with_rev_space(1);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	/* Change cipher spec */
	netbuf_rev_write_u8(txnb, 0x01);
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "length error");

	/* Send */
	if (!tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC, txnb)) {
		netbuf_free(txnb);
		return false;
	}

	netbuf_free(txnb);
	return true;
}

static void tls_client_connection_handshake_long_task_failed(void *arg)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;
	if (tls_client_connection_deref(tls_conn) == 0) {
		return;
	}

	tls_client_connection_close_and_notify(tls_conn);
}

static void tls_client_connection_handshake_long_task_success(void *arg)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;
	if (tls_client_connection_deref(tls_conn) == 0) {
		return;
	}

	netbuf_free(tls_conn->handshake_hash_data_nb);
	tls_conn->handshake_hash_data_nb = NULL;

	netbuf_free(tls_conn->handshake_long_task_certificate_chain_nb);
	tls_conn->handshake_long_task_certificate_chain_nb = NULL;

	/* Send client key exchange */
	if (!tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, tls_conn->handshake_long_task_client_key_exchange_nb)) {
		tls_client_connection_close_and_notify(tls_conn);
		return;
	}

	netbuf_free(tls_conn->handshake_long_task_client_key_exchange_nb);
	tls_conn->handshake_long_task_client_key_exchange_nb = NULL;

	/* Send client certificate verify */
	if (tls_conn->client_certificate_requested) {
		if (!tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, tls_conn->handshake_long_task_client_certificate_verify_nb)) {
			tls_client_connection_close_and_notify(tls_conn);
			return;
		}

		netbuf_free(tls_conn->handshake_long_task_client_certificate_verify_nb);
		tls_conn->handshake_long_task_client_certificate_verify_nb = NULL;
	}

	/* Send change cipher spec */
	if (!tls_client_connection_send_change_cipher_spec(tls_conn)) {
		tls_client_connection_close_and_notify(tls_conn);
		return;
	}

	/* Enable encryption*/
	tls_conn->encrypt = true;

	/* Send handshake finished */
	if (!tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, tls_conn->handshake_long_task_handshake_finished_nb)) {
		tls_client_connection_close_and_notify(tls_conn);
		return;
	}

	netbuf_free(tls_conn->handshake_long_task_handshake_finished_nb);
	tls_conn->handshake_long_task_handshake_finished_nb = NULL;

	/* Complete */
	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_HANDSHAKE_FINISHED_SENT_EXPECTING_CHANGE_CIPHER_SPEC;
}

static struct rsa_key_t *tls_client_connection_handshake_long_task_verify_certificate_chain(struct tls_client_connection_t *tls_conn, struct slist_t *server_cert_chain, struct netbuf *nb)
{
	/* Import and verify certificate chain */
	while (1) {
		if (!netbuf_fwd_check_space(nb, 3)) {
			break;
		}

		size_t certificate_length = (size_t)netbuf_fwd_read_u24(nb);
		addr_t certificate_end = netbuf_get_pos(nb) + certificate_length;
		if (certificate_end > netbuf_get_end(nb)) {
			DEBUG_WARN("bad length");
			return NULL;
		}

		/* Import certificate */
		struct x509_certificate_t *cert = x509_certificate_import_netbuf(nb, certificate_length);
		if (!cert) {
			DEBUG_WARN("bad cert");
			return NULL;
		}

		slist_attach_tail(struct x509_certificate_t, server_cert_chain, cert);
		netbuf_set_pos(nb, certificate_end);
	}

	struct x509_certificate_t *cert = slist_get_head(struct x509_certificate_t, server_cert_chain);
	if (!cert) {
		DEBUG_WARN("no server cert");
		return NULL;
	}

	if (RUNTIME_DEBUG && 0) {
		char common_name[128];
		x509_certificate_get_subject_common_name(cert, common_name, common_name + sizeof(common_name));
		DEBUG_INFO("server CN = %s", common_name);
	}

	if (!x509_certificate_is_usable_for_tls_web_server_authentication(cert)) {
		DEBUG_WARN("certificate not valid for tls server authentication");
		return NULL;
	}

	if (!x509_certificate_is_valid_for_dns_name(cert, tls_conn->host_name)) {
		DEBUG_WARN("certificate not valid for %s", tls_conn->host_name);
		return NULL;
	}

	if (!x509_chain_verify(server_cert_chain, &tls_client_manager.root_certs, true)) {
		DEBUG_WARN("cert chain verify failed");
		return NULL;
	}

	struct rsa_key_t *server_public_key = x509_certificate_get_public_key(cert);
	if (!server_public_key) {
		DEBUG_WARN("rsa import failed");
		return NULL;
	}

	return server_public_key;
}

static struct netbuf *tls_client_connection_handshake_long_task_generate_client_key_exchange(struct tls_client_connection_t *tls_conn, uint8_t *pre_master_secret, struct rsa_key_t *server_public_key)
{
	/* Encrypt pre_master_secret with server public key */
	uint8_t buffer[512];
	size_t buffer_len = rsa_key_get_size_bytes(server_public_key);
	if (buffer_len > sizeof(buffer)) {
		DEBUG_WARN("rsa key > 4096 bit");
		return NULL;
	}

	pkcs1_v15_type2_pad(pre_master_secret, 48, buffer, buffer_len);

	if (!rsa_exptmod_auto(buffer, buffer, buffer_len, server_public_key)) {
		DEBUG_WARN("rsa encrypt failed");
		return NULL;
	}

	/* Generate client key exchange packet */
	struct netbuf *txnb = netbuf_alloc_with_rev_space(6 + buffer_len);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	/* Handshake - encrypted exchange */
	netbuf_rev_write(txnb, buffer, buffer_len);
	netbuf_rev_write_u16(txnb, (uint16_t)buffer_len);

	/* Handshake - client key exchange */
	netbuf_rev_write_u24(txnb, (uint32_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u8(txnb, TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE);
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "length error");

	/* Complete */
	return txnb;
}

static struct netbuf *tls_client_connection_handshake_long_task_generate_client_certificate_verify(struct tls_client_connection_t *tls_conn)
{
	/* Compute hash of handshake data */
	netbuf_set_pos_to_start(tls_conn->handshake_hash_data_nb);
	size_t handshake_data_length = netbuf_get_remaining(tls_conn->handshake_hash_data_nb);

	sha256_digest_t sha256_hash;
	sha256_compute_digest_netbuf(&sha256_hash, tls_conn->handshake_hash_data_nb, handshake_data_length);

	/* Sign with client key */
	uint8_t signature[512];
	size_t signature_len = rsa_key_get_size_bytes(tls_client_manager.client_key_optional);
	if (signature_len > sizeof(signature)) {
		DEBUG_WARN("rsa key > 4096 bit");
		return NULL;
	}

	pkcs1_v15_pad_sha256(&sha256_hash, signature, signature_len);

	if (!rsa_exptmod_auto(signature, signature, signature_len, tls_client_manager.client_key_optional)) {
		DEBUG_WARN("rsa encrypt failed");
		return NULL;
	}

	/* Generate client certificate verify packet */
	struct netbuf *txnb = netbuf_alloc_with_rev_space(8 + signature_len);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	/* Handshake - encrypted exchange */
	netbuf_rev_write(txnb, signature, signature_len);
	netbuf_rev_write_u16(txnb, (uint16_t)signature_len);
	netbuf_rev_write_u16(txnb, TLS_EXTENSION_SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256);

	/* Handshake - client key exchange */
	netbuf_rev_write_u24(txnb, (uint32_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u8(txnb, TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY);
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "length error");

	/* Complete */
	return txnb;
}

static void tls_client_connection_handshake_long_task_generate_master_secret_and_key_block(struct tls_client_connection_t *tls_conn, uint8_t *pre_master_secret)
{
	/* Master secret */
	uint8_t seed[64];
	memcpy(seed + 0, tls_conn->client_random, 32);
	memcpy(seed + 32, tls_conn->server_random, 32);
	tls_prf(tls_conn->master_secret, sizeof(tls_conn->master_secret), "master secret", seed, sizeof(seed), pre_master_secret, 48);

	/* Key block */
	uint8_t key_block[(SHA1_SIZE + AES_128_SIZE + AES_128_SIZE) * 2];
	memcpy(seed + 0, tls_conn->server_random, 32);
	memcpy(seed + 32, tls_conn->client_random, 32);
	tls_prf(key_block, sizeof(key_block), "key expansion", seed, sizeof(seed), tls_conn->master_secret, sizeof(tls_conn->master_secret));

	uint8_t *ptr = key_block;
	memcpy(tls_conn->client_write_mac_secret, ptr, SHA1_SIZE); ptr += SHA1_SIZE;
	memcpy(tls_conn->server_write_mac_secret, ptr, SHA1_SIZE); ptr += SHA1_SIZE;
	memcpy(tls_conn->client_write_key.u8, ptr, AES_128_SIZE); ptr += AES_128_SIZE;
	memcpy(tls_conn->server_write_key.u8, ptr, AES_128_SIZE); ptr += AES_128_SIZE;
	memcpy(tls_conn->client_write_iv.u8, ptr, AES_128_SIZE); ptr += AES_128_SIZE;
	memcpy(tls_conn->server_write_iv.u8, ptr, AES_128_SIZE); ptr += AES_128_SIZE;
}

static struct netbuf *tls_client_connection_handshake_long_task_generate_handshake_finished(struct tls_client_connection_t *tls_conn)
{
	if (!tls_conn->handshake_hash_data_nb) {
		DEBUG_ERROR("no handshake data");
		return NULL;
	}

	struct netbuf *txnb = netbuf_alloc_with_rev_space(16);
	if (!txnb) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	/* Write the verify data */
	netbuf_set_pos_to_start(tls_conn->handshake_hash_data_nb);
	size_t length = netbuf_get_remaining(tls_conn->handshake_hash_data_nb);

	sha256_digest_t sha256_hash;
	sha256_compute_digest_netbuf(&sha256_hash, tls_conn->handshake_hash_data_nb, length);

	uint8_t verify_data[12];
	tls_prf(verify_data, sizeof(verify_data), "client finished", sha256_hash.u8, sizeof(sha256_hash.u8), tls_conn->master_secret, sizeof(tls_conn->master_secret));
	netbuf_rev_write(txnb, verify_data, 12);

	/* Handshake - finished */
	netbuf_rev_write_u24(txnb, (uint32_t)netbuf_get_remaining(txnb));
	netbuf_rev_write_u8(txnb, TLS_HANDSHAKE_TYPE_FINISHED);
	DEBUG_ASSERT(netbuf_get_pos(txnb) == netbuf_get_start(txnb), "length error");

	/* Complete */
	return txnb;
}

static bool tls_client_connection_handshake_long_task_compute_server_finished_verify_data(struct tls_client_connection_t *tls_conn)
{
	if (!tls_conn->handshake_hash_data_nb) {
		DEBUG_ERROR("no handshake data");
		return false;
	}

	netbuf_set_pos_to_start(tls_conn->handshake_hash_data_nb);
	size_t length = netbuf_get_remaining(tls_conn->handshake_hash_data_nb);

	sha256_digest_t sha256_hash;
	sha256_compute_digest_netbuf(&sha256_hash, tls_conn->handshake_hash_data_nb, length);

	tls_prf(tls_conn->handshake_server_finished_verify_data, sizeof(tls_conn->handshake_server_finished_verify_data), "server finished", sha256_hash.u8, sizeof(sha256_hash.u8), tls_conn->master_secret, sizeof(tls_conn->master_secret));
	return true;
}

static bool tls_client_connection_handshake_long_task(void *arg)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;

	/* Verify certificate chain */
	struct slist_t server_cert_chain;
	memset(&server_cert_chain, 0, sizeof(server_cert_chain));

	struct rsa_key_t *server_public_key = tls_client_connection_handshake_long_task_verify_certificate_chain(tls_conn, &server_cert_chain, tls_conn->handshake_long_task_certificate_chain_nb);
	slist_clear(struct x509_certificate_t, &server_cert_chain, x509_certificate_free);
	if (!server_public_key) {
		return false;
	}

	/* Generate pre master secret  */
	uint32_t pre_master_secret_u32be[12];
	for (int i = 0; i < 12; i++) {
		pre_master_secret_u32be[i] = random_get32();
	}

	uint8_t *pre_master_secret = (uint8_t *)pre_master_secret_u32be;
	mem_int_write_be_u16(pre_master_secret, TLS_VERSION);

	/* Generate client key exchange packet */
	tls_conn->handshake_long_task_client_key_exchange_nb = tls_client_connection_handshake_long_task_generate_client_key_exchange(tls_conn, pre_master_secret, server_public_key);
	rsa_key_free(server_public_key);

	if (!tls_conn->handshake_long_task_client_key_exchange_nb) {
		return false;
	}
	if (!tls_client_connection_append_hash_data(tls_conn, tls_conn->handshake_long_task_client_key_exchange_nb)) {
		return false;
	}

	/* Generate client certificate verify */
	if (tls_conn->client_certificate_requested) {
		tls_conn->handshake_long_task_client_certificate_verify_nb = tls_client_connection_handshake_long_task_generate_client_certificate_verify(tls_conn);
		if (!tls_conn->handshake_long_task_client_certificate_verify_nb) {
			return false;
		}
		if (!tls_client_connection_append_hash_data(tls_conn, tls_conn->handshake_long_task_client_certificate_verify_nb)) {
			return false;
		}
	}

	/* Generate master secret and key block */
	tls_client_connection_handshake_long_task_generate_master_secret_and_key_block(tls_conn, pre_master_secret);

	/* Generate handshake finished packet */
	tls_conn->handshake_long_task_handshake_finished_nb = tls_client_connection_handshake_long_task_generate_handshake_finished(tls_conn);
	if (!tls_conn->handshake_long_task_handshake_finished_nb) {
		return false;
	}
	if (!tls_client_connection_append_hash_data(tls_conn, tls_conn->handshake_long_task_handshake_finished_nb)) {
		return false;
	}

	/* Compute server finished verify data */
	if (!tls_client_connection_handshake_long_task_compute_server_finished_verify_data(tls_conn)) {
		return false;
	}

	/* Complete */
	return true;
}

static bool tls_client_connection_recv_server_hello(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	DEBUG_TRACE("recv server hello");

	if (!netbuf_fwd_check_space(nb, 35)) {
		DEBUG_WARN("short hello header");
		return false;
	}

	/* Version */
	uint16_t version = netbuf_fwd_read_u16(nb);
	if (version != TLS_VERSION) {
		DEBUG_WARN("unsupported version");
		return false;
	}

	/* Server random */
	netbuf_fwd_read(nb, tls_conn->server_random, 32);

	/* Session id */
	uint8_t session_id_len = netbuf_fwd_read_u8(nb);
	if (session_id_len > 0) {
		if (!netbuf_fwd_check_space(nb, session_id_len)) {
			DEBUG_WARN("short hello header");
			return false;
		}

		netbuf_advance_pos(nb, session_id_len);
	}

	/* Cipher suite */
	if (!netbuf_fwd_check_space(nb, 2)) {
		DEBUG_WARN("short hello header");
		return false;
	}

	uint16_t cipher_suite = netbuf_fwd_read_u16(nb);
	if (cipher_suite != TLS_HANDSHAKE_CIPHER_TLS_RSA_WITH_AES_128_CBC_SHA) {
		DEBUG_WARN("unsupported cipher suite");
		return false;
	}

	/* Success */
	if (!tls_client_connection_append_hash_data(tls_conn, nb)) {
		return false;
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_SERVER_HELLO_RECV_EXPECTING_CERTIFICATE;
	return true;
}

static bool tls_client_connection_recv_certificate(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	DEBUG_TRACE("recv certificate");

	/* Certificates length */
	if (!netbuf_fwd_check_space(nb, 3)) {
		DEBUG_WARN("short certificate header");
		return false;
	}

	uint32_t certificates_length = netbuf_fwd_read_u24(nb);
	addr_t certificates_end = netbuf_get_pos(nb) + certificates_length;
	if (certificates_end > netbuf_get_end(nb)) {
		DEBUG_WARN("bad length");
		return false;
	}

	/* Append to handshake hash data before modifing the nb */
	if (!tls_client_connection_append_hash_data(tls_conn, nb)) {
		return false;
	}

	/* Save certificate data for later long_task processing */
	netbuf_set_start_to_pos(nb);
	netbuf_set_end(nb, certificates_end);

	tls_conn->handshake_long_task_certificate_chain_nb = netbuf_alloc_and_steal(nb);
	if (!tls_conn->handshake_long_task_certificate_chain_nb) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_CERTIFICATE_RECV_EXPECTING_SERVER_HELLO_DONE;
	return true;
}

static bool tls_client_connection_recv_certificate_request(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	DEBUG_TRACE("recv certificate request");

	if (!tls_client_connection_append_hash_data(tls_conn, nb)) {
		return false;
	}

	tls_conn->client_certificate_requested = true;
	return true;
}

static bool tls_client_connection_recv_server_hello_done(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	DEBUG_TRACE("recv server hello done");

	if (!tls_client_connection_append_hash_data(tls_conn, nb)) {
		return false;
	}

	if (tls_conn->client_certificate_requested) {
		if (!tls_client_connection_send_client_certificate(tls_conn)) {
			return false;
		}
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_HANDSHAKE_LONG_TASK;

	tls_client_connection_ref(tls_conn);
	if (!long_task_enqueue(tls_client_connection_handshake_long_task, tls_client_connection_handshake_long_task_success, tls_client_connection_handshake_long_task_failed, tls_conn)) {
		tls_client_connection_deref(tls_conn);
		return false;
	}

	return true;
}

static bool tls_client_connection_recv_finished(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	DEBUG_TRACE("recv finished");

	size_t verify_data_length = netbuf_get_remaining(nb);
	if (verify_data_length != 12) {
		DEBUG_WARN("bad finished data");
		return false;
	}

	if (netbuf_fwd_memcmp(nb, tls_conn->handshake_server_finished_verify_data, 12) != 0) {
		DEBUG_ERROR("finished verify failed");
		return false;
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA;

	if (tls_conn->establish_callback) {
		tls_conn->establish_callback(tls_conn->callback_arg);
	}

	return true;
}

static bool tls_client_connection_recv_handshake(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	if (!tls_client_connection_record_recv_decrypt(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, nb)) {
		return false;
	}

	if (!netbuf_fwd_check_space(nb, 4)) {
		DEBUG_WARN("short handshake header");
		return false;
	}

	uint8_t handshake_type = netbuf_fwd_read_u8(nb);

	uint32_t handshake_length = netbuf_fwd_read_u24(nb);
	if (handshake_length > netbuf_get_remaining(nb)) {
		DEBUG_WARN("length error");
		return false;
	}

	netbuf_set_end(nb, netbuf_get_pos(nb) + handshake_length);

	if ((handshake_type == TLS_HANDSHAKE_TYPE_SERVER_HELLO) && (tls_conn->state == TLS_CLIENT_CONNECTION_STATE_CLIENT_HELLO_SENT_EXPECTING_SERVER_HELLO)) {
		return tls_client_connection_recv_server_hello(tls_conn, nb);
	}

	if ((handshake_type == TLS_HANDSHAKE_TYPE_CERTIFICATE) && (tls_conn->state == TLS_CLIENT_CONNECTION_STATE_SERVER_HELLO_RECV_EXPECTING_CERTIFICATE)) {
		return tls_client_connection_recv_certificate(tls_conn, nb);
	}

	if ((handshake_type == TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST) && (tls_conn->state == TLS_CLIENT_CONNECTION_STATE_CERTIFICATE_RECV_EXPECTING_SERVER_HELLO_DONE)) {
		return tls_client_connection_recv_certificate_request(tls_conn, nb);
	}

	if ((handshake_type == TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE) && (tls_conn->state == TLS_CLIENT_CONNECTION_STATE_CERTIFICATE_RECV_EXPECTING_SERVER_HELLO_DONE)) {
		return tls_client_connection_recv_server_hello_done(tls_conn, nb);
	}

	if ((handshake_type == TLS_HANDSHAKE_TYPE_FINISHED) && (tls_conn->state == TLS_CLIENT_CONNECTION_STATE_CHANGE_CIPHER_SPEC_RECV_EXPECTING_FINISHED)) {
		return tls_client_connection_recv_finished(tls_conn, nb);
	}

	DEBUG_WARN("unexpected handshake_type %u in state %u", handshake_type, tls_conn->state);
	return false;
}

static bool tls_client_connection_recv_change_cipher_spec(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_HANDSHAKE_FINISHED_SENT_EXPECTING_CHANGE_CIPHER_SPEC) {
		DEBUG_WARN("unexpected change_cipher_spec in state %u", tls_conn->state);
		return false;
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_CHANGE_CIPHER_SPEC_RECV_EXPECTING_FINISHED;
	return true;
}

static bool tls_client_connection_recv_application_data(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA) {
		DEBUG_WARN("unexpected application_data in state %u", tls_conn->state);
		return false;
	}

	if (!tls_client_connection_record_recv_decrypt(tls_conn, TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA, nb)) {
		return false;
	}

	if (tls_conn->recv_callback) {
		tls_conn->recv_callback(tls_conn->callback_arg, nb);
	}

	return true;
}

static bool tls_client_connection_recv_alert(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	if (!tls_client_connection_record_recv_decrypt(tls_conn, TLS_RECORD_CONTENT_TYPE_ALERT, nb)) {
		DEBUG_WARN("failed to decrypt alert:");
		return false;
	}

	if (!netbuf_fwd_check_space(nb, 2)) {
		DEBUG_WARN("alert length error");
		return false;
	}

	uint8_t __unused alert_level = netbuf_fwd_read_u8(nb);
	uint8_t alert_type = netbuf_fwd_read_u8(nb);

	switch (alert_type) {
	case TLS_ALERT_CLOSE_NOTIFY:
		DEBUG_INFO("close notify alert");
		tls_conn->close_reason = 0; /* no error */
		return false;

	default:
		DEBUG_INFO("alert level=%u type=%u", alert_level, alert_type);
		return false;
	}
}

static bool tls_client_connection_recv_record(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	uint8_t record_content_type = netbuf_fwd_read_u8(nb);

	uint16_t version = netbuf_fwd_read_u16(nb);
	if (version != TLS_VERSION) {
		DEBUG_WARN("unexpected version 0x%04x", version);
		return false;
	}

	netbuf_advance_pos(nb, 2);
	netbuf_set_start_to_pos(nb);

	switch (record_content_type) {
	case TLS_RECORD_CONTENT_TYPE_HANDSHAKE:
		return tls_client_connection_recv_handshake(tls_conn, nb);

	case TLS_RECORD_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
		return tls_client_connection_recv_change_cipher_spec(tls_conn, nb);

	case TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA:
		return tls_client_connection_recv_application_data(tls_conn, nb);

	case TLS_RECORD_CONTENT_TYPE_ALERT:
		return tls_client_connection_recv_alert(tls_conn, nb);

	default:
		DEBUG_ERROR("unexpected content type 0x%02x", record_content_type);
		return false;
	}
}

static size_t tls_client_connection_recv_required_length(struct netbuf *nb)
{
	if (!netbuf_fwd_check_space(nb, 5)) {
		return 5;
	}

	netbuf_advance_pos(nb, 3);
	size_t length = netbuf_fwd_read_u16(nb) + 5;
	netbuf_retreat_pos(nb, 5);
	return length;
}

static void tls_client_connection_tcp_recv_callback(void *arg, struct netbuf *nb)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;

	if (tls_conn->partial_rxnb) {
		netbuf_set_pos_to_start(tls_conn->partial_rxnb);
		size_t length = netbuf_get_remaining(tls_conn->partial_rxnb);

		if (!netbuf_rev_make_space(nb, length)) {
			DEBUG_ERROR("out of memory");
			tls_client_connection_close_and_notify(tls_conn);
			return;
		}

		netbuf_rev_copy(nb, tls_conn->partial_rxnb, length);

		netbuf_free(tls_conn->partial_rxnb);
		tls_conn->partial_rxnb = NULL;
	}

	while (1) {
		size_t required = tls_client_connection_recv_required_length(nb);
		if (required > min(TLS_MAX_RECORD_LENGTH, NETBUF_MAX_LENGTH)) {
			DEBUG_ERROR("record too big");
			tls_client_connection_close_and_notify(tls_conn);
			return;
		}

		size_t available = netbuf_get_remaining(nb);
		if (required > available) {
			tls_conn->partial_rxnb = netbuf_alloc_and_steal(nb);
			if (!tls_conn->partial_rxnb) {
				DEBUG_ERROR("out of memory");
				tls_client_connection_close_and_notify(tls_conn);
				return;
			}

			return;
		}

		if (required == available) {
			tls_client_connection_ref(tls_conn);
			bool success = tls_client_connection_recv_record(tls_conn, nb);
			if (tls_client_connection_deref(tls_conn) == 0) {
				return;
			}
			if (!success) {
				tls_client_connection_close_and_notify(tls_conn);
				return;
			}

			return;
		}

		struct netbuf *subnb = netbuf_clone(nb);
		if (!subnb) {
			DEBUG_ERROR("out of memory");
			tls_client_connection_close_and_notify(tls_conn);
			return;
		}

		netbuf_set_end(subnb, netbuf_get_pos(subnb) + required);
		netbuf_advance_pos(nb, required);
		netbuf_set_start_to_pos(nb);

		tls_client_connection_ref(tls_conn);
		bool success = tls_client_connection_recv_record(tls_conn, subnb);
		netbuf_free(subnb);
		if (tls_client_connection_deref(tls_conn) == 0) {
			return;
		}
		if (!success) {
			tls_client_connection_close_and_notify(tls_conn);
			return;
		}
	}
}

static void tls_client_connection_tcp_establish_callback(void *arg)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)arg;

	if (!tls_client_connection_send_client_hello(tls_conn)) {
		tls_client_connection_close_and_notify(tls_conn);
		return;
	}

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_CLIENT_HELLO_SENT_EXPECTING_SERVER_HELLO;
}

bool tls_client_connection_connect(struct tls_client_connection_t *tls_conn, ipv4_addr_t dest_addr, uint16_t dest_port, ipv4_addr_t src_addr, uint16_t src_port, const char *host_name, tls_client_establish_callback_t est, tls_client_recv_callback_t recv, tls_client_send_resume_callback_t send_resume, tls_client_close_callback_t close, void *callback_arg)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_NULL) {
		DEBUG_ASSERT(0, "attempt to connect when already active");
		return false;
	}

	tls_conn->host_name = heap_strdup(host_name, PKG_OS, MEM_TYPE_OS_TLS_CLIENT_CONNECTION);
	if (!tls_conn->host_name) {
		DEBUG_ERROR("out of memory");
		return false;
	}

	tls_conn->establish_callback = est;
	tls_conn->recv_callback = recv;
	tls_conn->send_resume_callback = send_resume;
	tls_conn->close_callback = close;
	tls_conn->callback_arg = callback_arg;

	tls_conn->state = TLS_CLIENT_CONNECTION_STATE_CONNECTING;

	tls_conn->conn = tcp_connection_alloc();
	if (!tls_conn->conn) {
		DEBUG_ERROR("tcp_connection_alloc failed");
		tls_client_connection_close(tls_conn);
		return false;
	}

	tcp_connection_set_max_recv_nb_size(tls_conn->conn, min(TLS_MAX_RECORD_LENGTH, NETBUF_MAX_LENGTH));

	tcp_error_t ret = tcp_connection_connect(tls_conn->conn, dest_addr, dest_port, src_addr, src_port, tls_client_connection_tcp_establish_callback, tls_client_connection_tcp_recv_callback, tls_client_connection_tcp_send_resume_callback, tls_client_connection_tcp_close_callback, tls_conn);
	if (ret != TCP_OK) {
		DEBUG_ERROR("tcp_connection_connect failed");
		tcp_connection_deref(tls_conn->conn);
		tls_conn->conn = NULL;
		tls_client_connection_close(tls_conn);
		return false;
	}

	return true;
}

bool tls_client_connection_send_netbuf(struct tls_client_connection_t *tls_conn, struct netbuf *nb)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA) {
		return false;
	}

	while (1) {
		size_t remaining = netbuf_get_remaining(nb);
		if (remaining <= TLS_MAX_APPLICATION_DATA_LENGTH) {
			return tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA, nb);
		}

		struct netbuf *nb_clone = netbuf_clone(nb);
		if (!nb_clone) {
			DEBUG_ERROR("out of memory");
			return false;
		}

		netbuf_advance_pos(nb, TLS_MAX_APPLICATION_DATA_LENGTH);
		netbuf_set_start_to_pos(nb);

		netbuf_set_end(nb_clone, netbuf_get_pos(nb_clone) + TLS_MAX_APPLICATION_DATA_LENGTH);
		bool success = tls_client_connection_record_send(tls_conn, TLS_RECORD_CONTENT_TYPE_APPLICATION_DATA, nb_clone);
		netbuf_free(nb_clone);
		if (!success) {
			return false;
		}
	}
}

bool tls_client_connection_can_send(struct tls_client_connection_t *tls_conn)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA) {
		return false;
	}

	return tcp_connection_can_send(tls_conn->conn) == TCP_OK;
}

void tls_client_connection_pause_recv(struct tls_client_connection_t *tls_conn)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA) {
		return;
	}

	tcp_connection_pause_recv(tls_conn->conn);
}

void tls_client_connection_resume_recv(struct tls_client_connection_t *tls_conn)
{
	if (tls_conn->state != TLS_CLIENT_CONNECTION_STATE_APPLICATION_DATA) {
		return;
	}

	tcp_connection_resume_recv(tls_conn->conn);
}

ipv4_addr_t tls_client_connection_get_local_addr(struct tls_client_connection_t *tls_conn)
{
	if (!tls_conn->conn) {
		return 0;
	}

	return tcp_connection_get_local_addr(tls_conn->conn);
}

ipv4_addr_t tls_client_connection_get_remote_addr(struct tls_client_connection_t *tls_conn)
{
	if (!tls_conn->conn) {
		return 0;
	}

	return tcp_connection_get_remote_addr(tls_conn->conn);
}

struct tls_client_connection_t *tls_client_connection_alloc(void)
{
	struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)heap_alloc_and_zero(sizeof(struct tls_client_connection_t), PKG_OS, MEM_TYPE_OS_TLS_CLIENT_CONNECTION);
	if (!tls_conn) {
		DEBUG_WARN("out of memory");
		return NULL;
	}

	tls_conn->refs = 1;
	tls_conn->close_reason = TCP_ERROR_FAILED;

	return tls_conn;
}

static void tls_client_load_certs_from_appfs_file(const char *filename, struct slist_t *certs)
{
	size_t file_length;
	uint8_t *file_start = appfs_file_mmap(filename, "", &file_length);
	if (!file_start) {
		return;
	}

	uint8_t *ptr = file_start;
	uint8_t *end = file_start + file_length;
	while (ptr < end) {
		size_t cert_length = x509_certificate_import_length(ptr, end - ptr);
		if (cert_length == 0) {
			break;
		}

		struct x509_certificate_t *cert = x509_certificate_import_no_copy(ptr, cert_length);
		if (!cert) {
			DEBUG_WARN("bad cert data in cert at 0x%08x", (unsigned int)(ptr - file_start));
			ptr += cert_length;
			continue;
		}

		slist_attach_tail(struct x509_certificate_t, certs, cert);
		ptr += cert_length;
	}
}

void tls_client_set_client_cert_appfs(const char *client_crt_appfs_filename, const char *client_key_appfs_filename)
{
	if (tls_client_manager.client_key_optional) {
		slist_clear(struct x509_certificate_t, &tls_client_manager.client_cert_chain_optional, x509_certificate_free);
		rsa_key_free(tls_client_manager.client_key_optional);
		tls_client_manager.client_key_optional = NULL;
	}

	size_t key_length;
	uint8_t *key_data = appfs_file_mmap(client_key_appfs_filename, "", &key_length);
	if (!key_data) {
		DEBUG_ERROR("failed to load client key %s", client_key_appfs_filename);
		return;
	}

	tls_client_manager.client_key_optional = rsa_key_import_private(key_data, key_length);
	if (!tls_client_manager.client_key_optional) {
		DEBUG_ERROR("failed to load client key %s", client_key_appfs_filename);
		return;
	}

	tls_client_load_certs_from_appfs_file(client_crt_appfs_filename, &tls_client_manager.client_cert_chain_optional);
	if (!slist_get_head(struct x509_certificate_t, &tls_client_manager.client_cert_chain_optional)) {
		DEBUG_ERROR("failed to load client certificate %s", client_crt_appfs_filename);
		rsa_key_free(tls_client_manager.client_key_optional);
		return;
	}
}

void tls_client_init()
{
	tls_client_load_certs_from_appfs_file("/tls/public_root_certs", &tls_client_manager.root_certs);
	DEBUG_INFO("imported %u root certs", slist_get_count(&tls_client_manager.root_certs));

	size_t length;
	if (appfs_file_mmap("/tls/client.key", "", &length)) {
		tls_client_set_client_cert_appfs("/tls/client.crt", "/tls/client.key");
	}
}

#if defined(DEBUG)
void tls_client_test(void)
{
	{
		struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)heap_alloc_and_zero(sizeof(struct tls_client_connection_t), PKG_OS, MEM_TYPE_OS_TLS_CLIENT_CONNECTION);
		uint8_t client_random[32] = { 0x29, 0xA1, 0x22, 0x22, 0x95, 0x3B, 0xD5, 0x7E, 0x3A, 0x69, 0xC4, 0x55, 0x29, 0xDA, 0xAF, 0x92, 0xC5, 0xC9, 0x76, 0x13, 0x72, 0x21, 0x45, 0xCE, 0xF2, 0x7D, 0xAB, 0x4F, 0xC7, 0x84, 0x4E, 0x76 };
		memcpy(tls_conn->client_random, client_random, 32);
		uint8_t server_random[32] = { 0x20, 0x2F, 0x43, 0x4D, 0x73, 0xFF, 0x75, 0x24, 0xF1, 0x88, 0x19, 0xB2, 0x6E, 0x1F, 0x09, 0x70, 0x31, 0xB9, 0x0B, 0x8E, 0x8F, 0xF5, 0x3F, 0x7E, 0xF8, 0x02, 0x47, 0xFF, 0xD4, 0x51, 0x34, 0xCC };
		memcpy(tls_conn->server_random, server_random, 32);

		uint8_t pre_master_secret[48] = { 0x03, 0x03, 0xDB, 0x9D, 0xB8, 0xA9, 0xCF, 0xFB, 0x6B, 0xEF, 0x62, 0x0D, 0xBF, 0xE3, 0x10, 0x14, 0x44, 0xD9, 0xEE, 0x61, 0x79, 0xE4, 0x07, 0x97, 0x34, 0xF5, 0xFF, 0x07, 0x8E, 0x03, 0xD1, 0xC9, 0x3A, 0xAB, 0x3A, 0x03, 0x07, 0x8C, 0xDE, 0x9F, 0x73, 0x84, 0x92, 0x6B, 0xE4, 0xFD, 0x08, 0xC3 };
		tls_client_connection_handshake_long_task_generate_master_secret_and_key_block(tls_conn, pre_master_secret);

		uint8_t expected_master_secret[48] = { 0x87, 0x05, 0x5C, 0x3C, 0xD1, 0xD8, 0x65, 0xFF, 0x2B, 0xAE, 0x56, 0xAB, 0x7F, 0xAC, 0x1C, 0x49, 0xEE, 0x99, 0x60, 0x0E, 0xB8, 0x10, 0x53, 0xB0, 0xDA, 0x13, 0xB0, 0x3C, 0x69, 0xDC, 0x87, 0xBD, 0x2F, 0x01, 0xBF, 0xF8, 0xE3, 0xA3, 0x3D, 0xC4, 0xCA, 0x04, 0x7D, 0x19, 0x4E, 0xAF, 0x94, 0xDE };
		uint8_t expected_client_write_mac_secret[20] = { 0x3A, 0x1F, 0x03, 0xC1, 0x17, 0x01, 0xCC, 0x46, 0x82, 0x4A, 0x43, 0x57, 0x7A, 0x82, 0x42, 0x44, 0xB7, 0xC6, 0xC4, 0xAD };
		uint8_t expected_server_write_mac_secret[20] = { 0xC9, 0x48, 0x75, 0x08, 0xB4, 0x63, 0x5E, 0xFF, 0x3A, 0xC4, 0x7D, 0x8D, 0x90, 0x6F, 0xAA, 0xF9, 0x8E, 0xF1, 0xA9, 0xDB };
		uint8_t expected_client_write_key[16] = { 0x9F, 0x1A, 0x24, 0xE8, 0xD8, 0x0E, 0x56, 0xB3, 0x91, 0xDC, 0x09, 0xF8, 0x93, 0x83, 0xFD, 0x90 };
		uint8_t expected_server_write_key[16] = { 0x95, 0x05, 0x45, 0xC8, 0x54, 0xBB, 0xE0, 0x4C, 0xB5, 0x91, 0x27, 0x66, 0xC6, 0x26, 0x29, 0x62 };
		uint8_t expected_client_write_iv[16] = { 0x6F, 0x58, 0xD7, 0x8F, 0x2E, 0x0F, 0x0B, 0xE8, 0xD9, 0x97, 0x94, 0xE8, 0xA4, 0xA1, 0x6A, 0xE7 };
		uint8_t expected_server_write_iv[16] = { 0xC6, 0x33, 0x99, 0x52, 0x55, 0xCE, 0x3E, 0x37, 0xF6, 0x3F, 0xA8, 0x19, 0x99, 0x8C, 0xA9, 0x60 };
		DEBUG_ASSERT(memcmp(tls_conn->master_secret, expected_master_secret, 48) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");
		DEBUG_ASSERT(memcmp(tls_conn->client_write_mac_secret, expected_client_write_mac_secret, 20) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");
		DEBUG_ASSERT(memcmp(tls_conn->server_write_mac_secret, expected_server_write_mac_secret, 20) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");
		DEBUG_ASSERT(memcmp(tls_conn->client_write_key.u8, expected_client_write_key, 16) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");
		DEBUG_ASSERT(memcmp(tls_conn->server_write_key.u8, expected_server_write_key, 16) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");
		DEBUG_ASSERT(memcmp(tls_conn->client_write_iv.u8, expected_client_write_iv, 16) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");
		DEBUG_ASSERT(memcmp(tls_conn->server_write_iv.u8, expected_server_write_iv, 16) == 0, "tls_client_connection_generate_master_secret_and_key_block failed");

		heap_free(tls_conn);
	}

	{
		struct tls_client_connection_t *tls_conn = (struct tls_client_connection_t *)heap_alloc_and_zero(sizeof(struct tls_client_connection_t), PKG_OS, MEM_TYPE_OS_TLS_CLIENT_CONNECTION);
		tls_conn->encrypt = true;
		uint8_t client_write_mac_secret[20] = { 0x88, 0xFF, 0x30, 0xBE, 0x8B, 0x4A, 0x93, 0x08, 0x4C, 0x2E, 0x06, 0xD3, 0x9A, 0x3B, 0x78, 0xFD, 0xC3, 0x8D, 0xAD, 0xE4 };
		memcpy(tls_conn->client_write_mac_secret, client_write_mac_secret, 20);
		uint8_t client_write_key[16] = { 0xBA, 0x5B, 0x3E, 0x6B, 0xF9, 0x11, 0x6D, 0xE9, 0x9E, 0x89, 0xD7, 0x8E, 0x52, 0xF1, 0x0C, 0xA7 };
		memcpy(tls_conn->client_write_key.u8, client_write_key, 16);
		uint8_t client_write_iv[16] = { 0x2F, 0xCF, 0xAF, 0x39, 0x26, 0x4A, 0xCC, 0xDA, 0xA3, 0x7F, 0x03, 0xE8, 0x8B, 0x41, 0x34, 0x97 };
		memcpy(tls_conn->client_write_iv.u8, client_write_iv, 16);

		uint8_t payload[16] = { 0x14, 0x00, 0x00, 0x0C, 0x94, 0xB1, 0xFA, 0xA7, 0xFF, 0x8D, 0x96, 0x83, 0x2E, 0x8E, 0x88, 0x16 };
		struct netbuf *nb = netbuf_alloc_with_fwd_space(16);
		netbuf_fwd_write(nb, payload, 16);
		netbuf_set_pos_to_start(nb);

		uint8_t override_iv[16] = { 0xED, 0x26, 0x06, 0x40, 0xBF, 0xE3, 0x33, 0xCC, 0x31, 0x7C, 0x5A, 0x8B, 0x8F, 0x2C, 0x0C, 0x4C };
		tls_client_connection_record_send_encrypt(tls_conn, TLS_RECORD_CONTENT_TYPE_HANDSHAKE, override_iv, nb);

		uint8_t expected[64] = { 0xBA, 0x70, 0x6A, 0x3A, 0xAB, 0x3E, 0xB5, 0x25, 0x28, 0x79, 0x58, 0xDC, 0x69, 0x94, 0x52, 0x07, 0x55, 0x3E, 0xCB, 0x94, 0xE6, 0xCB, 0x61, 0x14, 0x4B, 0xBA, 0xAA, 0x33, 0x46, 0xAC, 0x5B, 0xAB, 0x71, 0x45, 0xC1, 0x37, 0xFD, 0xEB, 0x83, 0xC1, 0x16, 0x38, 0x4B, 0xDD, 0x88, 0x0E, 0xF3, 0x10, 0x53, 0x87, 0xD0, 0x13, 0xE1, 0xF2, 0x3C, 0xDC, 0x69, 0xB6, 0x2C, 0x17, 0x3A, 0xCB, 0xEB, 0xB8 };
		DEBUG_ASSERT(netbuf_fwd_memcmp(nb, expected, 64) == 0, "tls_client_connection_record_send_encrypt failed");

		netbuf_free(nb);
		heap_free(tls_conn);
	}

	{
		const char *data_hex = "0100008F0303D23B358DA3A031CE3C8C96E4286762F369FF863A1CFD13088B144AE6EA3D486B000004002F00FF010000620000001C001A000017746C73746573742E73696C69636F6E647573742E6E6574337400000010000E000C02683208687474702F312E310016000000170000000D0020001E0601060206030501050205030401040204030301030203030201020202030200006003038714E73B3FF0F564968AE3C76B74734984324F849B6D62B58A37BED9665907692018D53A133EDE8095D1475A2597D6F6986472C9BE2EDEBEF69E91E2022076995A002F00001800000000FF010001000010000B000908687474702F312E310B00152B00152800055E3082055A30820442A0030201020210695A703DD89A683A364C9E918223DFDF300D06092A864886F70D01010B0500308190310B3009060355040613024742311B30190603550408131247726561746572204D616E636865737465723110300E0603550407130753616C666F7264311A3018060355040A1311434F4D4F444F204341204C696D69746564313630340603550403132D434F4D4F444F2052534120446F6D61696E2056616C69646174696F6E2053656375726520536572766572204341301E170D3138303330393030303030305A170D3230303430353233353935395A305E3121301F060355040B1318446F6D61696E20436F6E74726F6C2056616C696461746564311D301B060355040B1314506F73697469766553534C2057696C6463617264311A301806035504030C112A2E73696C69636F6E647573742E636F6D30820122300D06092A864886F70D01010105000382010F003082010A0282010100D7CDBB0D9EFAA3FE33B118963D7BAC5A78E8B1C48EC49217F2538A8FB64C6F0CDE79F10199B31E9BAF62D3B9CEE70DA0D2D47FC5DD8E8AF4A84DB65D6DA7102AF0436ED7EA4A47747340ADD1B4398B8454AC15FBD51E161D2FE9DA3130E6F10DFA5D9B485A8A1AB223BD6DDC355FD73BB43AFB5DE07F03FCB5025F520DD694EEF249443DA1F7762FCD1FABFE6590D169C008E742A4B926B5E3283E0BB848E2A58969FF3B770A4DFF40C1D0C21B3510F4EB7429A7D6F9457388963491E5DCBC24EC55AD7CDC4A83C046953DEDFBFA2ADF89E74A8A02B2BAF332428CC97CE19A68B8036FD4EE4BA6F0877A8AC16D4502EF4CE1E372A91A752ADD08655EF6BA22530203010001A38201DF308201DB301F0603551D2304183016801490AF6A3A945A0BD890EA125673DF43B43A28DAE7301D0603551D0E041604141D89E43126E0DA678B35E633964365FBB654F846300E0603551D0F0101FF0404030205A0300C0603551D130101FF04023000301D0603551D250416301406082B0601050507030106082B06010505070302304F0603551D2004483046303A060B2B06010401B23101020207302B302906082B06010505070201161D68747470733A2F2F7365637572652E636F6D6F646F2E636F6D2F4350533008060667810C01020130540603551D1F044D304B3049A047A0458643687474703A2F2F63726C2E636F6D6F646F63612E636F6D2F434F4D4F444F525341446F6D61696E56616C69646174696F6E53656375726553657276657243412E63726C30818506082B0601050507010104793077304F06082B060105050730028643687474703A2F2F6372742E636F6D6F646F63612E636F6D2F434F4D4F444F525341446F6D61696E56616C69646174696F6E53656375726553657276657243412E637274302406082B060105050730018618687474703A2F2F6F6373702E636F6D6F646F63612E636F6D302D0603551D110426302482112A2E73696C69636F6E647573742E636F6D820F73696C69636F6E647573742E636F6D300D06092A864886F70D01010B050003820101007668C2B70E91FE9DB77884AA717D009F1B81276F11BDB125BF97C1664A357283B76C5B26CA30EE069909D938C35427F56821EAB5F75283C15C9A79B15161E14CA7E33E7CB9DD6AC06C45EE7181AD47C3D07C39FA1935F42EF60870AE22C20730CCD6F587E71AA2BACC581EB82C9162333826359A4DE70A8A6834E636E30C5C2C704D139FFFFED30DA0D17B5BAE7BD24A603035664D35131A90FCF7681DA278B2479C4F66D750FA4962223731013E12990803D7ED794BFD3F098E85B68C8CE10FCDE54DBE063836310FAB00126EC3FFE4EBD32DFB05C36C2B375102C49CEBFDB6C6BA2BB0FB72428808CA8A4CA5030FD9BE141D5B75FE64A843AF8935B0559A8C00060C30820608308203F0A00302010202102B2E6EEAD975366C148A6EDBA37C8C07300D06092A864886F70D01010C0500308185310B3009060355040613024742311B30190603550408131247726561746572204D616E636865737465723110300E0603550407130753616C666F7264311A3018060355040A1311434F4D4F444F204341204C696D69746564312B302906035504031322434F4D4F444F205253412043657274696669636174696F6E20417574686F72697479301E170D3134303231323030303030305A170D3239303231313233353935395A308190310B3009060355040613024742311B30190603550408131247726561746572204D616E636865737465723110300E0603550407130753616C666F7264311A3018060355040A1311434F4D4F444F204341204C696D69746564313630340603550403132D434F4D4F444F2052534120446F6D61696E2056616C69646174696F6E205365637572652053657276657220434130820122300D06092A864886F70D01010105000382010F003082010A02820101008EC20219E1A059A4EB38358D2CFD01D0D349C064C70B620545163AA8A0C00C027F1DCCDBC4A16D7703A30F86F9E3069C3E0B818A9B491BAD03BEFA4BDB8C20EDD5CE5E658E3E0DAF4CC2B0B7455E522F34DE482464B441AE0097F7BE67DE9ED07AA753803B7CADF596556F97470A7C858B22978DB384E09657D0701860968FEE2D07939DA1BACAD1CD7BE9C42A9A2821914D6F924F25A5F27A35DD26DC46A5D0AC59358CFF4E9143503F59931E6C5121EE5814ABFE7550783E4CB01C8613FA6B98BCE03B941E8552DC039324186ECB275145E670DE2543A40DE14AA5EDB67EC8CD6DEE2E1D27735DDC453080AAE3B2410BAFBD4487DAB9E51B9D7FAEE58582A50203010001A382016530820161301F0603551D23041830168014BBAF7E023DFAA6F13C848EADEE3898ECD93232D4301D0603551D0E0416041490AF6A3A945A0BD890EA125673DF43B43A28DAE7300E0603551D0F0101FF04040302018630120603551D130101FF040830060101FF020100301D0603551D250416301406082B0601050507030106082B06010505070302301B0603551D200414301230060604551D20003008060667810C010201304C0603551D1F044530433041A03FA03D863B687474703A2F2F63726C2E636F6D6F646F63612E636F6D2F434F4D4F444F52534143657274696669636174696F6E417574686F726974792E63726C307106082B0601050507010104653063303B06082B06010505073002862F687474703A2F2F6372742E636F6D6F646F63612E636F6D2F434F4D4F444F525341416464547275737443412E637274302406082B060105050730018618687474703A2F2F6F6373702E636F6D6F646F63612E636F6D300D06092A864886F70D01010C050003820201004E2B764F921C623689BA77C12705F41CD6449DA99A3EAAD56666013EEA49E6A235BCFAF6DD958E9935980E361875B1DDDD50727CAEDC7788CE0FF79020CAA3672E1F567F7BE144EA4295C45D0D01504615F28189596C8ADD8CF112A18D3A428A98F84B347B273B08B46F243B729D6374583C1A6C3F4FC7119AC8A8F5B537EF1045C66CD9E05E9526B3EBADA3B9EE7F0C9A66357332604EE5DD8A612C6E5211776896D318755115001B7488DDE1C738044328E916FDD905D45D472760D6FB383B6C72A294F8421ADFED6F068C45C20600AAE4E8DCD9B5E17378ECF623DCD1DD6C8E1A8FA5EA547C96B7C3FE558E8D495EFC64BBCF3EBD96EB69CDBFE048F1628210E50C4657F233DAD0C863EDC61F9405964A1A91D1F7EBCF8F52AE0D08D93EA8A051E9C18774D5C9F774AB2E53FBBB7AFB97E2F81F268FB3D2A0E0375B283B31E50E572D5AB8AD79AC5E20661AA5B9A6B539C1F59843FFEEF9A7A7FDEECA243D8016C4178F8AC160A10CAE5B4347914BD59A175FF9D487C1C28CB7E7E20F30193786ACE0DC4203E694A89DAEFD0F245194CE9208D1FC50F003407B8859ED0EDDACD2778234DC069502D890F92DEA37D51A60D06720D7D8420B45AF8268DEDD66243790299419461925B880D7CBD486286A4470262362A99F866FBFBA9070D256778578EFEA25A917CE50728C003AAAE3DB63349FF8067101E28220D4FE6FBDB1000578308205743082045CA00302010202102766EE56EB49F38EABD770A2FC84DE22300D06092A864886F70D01010C0500306F310B300906035504061302534531143012060355040A130B416464547275737420414231263024060355040B131D41646454727573742045787465726E616C20545450204E6574776F726B312230200603550403131941646454727573742045787465726E616C20434120526F6F74301E170D3030303533303130343833385A170D3230303533303130343833385A308185310B3009060355040613024742311B30190603550408131247726561746572204D616E636865737465723110300E0603550407130753616C666F7264311A3018060355040A1311434F4D4F444F204341204C696D69746564312B302906035504031322434F4D4F444F205253412043657274696669636174696F6E20417574686F7269747930820222300D06092A864886F70D01010105000382020F003082020A028202010091E85492D20A56B1AC0D24DDC5CF446774992B37A37D23700071BC53DFC4FA2A128F4B7F1056BD9F7072B7617FC94B0F17A73DE3B00461EEFF1197C7F4863E0AFA3E5CF993E6347AD9146BE79CB385A0827A76AF7190D7ECFD0DFA9C6CFADFB082F4147EF9BEC4A62F4F7F997FB5FC674372BD0C00D689EB6B2CD3ED8F981C14AB7EE5E36EFCD8A8E49224DA436B62B855FDEAC1BC6CB68BF30E8D9AE49B6C6999F878483045D5ADE10D3C4560FC32965127BC67C3CA2EB66BEA46C7C720A0B11F65DE4808BAA44EA9F283463784EBE8CC814843674E722A9B5CBD4C1B288A5C227BB4AB98D9EEE05183C309464E6D3E99FA9517DA7C3357413C8D51ED0BB65CAF2C631ADF57C83FBCE95DC49BAF4599E2A35A24B4BAA9563DCF6FAAFF4958BEF0A8FFF4B8ADE937FBBAB8F40B3AF9E843421E89D884CB13F1D9BBE18960B88C2856AC141D9C0AE771EBCF0EDD3DA996A148BD3CF7AFB50D224CC01181EC563BF6D3A2E25BB7B204225295809369E88E4C65F191032D707402EA8B671529695202BBD7DF506A5546BFA0A328617F70D0C3A2AA2C21AA47CE289C064576BF821827B4D5AEB4CB50E66BF44C867130E9A6DF1686E0D8FF40DDFBD042887FA3333A2E5C1E41118163CE18716B2BECA68AB7315C3A6A47E0C37959D6201AAFF26A98AA72BC574AD24B9DBB10FCB04C41E5ED1D3D5E289D9CCCBFB351DAA747E584530203010001A381F43081F1301F0603551D23041830168014ADBD987A34B426F7FAC42654EF03BDE024CB541A301D0603551D0E04160414BBAF7E023DFAA6F13C848EADEE3898ECD93232D4300E0603551D0F0101FF040403020186300F0603551D130101FF040530030101FF30110603551D20040A300830060604551D200030440603551D1F043D303B3039A037A0358633687474703A2F2F63726C2E7573657274727573742E636F6D2F416464547275737445787465726E616C4341526F6F742E63726C303506082B0601050507010104293027302506082B060105050730018619687474703A2F2F6F6373702E7573657274727573742E636F6D300D06092A864886F70D01010C0500038201010064BF83F15F9A85D0CDB8A129570DE85AF7D1E93EF276046EF15270BB1E3CFF4D0D746ACC818225D3C3A02A5D4CF5BA8BA16DC4540975C7E3270E5D847937401377F5B4AC1CD03BAB1712D6EF34187E2BE979D3AB57450CAF28FAD0DBE5509588BBDF8557697D92D852CA7381BF1CF3E6B86E661105B31E942D7F91959259F14CCEA391714C7C470C3B0B19F6A1B16C863E5CAAC42E82CBF90796BA484D90F294C8A973A2EB067B239DDEA2F34D559F7A6145981868C75E406B23F5797AEF8CB56B8BB76F46F47BF13D4B04D89380595AE041241DB28F15605847DBEF6E46FD15F5D95F9AB3DBD8B8E440B3CD9739AE85BB1D8EBCDC879BD1A6EFF13B6F10386F00043A308204363082031EA003020102020101300D06092A864886F70D0101050500306F310B300906035504061302534531143012060355040A130B416464547275737420414231263024060355040B131D41646454727573742045787465726E616C20545450204E6574776F726B312230200603550403131941646454727573742045787465726E616C20434120526F6F74301E170D3030303533303130343833385A170D3230303533303130343833385A306F310B300906035504061302534531143012060355040A130B416464547275737420414231263024060355040B131D41646454727573742045787465726E616C20545450204E6574776F726B312230200603550403131941646454727573742045787465726E616C20434120526F6F7430820122300D06092A864886F70D01010105000382010F003082010A0282010100B7F71A33E6F200042D39E04E5BED1FBC6C0FCDB5FA23B6CEDE9B113397A4294C7D939FBD4ABC93ED031AE38FCFE56D505AD69729945A80B0497ADB2E95FDB8CABF37382D1E3E9141AD7056C7F04F3FE8329E74CAC89054E9C65F0F789D9A403C0EAC61AA5E148F9E87A16A50DCD79A4EAF05B3A671949C71B350600AC7139D38078602A8E9A869261890AB4CB04F23AB3A4F84D8DFCE9FE1696FBBD742D76B44E4C7ADEE6D415F725A710837B37965A459A09437F7002F0DC29272DAD03872DB14A845C45D2A7DB7B4D6C4EEACCD1344B7C92BDD430025FA61B9696A582311B7A7338F567559F5CD29D746B70A2B65B6D3426F15B2B87BFBEFE95D53D5345A270203010001A381DC3081D9301D0603551D0E04160414ADBD987A34B426F7FAC42654EF03BDE024CB541A300B0603551D0F040403020106300F0603551D130101FF040530030101FF3081990603551D2304819130818E8014ADBD987A34B426F7FAC42654EF03BDE024CB541AA173A471306F310B300906035504061302534531143012060355040A130B416464547275737420414231263024060355040B131D41646454727573742045787465726E616C20545450204E6574776F726B312230200603550403131941646454727573742045787465726E616C20434120526F6F74820101300D06092A864886F70D01010505000382010100B09BE08525C2D623E20F9606929D41989CD9847981D91E5B14072336658FB0D877BBAC416C47608351B0F9323DE7FCF62613C78016A5BF5AFC87CF787989219AE24C070A8635BCF2DE51C4D296B7DC7E4EEE70FD1C39EB0C0251142D8EBD16E0C1DF4675E724ADECF442B48593701067BA9D06354A18D32B7ACC5142A17A63D1E6BBA1C52BC236BE130DE6BD637E797BA7090D40AB6ADD8F8AC3F6F68C1A420551D445F59FA76221681520433C99E77CBD24D8A9911773883F561B313818B4710F9ACDC80E9E8E2E1BE18C9883CB1F31F1444CC604734976600FC7F8BD17806B2EE9CC4C0E5A9A790F200A2ED59E63261E559294D882175A7BD0BCC78F4E86040E0000001000010201006E9D1795A71A70667481D207EE123D5350180E7AC516534126EB44143E4773344F1FBD534A427EB6D3B926F80005BA1B1BEA73F04AA565682F8F3BE5D84034AAA63502E31544D2B63340FD7582DF66DFC1123FB84E2AD9A13207C13D644AD8CC013ACEE35024579E82BB72CC7C7F48FFAD84B770F0DDC70D2936946C33A1C06638FA7B4F8C3221AF571AB9641392DB4690F166098F2116A5BBC0E87979D49C51FDA5864F3931E486040F68FD16C7743643014C4F7124D2317CB002CA8CB6F2F44E152F88B3FABC7FBF0672C672B2B46E48910FFBD228F0AF9BAE62754BF7BEA90E8B16F2C62A33281FBFD7D33F9C07B3732FF120796B3C0A9B2FEA2387490A98";
		const char *hex_ptr = data_hex;
		size_t data_length = strlen(data_hex) / 2;

		struct netbuf *nb = netbuf_alloc_with_fwd_space(data_length);
		while (*hex_ptr) {
			char tmp[4];
			tmp[0] = *hex_ptr++;
			tmp[1] = *hex_ptr++;
			tmp[2] = 0;
			netbuf_fwd_write_u8(nb, (uint8_t)strtoul(tmp, NULL, 16));
		}

		sha256_digest_t sha256_hash;
		netbuf_set_pos_to_start(nb);
		sha256_compute_digest_netbuf(&sha256_hash, nb, netbuf_get_remaining(nb));

		uint8_t verify_data[12];
		uint8_t master_secret[48] = { 0x84, 0xA7, 0x4E, 0x29, 0x87, 0xC5, 0xD3, 0xFF, 0x14, 0x8C, 0x39, 0x83, 0xC8, 0x44, 0x5E, 0x58, 0x89, 0x33, 0x8F, 0x66, 0xF6, 0x39, 0xAA, 0x2A, 0xB3, 0x18, 0x64, 0x9B, 0xE4, 0xCF, 0x7D, 0x22, 0x32, 0xC8, 0x7D, 0x6D, 0x8A, 0xEA, 0x9A, 0xC7, 0x4A, 0x40, 0x39, 0xA5, 0x77, 0x03, 0xA2, 0xFA };
		tls_prf(verify_data, sizeof(verify_data), "client finished", sha256_hash.u8, sizeof(sha256_hash.u8), master_secret, sizeof(master_secret));

		uint8_t expected[12] = { 0x9F, 0x1C, 0xFD, 0x8F, 0x18, 0x0E, 0x3C, 0x29, 0x57, 0x3F, 0xA6, 0x7A };
		DEBUG_ASSERT(memcmp(verify_data, expected, 12) == 0, "verify_data failed");

		netbuf_free(nb);
	}
}
#endif
