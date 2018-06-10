/*
 * soap_action_args.c
 *
 * Copyright © 2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("soap_action_args");

bool soap_action_args_get_bool(struct soap_action_args_t *action_args, const char *name, bool *psuccess)
{
	return soap_action_args_get_u32(action_args, name, psuccess) != 0;
}

uint8_t soap_action_args_get_u8(struct soap_action_args_t *action_args, const char *name, bool *psuccess)
{
	return (uint8_t)soap_action_args_get_u32(action_args, name, psuccess);
}

uint16_t soap_action_args_get_u16(struct soap_action_args_t *action_args, const char *name, bool *psuccess)
{
	return (uint16_t)soap_action_args_get_u32(action_args, name, psuccess);
}

uint32_t soap_action_args_get_u32(struct soap_action_args_t *action_args, const char *name, bool *psuccess)
{
	const char *str = soap_action_args_get_string(action_args, name, psuccess);
	if (!str) {
		/* Error already flagged by get_string function. */
		return 0;
	}

	char *end = (char *)str;
	uint32_t result = (uint32_t)strtoul(str, &end, 0);
	if ((end == str) || (*end != 0)) {
		DEBUG_WARN("%s: %s not u32", name, str);
		*psuccess = false;
		return 0;
	}

	return result;
}

int32_t soap_action_args_get_s32(struct soap_action_args_t *action_args, const char *name, bool *psuccess)
{
	const char *str = soap_action_args_get_string(action_args, name, psuccess);
	if (!str) {
		/* Error already flagged by get_string function. */
		return 0;
	}

	char *end = (char *)str;
	int32_t result = (int32_t)strtol(str, &end, 0);
	if ((end == str) || (*end != 0)) {
		DEBUG_WARN("%s: %s not s32", name, str);
		*psuccess = false;
		return 0;
	}

	return result;
}

const char *soap_action_args_get_string(struct soap_action_args_t *action_args, const char *name, bool *psuccess)
{
	struct soap_action_arg_t *arg = slist_get_head(struct soap_action_arg_t, &action_args->arg_list);
	while (arg) {
		if (strcmp(name, arg->name) == 0) {
			DEBUG_INFO("%s = %s", name, arg->value);
			return arg->value;
		}

		arg = slist_get_next(struct soap_action_arg_t, arg);
	}

	DEBUG_WARN("%s not found", name);
	*psuccess = false;
	return NULL;
}

struct netbuf *soap_action_args_string_to_netbuf(const char *str)
{
	size_t length = strlen(str);
	struct netbuf *nb = netbuf_alloc_with_rev_space(length);
	if (!nb) {
		DEBUG_ERROR("out of memory");
		return NULL;
	}

	if (length > 0) {
		netbuf_rev_write(nb, str, length);
	}

	return nb;
}

static void soap_action_args_free_parser_name_value_netbufs(struct soap_action_args_t *action_args)
{
	if (action_args->parser_name_nb) {
		netbuf_free(action_args->parser_name_nb);
		action_args->parser_name_nb = NULL;
	}

	while (netbuf_queue_get_head(&action_args->parser_value_nb_list)) {
		netbuf_free(netbuf_queue_detach_head(&action_args->parser_value_nb_list));
	}
}

void soap_action_args_release_and_reset(struct soap_action_args_t *action_args)
{
	slist_clear(struct soap_action_arg_t, &action_args->arg_list, heap_free);
	soap_action_args_free_parser_name_value_netbufs(action_args);

	action_args->parser_result = 0;
	action_args->parser_state = 0;
	action_args->parser_element_level = 0;
}

static struct soap_action_arg_t *soap_action_args_create_and_add_arg(struct soap_action_args_t *action_args, struct netbuf *name_nb, struct netbuf_queue *value_nb_list)
{
	DEBUG_ASSERT(name_nb, "name_nb is null");
	size_t name_len = netbuf_get_remaining(name_nb);
	size_t value_len = 0;
	
	struct netbuf *value_nb = netbuf_queue_get_head(value_nb_list);
	while (value_nb) {
		value_len += netbuf_get_remaining(value_nb);
		value_nb = value_nb->next;
	}

	struct soap_action_arg_t *arg = (struct soap_action_arg_t *)heap_alloc(sizeof(struct soap_action_arg_t) + name_len + value_len + 2, PKG_OS, MEM_TYPE_OS_SOAP_ACTION_ARGS_ARG);
	if (!arg) {
		upnp_error_out_of_memory(__this_file, __LINE__);
		return NULL;
	}

	char *name = (char *)(arg + 1);
	netbuf_fwd_read(name_nb, name, name_len);
	name[name_len] = 0;

	char *value = name + name_len + 1;
	char *ptr = value;
	value_nb = netbuf_queue_get_head(value_nb_list);
	while (value_nb) {
		size_t len = netbuf_get_remaining(value_nb);
		netbuf_fwd_read(value_nb, ptr, len);
		ptr += len;
		value_nb = value_nb->next;
	}
	DEBUG_ASSERT((size_t)(ptr - value) == value_len, "internal length tracking error");
	*ptr = 0;

	memset(&arg->slist_prefix, 0, sizeof(arg->slist_prefix));
	arg->name = name;
	arg->value = value;

	slist_attach_head(struct soap_action_arg_t, &action_args->arg_list, arg);
	return arg;
}

#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ENVELOPE 0
#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY 1
#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME 2
#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER 3
#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_PARAMETER_TEXT_OR_CLOSE 4
#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY_CLOSE 5
#define SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ENVELOPE_CLOSE 6
#define SOAP_ACTION_ARGS_PARSER_STATE_COMPLETE 7

static xml_parser_error_t soap_action_args_xml_parser_element_name_start(struct soap_action_args_t *action_args, const char *action_name, struct netbuf *nb)
{
	switch (action_args->parser_state) {
	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ENVELOPE:
		if ((action_args->parser_element_level == 1) && (netbuf_fwd_strcmp(nb, "Envelope") == 0)) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY:
		if ((action_args->parser_element_level == 2) && (netbuf_fwd_strcmp(nb, "Body") == 0)) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME:
		if ((action_args->parser_element_level == 3) && (netbuf_fwd_strcmp(nb, action_name) == 0)) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER:
		if (action_args->parser_element_level == 4) {
			DEBUG_ASSERT(!action_args->parser_name_nb, "unexpected state");
			DEBUG_ASSERT(!netbuf_queue_get_head(&action_args->parser_value_nb_list), "unexpected state");

			action_args->parser_name_nb = netbuf_clone(nb);
			if (!action_args->parser_name_nb) {
				upnp_error_out_of_memory(__this_file, __LINE__);
				action_args->parser_result = SOAP_XML_PARSER_RESULT_ENOMEM;
				return XML_PARSER_ESTOP;
			}

			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_PARAMETER_TEXT_OR_CLOSE;
		}
		return XML_PARSER_OK;

	default:
		DEBUG_WARN("malformed or spurious tag in soap request");
		DEBUG_PRINT_NETBUF_TEXT(nb, 0);
		return XML_PARSER_OK;
	}
}

static xml_parser_error_t soap_action_args_xml_parser_element_name_end(struct soap_action_args_t *action_args, const char *action_name, struct netbuf *nb)
{
	switch (action_args->parser_state) {
	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ENVELOPE_CLOSE:
		if ((action_args->parser_element_level == 1) && (netbuf_fwd_strcmp(nb, "Envelope") == 0)) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_COMPLETE;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY_CLOSE:
		if ((action_args->parser_element_level == 2) && (netbuf_fwd_strcmp(nb, "Body") == 0)) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ENVELOPE_CLOSE;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER:
		if ((action_args->parser_element_level == 3) && (netbuf_fwd_strcmp(nb, action_name) == 0)) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY_CLOSE;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_PARAMETER_TEXT_OR_CLOSE:
		if (action_args->parser_element_level == 4) {
			if (!soap_action_args_create_and_add_arg(action_args, action_args->parser_name_nb, &action_args->parser_value_nb_list)) {
				soap_action_args_free_parser_name_value_netbufs(action_args);
				action_args->parser_result = SOAP_XML_PARSER_RESULT_ENOMEM;
				return XML_PARSER_ESTOP;
			}

			soap_action_args_free_parser_name_value_netbufs(action_args);
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER;
		}
		return XML_PARSER_OK;

	default:
		return XML_PARSER_OK;
	}
}

static xml_parser_error_t soap_action_args_xml_parser_element_self_close(struct soap_action_args_t *action_args, const char *action_name, struct netbuf *nb)
{
	switch (action_args->parser_state) {
	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER:
		if (action_args->parser_element_level == 3) {
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_BODY_CLOSE;
		}
		return XML_PARSER_OK;

	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_PARAMETER_TEXT_OR_CLOSE:
		if (action_args->parser_element_level == 4) {
			if (!soap_action_args_create_and_add_arg(action_args, action_args->parser_name_nb, &action_args->parser_value_nb_list)) {
				soap_action_args_free_parser_name_value_netbufs(action_args);
				action_args->parser_result = SOAP_XML_PARSER_RESULT_ENOMEM;
				return XML_PARSER_ESTOP;
			}

			soap_action_args_free_parser_name_value_netbufs(action_args);
			action_args->parser_state = SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_ACTION_NAME_CLOSE_OR_PARAMETER;
		}
		return XML_PARSER_OK;

	default:
		return XML_PARSER_OK;
	}
}

static xml_parser_error_t soap_action_args_xml_parser_element_text(struct soap_action_args_t *action_args, const char *action_name, struct netbuf *nb)
{
	switch (action_args->parser_state) {
	case SOAP_ACTION_ARGS_PARSER_STATE_WAITING_FOR_PARAMETER_TEXT_OR_CLOSE:
		if (action_args->parser_element_level == 4) {
			if (netbuf_get_remaining(nb) == 0) {
				return XML_PARSER_OK;
			}

			struct netbuf *nb_clone = netbuf_clone(nb);
			if (!nb_clone) {
				upnp_error_out_of_memory(__this_file, __LINE__);
				action_args->parser_result = SOAP_XML_PARSER_RESULT_ENOMEM;
				return XML_PARSER_ESTOP;
			}

			netbuf_queue_attach_tail(&action_args->parser_value_nb_list, nb_clone);
		}
		return XML_PARSER_OK;

	default:
		return XML_PARSER_OK;
	}
}

xml_parser_error_t soap_action_args_xml_parser_callback(struct soap_action_args_t *action_args, const char *action_name, xml_parser_event_t event, struct netbuf *nb)
{
	xml_parser_error_t ret;

	switch (event) {
	case XML_PARSER_EVENT_ELEMENT_START_NAME:
		action_args->parser_element_level++;
		DEBUG_TRACE("element start name (level %u)", action_args->parser_element_level);
		return soap_action_args_xml_parser_element_name_start(action_args, action_name, nb);

	case XML_PARSER_EVENT_ELEMENT_END_NAME:
		DEBUG_TRACE("element end name (level %u)", action_args->parser_element_level);
		ret = soap_action_args_xml_parser_element_name_end(action_args, action_name, nb);
		if (ret != XML_PARSER_OK) {
			return ret;
		}
		action_args->parser_element_level--;
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_SELF_CLOSE:
		DEBUG_TRACE("element self close (level %u)", action_args->parser_element_level);
		ret = soap_action_args_xml_parser_element_self_close(action_args, action_name, nb);
		if (ret != XML_PARSER_OK) {
			return ret;
		}
		action_args->parser_element_level--;
		return XML_PARSER_OK;

	case XML_PARSER_EVENT_ELEMENT_TEXT:
		DEBUG_TRACE("element text (level = %u)", action_args->parser_element_level);
		return soap_action_args_xml_parser_element_text(action_args, action_name, nb);

	case XML_PARSER_EVENT_PARSE_ERROR:
		DEBUG_WARN("xml reported error");
		action_args->parser_result = SOAP_XML_PARSER_RESULT_EPARSE;
		return XML_PARSER_ESTOP;

	case XML_PARSER_EVENT_INTERNAL_ERROR:
		upnp_error_out_of_memory(__this_file, __LINE__);
		action_args->parser_result = SOAP_XML_PARSER_RESULT_ENOMEM;
		return XML_PARSER_ESTOP;

	default:
		DEBUG_TRACE("event %u", event);
		return XML_PARSER_OK;
	}
}

bool soap_action_args_is_valid_complete(struct soap_action_args_t *action_args)
{
	if (action_args->parser_state != SOAP_ACTION_ARGS_PARSER_STATE_COMPLETE) {
		DEBUG_WARN("action name not found");
		return false;
	}

	return true;
}
