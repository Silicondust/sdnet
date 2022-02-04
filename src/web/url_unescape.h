/*
 * url_unescape.h
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* Unescapes the URL up until the query string. Returns the parse stop location or NULL on error */
extern const char *url_unescape(char *out, char *end, const char *in);
