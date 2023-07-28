/*
 * language.c
 *
 * Copyright © 2021 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("json_process");

struct language_iso639_entry_t {
	char iso639_2char[4];
	char iso639_3char[4];
};

static struct language_iso639_entry_t language_iso639_lookup_table[] =
{
	{ "aa", "aar" },
	{ "ab", "abk" },
	{ "ae", "ave" },
	{ "af", "afr" },
	{ "ak", "aka" },
	{ "am", "amh" },
	{ "an", "arg" },
	{ "ar", "ara" },
	{ "as", "asm" },
	{ "av", "ava" },
	{ "ay", "aym" },
	{ "az", "aze" },
	{ "ba", "bak" },
	{ "be", "bel" },
	{ "bg", "bul" },
	{ "bh", "bih" },
	{ "bi", "bis" },
	{ "bm", "bam" },
	{ "bn", "ben" },
	{ "bo", "bod" },
	{ "br", "bre" },
	{ "bs", "bos" },
	{ "ca", "cat" },
	{ "ce", "che" },
	{ "ch", "cha" },
	{ "co", "cos" },
	{ "cr", "cre" },
	{ "cs", "ces" },
	{ "cu", "chu" },
	{ "cv", "chv" },
	{ "cy", "cym" },
	{ "da", "dan" },
	{ "de", "deu" },
	{ "dv", "div" },
	{ "dz", "dzo" },
	{ "ee", "ewe" },
	{ "el", "ell" },
	{ "en", "eng" },
	{ "eo", "epo" },
	{ "es", "spa" },
	{ "et", "est" },
	{ "eu", "eus" },
	{ "fa", "fas" },
	{ "ff", "ful" },
	{ "fi", "fin" },
	{ "fj", "fij" },
	{ "fo", "fao" },
	{ "fr", "fra" },
	{ "fy", "fry" },
	{ "ga", "gle" },
	{ "gd", "gla" },
	{ "gl", "glg" },
	{ "gn", "grn" },
	{ "gu", "guj" },
	{ "gv", "glv" },
	{ "ha", "hau" },
	{ "he", "heb" },
	{ "hi", "hin" },
	{ "ho", "hmo" },
	{ "hr", "hrv" },
	{ "ht", "hat" },
	{ "hu", "hun" },
	{ "hy", "hye" },
	{ "hz", "her" },
	{ "ia", "ina" },
	{ "id", "ind" },
	{ "ie", "ile" },
	{ "ig", "ibo" },
	{ "ii", "iii" },
	{ "ik", "ipk" },
	{ "io", "ido" },
	{ "is", "isl" },
	{ "it", "ita" },
	{ "iu", "iku" },
	{ "ja", "jpn" },
	{ "jv", "jav" },
	{ "ka", "kat" },
	{ "kg", "kon" },
	{ "ki", "kik" },
	{ "kj", "kua" },
	{ "kk", "kaz" },
	{ "kl", "kal" },
	{ "km", "khm" },
	{ "kn", "kan" },
	{ "ko", "kor" },
	{ "kr", "kau" },
	{ "ks", "kas" },
	{ "ku", "kur" },
	{ "kv", "kom" },
	{ "kw", "cor" },
	{ "ky", "kir" },
	{ "la", "lat" },
	{ "lb", "ltz" },
	{ "lg", "lug" },
	{ "li", "lim" },
	{ "ln", "lin" },
	{ "lo", "lao" },
	{ "lt", "lit" },
	{ "lu", "lub" },
	{ "lv", "lav" },
	{ "mg", "mlg" },
	{ "mh", "mah" },
	{ "mi", "mri" },
	{ "mk", "mkd" },
	{ "ml", "mal" },
	{ "mn", "mon" },
	{ "mr", "mar" },
	{ "ms", "msa" },
	{ "mt", "mlt" },
	{ "my", "mya" },
	{ "na", "nau" },
	{ "nb", "nob" },
	{ "nd", "nde" },
	{ "ne", "nep" },
	{ "ng", "ndo" },
	{ "nl", "nld" },
	{ "nn", "nno" },
	{ "no", "nor" },
	{ "nr", "nbl" },
	{ "nv", "nav" },
	{ "ny", "nya" },
	{ "oc", "oci" },
	{ "oj", "oji" },
	{ "om", "orm" },
	{ "or", "ori" },
	{ "os", "oss" },
	{ "pa", "pan" },
	{ "pi", "pli" },
	{ "pl", "pol" },
	{ "ps", "pus" },
	{ "pt", "por" },
	{ "qu", "que" },
	{ "rm", "roh" },
	{ "rn", "run" },
	{ "ro", "ron" },
	{ "ru", "rus" },
	{ "rw", "kin" },
	{ "sa", "san" },
	{ "sc", "srd" },
	{ "sd", "snd" },
	{ "se", "sme" },
	{ "sg", "sag" },
	{ "si", "sin" },
	{ "sk", "slk" },
	{ "sl", "slv" },
	{ "sm", "smo" },
	{ "sn", "sna" },
	{ "so", "som" },
	{ "sq", "sqi" },
	{ "sr", "srp" },
	{ "ss", "ssw" },
	{ "st", "sot" },
	{ "su", "sun" },
	{ "sv", "swe" },
	{ "sw", "swa" },
	{ "ta", "tam" },
	{ "te", "tel" },
	{ "tg", "tgk" },
	{ "th", "tha" },
	{ "ti", "tir" },
	{ "tk", "tuk" },
	{ "tl", "tgl" },
	{ "tn", "tsn" },
	{ "to", "ton" },
	{ "tr", "tur" },
	{ "ts", "tso" },
	{ "tt", "tat" },
	{ "tw", "twi" },
	{ "ty", "tah" },
	{ "ug", "uig" },
	{ "uk", "ukr" },
	{ "ur", "urd" },
	{ "uz", "uzb" },
	{ "ve", "ven" },
	{ "vi", "vie" },
	{ "vo", "vol" },
	{ "wa", "wln" },
	{ "wo", "wol" },
	{ "xh", "xho" },
	{ "yi", "yid" },
	{ "yo", "yor" },
	{ "za", "zha" },
	{ "zh", "zho" },
	{ "zu", "zul" },
	{ "||", "" }
};

const char *language_iso639_3char_from_iso639_2char(const char *iso639_2char)
{
	if (strlen(iso639_2char) != 2) {
		return NULL;
	}

	if ((uint8_t)iso639_2char[0] > (uint8_t)'z') {
		return NULL;
	}

	struct language_iso639_entry_t *entry = language_iso639_lookup_table;
	while (1) {
		if ((uint8_t)entry->iso639_2char[0] >= (uint8_t)iso639_2char[0]) {
			break;
		}

		entry++;
	}

	while (1) {
		if ((uint8_t)entry->iso639_2char[0] > (uint8_t)iso639_2char[0]) {
			return NULL;
		}

		if ((uint8_t)entry->iso639_2char[1] >= (uint8_t)iso639_2char[1]) {
			break;
		}

		entry++;
	}
		
	if ((uint8_t)entry->iso639_2char[1] > (uint8_t)iso639_2char[1]) {
		return NULL;
	}

	return entry->iso639_3char;
}
