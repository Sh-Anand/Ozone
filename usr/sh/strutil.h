

#ifndef _STRUTIL_H
#define _STRUTIL_H

#include <stdint.h>
#include <stdio.h>

inline static uint8_t is_alpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); // upper- and lowercase letters count as alpha
}

inline static uint8_t is_nummeric(char c) {
	return c >= '0' && c <= '9';
}


inline static uint8_t is_whitespace(char c) {
	return c == '\n' || c == '\t' || c == '\r' || c == ' '; // Tabs, newlines and spaces count as white space
}

inline static int make_printable(char* buf, size_t len, char c) {
	if (c == '\e') return snprintf(buf, len, "ESC");
	if (c == '\0') return snprintf(buf, len, "\\0");
	if (c == 127) return snprintf(buf, len, "DEL");
	if (c == '\n') return snprintf(buf, len, "\\n");
	if (c == '\r') return snprintf(buf, len, "\\r");
	if (c == '\t') return snprintf(buf, len, "\\t");
	
	return snprintf(buf, len, "%c", c);
}

#endif // _STRUTIL_H