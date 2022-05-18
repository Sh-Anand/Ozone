

#ifndef _STRUTIL_H
#define _STRUTIL_H

#include <stdint.h>

inline static uint8_t is_alpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); // upper- and lowercase letters count as alpha
}

inline static uint8_t is_nummeric(char c) {
	return c >= '0' && c <= '9';
}


inline static uint8_t is_whitespace(char c) {
	return c == '\n' || c == '\t' || c == '\r' || c == ' '; // Tabs, newlines and spaces count as white space
}

#endif // _STRUTIL_H