/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <ctype.h>
#include <limits.h>

int duda_utils_strtol(const char *nptr, int len, long *result)
{
    /*
     * Part of the following code was taken from the following links:
     *
     * - http://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/libkern/strtol.c
     * - http://www.koders.com/c/fid0A9B008CA98BE77AEC5E59AFC19BECAE325AC60F.aspx
     * - http://www.ethernut.de/api/strtol_8c_source.html
     *
     * It has been modified in order to accept the string length and store the result
     * in the 'result' parameter.
     */

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
	 * between valid and invalid numbers is then based on the last
	 * digit.  For instance, if the range for longs is
	 * [-2147483648..2147483647] and the input base is 10,
	 * cutoff will be set to 214748364 and cutlim to either
	 * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
	 * a value > 214748364, or equal but the next digit is > 7 (or 8),
	 * the number is too big, and we will return a range error.
	 *
	 * Set any if any `digits' consumed; make it negative to indicate
	 * overflow.
	 */

    const char *s = nptr;
	unsigned long acc;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;
    int base = 10;

    c = *s++;
	if (c == '-') {
		neg = 1;
		c = *s++;
	}
    else if (c == '+') {
		c = *s++;
    }

	cutoff = neg ? - (unsigned long) LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long) base;
	cutoff /= (unsigned long) base;

	for (acc = 0, any = 0; (s - ((const char *) nptr) <= len ); c = *s++) {
		if (isdigit(c)) {
			c -= '0';
        }
		else {
            any = -1;
			break;
        }

		if (c >= base) {
            any = -1;
			break;
        }

		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim) {
			any = -1;
        }
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}

	if (any < 0) {
        *result = 0;
        return -1;
	}
    else if (neg) {
		acc = -acc;
    }

    *result = acc;

	return 0;
}
