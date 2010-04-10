/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>

/* iso_8859_15 (man iso_8859_15) */
int get_char(int code)
{
    switch (code) {
        /* Perl is great :) */
    case 160:
        return ' ';
    case 161:
        return '¡';
    case 162:
        return '¢';
    case 163:
        return '£';
    case 164:
        return '¤';
    case 165:
        return '¥';
    case 166:
        return '¦';
    case 167:
        return '§';
    case 168:
        return '¨';
    case 169:
        return '©';
    case 170:
        return 'ª';
    case 171:
        return '«';
    case 172:
        return '¬';
    case 173:
        return '­';
    case 174:
        return '®';
    case 175:
        return '¯';
    case 176:
        return '°';
    case 177:
        return '±';
    case 178:
        return '²';
    case 179:
        return '³';
    case 180:
        return '´';
    case 181:
        return 'µ';
    case 182:
        return '¶';
    case 183:
        return '·';
    case 184:
        return '¸';
    case 185:
        return '¹';
    case 186:
        return 'º';
    case 187:
        return '»';
    case 188:
        return '¼';
    case 189:
        return '½';
    case 190:
        return '¾';
    case 191:
        return '¿';
    case 192:
        return 'À';
    case 193:
        return 'Á';
    case 194:
        return 'Â';
    case 195:
        return 'Ã';
    case 196:
        return 'Ä';
    case 197:
        return 'Å';
    case 198:
        return 'Æ';
    case 199:
        return 'Ç';
    case 200:
        return 'È';
    case 201:
        return 'É';
    case 202:
        return 'Ê';
    case 203:
        return 'Ë';
    case 204:
        return 'Ì';
    case 205:
        return 'Í';
    case 206:
        return 'Î';
    case 207:
        return 'Ï';
    case 208:
        return 'Ð';
    case 209:
        return 'Ñ';
    case 210:
        return 'Ò';
    case 211:
        return 'Ó';
    case 212:
        return 'Ô';
    case 213:
        return 'Õ';
    case 214:
        return 'Ö';
    case 215:
        return '×';
    case 216:
        return 'Ø';
    case 217:
        return 'Ù';
    case 218:
        return 'Ú';
    case 219:
        return 'Û';
    case 220:
        return 'Ü';
    case 221:
        return 'Ý';
    case 222:
        return 'Þ';
    case 223:
        return 'ß';
    case 224:
        return 'à';
    case 225:
        return 'á';
    case 226:
        return 'â';
    case 227:
        return 'ã';
    case 228:
        return 'ä';
    case 229:
        return 'å';
    case 230:
        return 'æ';
    case 231:
        return 'ç';
    case 232:
        return 'è';
    case 233:
        return 'é';
    case 234:
        return 'ê';
    case 235:
        return 'ë';
    case 236:
        return 'ì';
    case 237:
        return 'í';
    case 238:
        return 'î';
    case 239:
        return 'ï';
    case 240:
        return 'ð';
    case 241:
        return 'ñ';
    case 242:
        return 'ò';
    case 243:
        return 'ó';
    case 244:
        return 'ô';
    case 245:
        return 'õ';
    case 246:
        return 'ö';
    case 247:
        return '÷';
    case 248:
        return 'ø';
    case 249:
        return 'ù';
    case 250:
        return 'ú';
    case 251:
        return 'û';
    case 252:
        return 'ü';
    case 253:
        return 'ý';
    case 254:
        return 'þ';
    case 255:
        return 'ÿ';
    }
    return -1;
}

/* Convert hexadecimal to int */
int hex2int(char *pChars)
{
    int Hi;
    int Lo;
    int Result;

    Hi = pChars[0];
    if ('0' <= Hi && Hi <= '9') {
        Hi -= '0';
    }
    else if ('a' <= Hi && Hi <= 'f') {
        Hi -= ('a' - 10);
    }
    else if ('A' <= Hi && Hi <= 'F') {
        Hi -= ('A' - 10);
    }
    Lo = pChars[1];
    if ('0' <= Lo && Lo <= '9') {
        Lo -= '0';
    }
    else if ('a' <= Lo && Lo <= 'f') {
        Lo -= ('a' - 10);
    }
    else if ('A' <= Lo && Lo <= 'F') {
        Lo -= ('A' - 10);
    }
    Result = Lo + (16 * Hi);

    return (Result);
}
