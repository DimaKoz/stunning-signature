/*

The MIT License (MIT)

Copyright (c) 2018  Dmitrii Kozhevin <kozhevin.dima@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

#ifndef NATIVESIGNATUREVERIFICATION_PKCS7_HELPER_H
#define NATIVESIGNATUREVERIFICATION_PKCS7_HELPER_H

#include <stdbool.h>
#include <assert.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>

#include "def.h"

// Tags:
// https://en.wikipedia.org/wiki/X.690
#define TAG_INTEGER         0x02
#define TAG_BITSTRING       0x03
#define TAG_OCTETSTRING     0x04
#define TAG_NULL            0x05
#define TAG_OBJECTID        0x06
#define TAG_UTCTIME         0x17
#define TAG_GENERALIZEDTIME 0x18
#define TAG_SEQUENCE        0x30
#define TAG_SET             0x31

#define TAG_OPTIONAL    0xA0


#define NAME_LEN    63

typedef struct element {
    unsigned char tag;
    char name[NAME_LEN];
    int begin;
    size_t len;
    int level;
    struct element *next;
} element;


unsigned char * pkcs7HelperGetSignature(unsigned char * certrsa, size_t len_in, size_t *len_out);

void pkcs7HelperFree();


#endif //NATIVESIGNATUREVERIFICATION_PKCS7_HELPER_H
