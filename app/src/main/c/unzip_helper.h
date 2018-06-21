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

#ifndef NATIVESIGNATUREVERIFICATION_UNZIP_HELPER_H
#define NATIVESIGNATUREVERIFICATION_UNZIP_HELPER_H

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#include "third/minizip/mz.h"
#include "third/minizip/mz_os.h"
#include "third/minizip/mz_strm.h"
#include "third/minizip/mz_strm_mem.h"
#include "third/minizip/mz_strm_bzip.h"
#include "third/minizip/mz_strm_zlib.h"
#include "third/minizip/mz_zip.h"
#include "third/minizip/mz_strm_split.h"
#include "third/minizip/mz_strm_buf.h"

#include "def.h"


unsigned char * unzipHelperGetCertificateDetails(const char * fullApkPath, size_t * len);

#endif //NATIVESIGNATUREVERIFICATION_UNZIP_HELPER_H
