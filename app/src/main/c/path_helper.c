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

#include "path_helper.h"


static char *getPackageName() {
    const size_t BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE] = "";
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd > 0) {
        ssize_t r = read(fd, buffer, BUFFER_SIZE - 1);
        close(fd);
        if (r > 0) {
            return strdup(buffer);
        }
    }
    return NULL;
}

static const char *getFilenameExt(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot + 1;
}

char *pathHelperGetPath() {

    char *package = getPackageName();
    if (NULL == package) {
        return NULL;
    }

    FILE *fp = fopen("/proc/self/maps", "r");
    if (NULL == fp) {
        free(package);
        return NULL;
    }
    const size_t BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE] = "";
    char path[BUFFER_SIZE] = "";

    bool find = false;
    while (fgets(buffer, BUFFER_SIZE, fp)) {
        if (sscanf(buffer, "%*llx-%*llx %*s %*s %*s %*s %s", path) == 1) {
            if (strstr(path, package)) {
                char *bname = basename(path);
                NSV_LOGI("check basename[%s]", bname);
                if (strcasecmp(getFilenameExt(bname), "apk") == 0) {
                    find = true;
                    break;
                }
            }
        }
    }
    fclose(fp);
    free(package);
    if (find) {
        return strdup(path);
    }
    return NULL;
}

