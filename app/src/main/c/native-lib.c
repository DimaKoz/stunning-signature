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

#include <jni.h>
#include <malloc.h>

#include "path_helper.h"
#include "unzip_helper.h"
#include "pkcs7_helper.h"


JNIEXPORT jbyteArray JNICALL
Java_com_kozhevin_signverification_MainActivity_bytesFromJNI(JNIEnv *env, jobject this) {

    NSV_LOGI("pathHelperGetPath starts\n");
    char *path = pathHelperGetPath();
    NSV_LOGI("pathHelperGetPath finishes\n");

    if (!path) {
        return NULL;
    }
    NSV_LOGI("pathHelperGetPath result[%s]\n", path);
    NSV_LOGI("unzipHelperGetCertificateDetails starts\n");
    size_t len_in = 0;
    size_t len_out = 0;
    unsigned char *content = unzipHelperGetCertificateDetails(path, &len_in);
    NSV_LOGI("unzipHelperGetCertificateDetails finishes\n");
    if (!content) {
        free(path);
        return NULL;
    }
    NSV_LOGI("pkcs7HelperGetSignature starts\n");

    unsigned char *res = pkcs7HelperGetSignature(content, len_in, &len_out);
    NSV_LOGI("pkcs7HelperGetSignature finishes\n");
    jbyteArray jbArray = NULL;
    if (NULL != res || len_out != 0) {
        jbArray = (*env)->NewByteArray(env, len_out);
        (*env)->SetByteArrayRegion(env, jbArray, 0, len_out, (jbyte *) res);
    }
    free(content);
    free(path);
    pkcs7HelperFree();
    return jbArray;
}

