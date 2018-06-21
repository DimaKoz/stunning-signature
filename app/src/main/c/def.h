

#ifndef NATIVESIGNATUREVERIFICATION_DEF_H
#define NATIVESIGNATUREVERIFICATION_DEF_H

#include <android/log.h>
#include <jni.h>

#define NSV_LOG_TAG "SignVerification"



#ifndef NDEBUG

#define NSV_LOGI(...)  __android_log_print(ANDROID_LOG_INFO,NSV_LOG_TAG,__VA_ARGS__)
#define NSV_LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,NSV_LOG_TAG,__VA_ARGS__)
#define NSV_LOGW(...)  __android_log_print(ANDROID_LOG_WARN,NSV_LOG_TAG,__VA_ARGS__)
#define NSV_LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,NSV_LOG_TAG,__VA_ARGS__)
#define NSV_LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE,NSV_LOG_TAG,__VA_ARGS__)

#else //NDEBUG

#define NSV_LOGI(...)
#define NSV_LOGE(...)
#define NSV_LOGW(...)
#define NSV_LOGD(...)
#define NSV_LOGV(...)

#endif //NDEBUG

#endif //NATIVESIGNATUREVERIFICATION_DEF_H
