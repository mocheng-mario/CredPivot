#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int credpivot_agent_start(void);
extern int credpivot_agent_stop(void);
extern int credpivot_agent_is_running(void);
extern char *credpivot_agent_request_json(const char *request);
extern void credpivot_string_free(char *response);
extern void credpivot_webdav_error(uint32_t operation, uint32_t phase, uint32_t directory, uint32_t status, uint32_t reason);

JNIEXPORT void JNICALL Java_com_credpivot_android_NativeAgent_webDavError(
    JNIEnv *env, jobject self, jint operation, jint phase, jint directory, jint status, jint reason) {
    (void)env; (void)self;
    credpivot_webdav_error((uint32_t)operation, (uint32_t)phase, (uint32_t)directory, (uint32_t)status, (uint32_t)reason);
}

JNIEXPORT jint JNICALL Java_com_credpivot_android_NativeAgent_initialize(
    JNIEnv *env, jobject self, jstring directory, jstring temporary) {
    (void)self;
    const char *path = (*env)->GetStringUTFChars(env, directory, NULL);
    if (!path) return -1;
    const char *temp = (*env)->GetStringUTFChars(env, temporary, NULL);
    if (!temp) { (*env)->ReleaseStringUTFChars(env, directory, path); return -1; }
    // 在任何 Rust 初始化前绑定应用私有目录，绝不使用共享存储作为 HOME。
    const char *existing = getenv("HOME");
    int result = existing && strcmp(existing, path) == 0 ? 0 : setenv("HOME", path, 1);
    existing = getenv("TMPDIR");
    if (result == 0 && (!existing || strcmp(existing, temp) != 0)) result = setenv("TMPDIR", temp, 1);
    (*env)->ReleaseStringUTFChars(env, temporary, temp);
    (*env)->ReleaseStringUTFChars(env, directory, path);
    return result;
}

JNIEXPORT jint JNICALL Java_com_credpivot_android_NativeAgent_start(JNIEnv *env, jobject self) {
    (void)env; (void)self;
    return credpivot_agent_start();
}

JNIEXPORT jint JNICALL Java_com_credpivot_android_NativeAgent_stop(JNIEnv *env, jobject self) {
    (void)env; (void)self;
    return credpivot_agent_stop();
}

JNIEXPORT jint JNICALL Java_com_credpivot_android_NativeAgent_isRunning(JNIEnv *env, jobject self) {
    (void)env; (void)self;
    return credpivot_agent_is_running();
}

JNIEXPORT jbyteArray JNICALL Java_com_credpivot_android_NativeAgent_request(
    JNIEnv *env, jobject self, jbyteArray request) {
    (void)self;
    jsize size = (*env)->GetArrayLength(env, request);
    char *body = calloc((size_t)size + 1, 1);
    if (!body) return NULL;
    (*env)->GetByteArrayRegion(env, request, 0, size, (jbyte *)body);
    if ((*env)->ExceptionCheck(env)) { free(body); return NULL; }
    char *response = credpivot_agent_request_json(body);
    // 主密码等请求体只在本次 JNI 调用内存在，不写文件或诊断日志。
    volatile char *wipe = body;
    for (jsize i = 0; i < size; i++) wipe[i] = 0;
    free(body);
    if (!response) return NULL;
    size_t length = 0;
    while (response[length]) length++;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)length);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, (jsize)length, (jbyte *)response);
    wipe = response;
    for (size_t i = 0; i < length; i++) wipe[i] = 0;
    credpivot_string_free(response);
    return result;
}
