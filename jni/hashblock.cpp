/**
 * Created by Hash Engineering on 4/24/14 for the X11 algorithm
 */
#include "hashblock.h"
#include <inttypes.h>

#include <jni.h>



jbyteArray JNICALL hash11_native(JNIEnv *env, jclass cls, jbyteArray header)
{
    jint Plen = (env)->GetArrayLength(header);
    jbyte *P = (env)->GetByteArrayElements(header, NULL);
    //uint8_t *buf = malloc(sizeof(uint8_t) * dkLen);
    jbyteArray DK = NULL;

    if (P)
	{
	
	uint256 result = Hash9(P, P+Plen);

    /*if (crypto_scrypt((uint8_t *) P, Plen, (uint8_t *) S, Slen, N, r, p, buf, dkLen)) {
        jclass e = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        char *msg;
        switch (errno) {
            case EINVAL:
                msg = "N must be a power of 2 greater than 1";
                break;
            case EFBIG:
            case ENOMEM:
                msg = "Insufficient memory available";
                break;
            default:
                msg = "Memory allocation failed";
        }
        (*env)->ThrowNew(env, e, msg);
        goto cleanup;
    }*/

    DK = (env)->NewByteArray(32);
    if (DK)
	{
		(env)->SetByteArrayRegion(DK, 0, 32, (jbyte *) result.begin());
	}
	

    if (P) (env)->ReleaseByteArrayElements(header, P, JNI_ABORT);
    //if (buf) free(buf);
	}
    return DK;
}

static const JNINativeMethod methods[] = {
    { "x11_native", "([B)[B", (void *) hash11_native }
};

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;

    if ((vm)->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass cls = (env)->FindClass("com/crypto/X11");
    int r = (env)->RegisterNatives(cls, methods, 1);

    return (r == JNI_OK) ? JNI_VERSION_1_6 : -1;
}