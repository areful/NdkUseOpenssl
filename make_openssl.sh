#!/bin/bash -e
# thanks to : https://github.com/217heidai/openssl_for_android/blob/master/openssl_build.sh
#
# ./make_openssl.sh 21 armeabi-v7a
# ./make_openssl.sh 21 arm64-v8a
# ./make_openssl.sh 21 x86
# ./make_openssl.sh 21 x86_64

WORK_PATH=$(cd "$(dirname "$0")";pwd)
ANDROID_NDK_PATH=${WORK_PATH}/android-ndk-r20b
OPENSSL_SOURCES_PATH=${WORK_PATH}/openssl-master
ANDROID_TARGET_API=$1
ANDROID_TARGET_ABI=$2

OUTPUT_PATH=${WORK_PATH}/openssl_master_${ANDROID_TARGET_ABI}

OPENSSL_TMP_FOLDER=/tmp/openssl_${ANDROID_TARGET_ABI}
mkdir -p ${OPENSSL_TMP_FOLDER}
cp -r ${OPENSSL_SOURCES_PATH}/* ${OPENSSL_TMP_FOLDER}

function build_library {
    mkdir -p ${OUTPUT_PATH}
    make -j16 && make install
    rm -rf ${OPENSSL_TMP_FOLDER}
    rm -rf ${OUTPUT_PATH}/bin
    rm -rf ${OUTPUT_PATH}/share
    rm -rf ${OUTPUT_PATH}/ssl
    rm -rf ${OUTPUT_PATH}/lib/engines*
    rm -rf ${OUTPUT_PATH}/lib/pkgconfig
    rm -rf ${OUTPUT_PATH}/lib/ossl-modules
    echo "Build completed! Check output libraries in ${OUTPUT_PATH}"
}

if [ "$ANDROID_TARGET_ABI" == "armeabi-v7a" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-arm -D__ANDROID_API__=${ANDROID_TARGET_API} -shared no-tests --prefix=${OUTPUT_PATH}
    build_library

elif [ "$ANDROID_TARGET_ABI" == "arm64-v8a" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-arm64 -D__ANDROID_API__=${ANDROID_TARGET_API} -shared no-tests --prefix=${OUTPUT_PATH}
    build_library

elif [ "$ANDROID_TARGET_ABI" == "x86" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-x86 -D__ANDROID_API__=${ANDROID_TARGET_API} -shared no-tests --prefix=${OUTPUT_PATH}
    build_library

elif [ "$ANDROID_TARGET_ABI" == "x86_64" ]
then
    export ANDROID_NDK_ROOT=${ANDROID_NDK_PATH}
    PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin:$PATH
    cd ${OPENSSL_TMP_FOLDER}
    ./Configure android-x86_64 -D__ANDROID_API__=${ANDROID_TARGET_API} -shared no-tests --prefix=${OUTPUT_PATH}
    build_library

else
    echo "Unsupported target ABI: $ANDROID_TARGET_ABI"
    exit 1
fi
