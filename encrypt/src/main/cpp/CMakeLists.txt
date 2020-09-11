# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

###############################################################
# import openssl library files BEGIN
include_directories(include)

set(SSL_LIB_NAME ssl)
add_library(${SSL_LIB_NAME} SHARED IMPORTED)
set_target_properties(${SSL_LIB_NAME} PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/libs/${ANDROID_ABI}/lib${SSL_LIB_NAME}.so)

set(CRYPTO_LIB_NAME crypto)
add_library(${CRYPTO_LIB_NAME} SHARED IMPORTED)
set_target_properties(${CRYPTO_LIB_NAME} PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/libs/${ANDROID_ABI}/lib${CRYPTO_LIB_NAME}.so)
# import openssl library files END
###############################################################

find_library(log-lib log)

aux_source_directory(b64 B64_SOURCE)
aux_source_directory(aes AES_SOURCE)
aux_source_directory(rsa RSA_SOURCE)

add_library(native-lib SHARED
        native-lib.cpp
        native-lib.h
        rsa_lib.cpp
        rsa_lib.h
        utils.cpp
        utils.h
        common.h
        ${AES_SOURCE}
        ${B64_SOURCE}
        ${RSA_SOURCE}
        )

target_link_libraries(
        native-lib
        ssl
        crypto
        ${log-lib})