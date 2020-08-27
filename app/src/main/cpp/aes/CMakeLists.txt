cmake_minimum_required(VERSION 3.15)

#pkgconfig, openssl
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

aux_source_directory(. AES5_SOURCE)

add_executable(test_aes
        ${AES5_SOURCE}
        )
target_link_libraries(test_aes ${OPENSSL_LIBRARIES})
