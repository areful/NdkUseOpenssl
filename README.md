# NdkUseOpenssl

#### Upgrade openssl to 3.3.0-dev.

## App build environment:
###### Android Studio Iguana | 2023.2.1 Patch 1
###### JDK 17,  `sourceCompatibility JavaVersion.VERSION_11`
###### gradle 7.5-all

## * .so library build environment:
###### Ubuntu 22.04.2 desktop
###### android-ndk-r20b-linux-x86_64
###### openssl source code (current version 3.3.0-dev)

#### How to compile *.so:
```
./make_openssl.sh 21 armeabi-v7a
./make_openssl.sh 21 arm64-v8a
./make_openssl.sh 21 x86
./make_openssl.sh 21 x86_64
```
