# NdkUseOpenssl

#### 升级项目的 openssl 版本到 3.3.0-dev.

## App 构建环境:
###### Android Studio Hedgehog | 2023.1.1 Patch 2
###### JDK 11,  `sourceCompatibility JavaVersion.VERSION_1_8`
###### gradle 6.5-all

## * .so 动态链接库构建环境:
###### Ubuntu 22.04.2 desktop
###### android-ndk-r20b-linux-x86_64
###### openssl 源码 (当前使用最新版本为 3.3.0-dev)

#### 如何构建*.so:
```
./make_openssl.sh 21 armeabi-v7a
./make_openssl.sh 21 arm64-v8a
./make_openssl.sh 21 x86
./make_openssl.sh 21 x86_64
```
