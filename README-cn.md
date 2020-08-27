# NdkUseOpenssl
##如何编译Openssl库:
###下载Openssl源代码，然后运行配置脚本，设置参数为编译Android平台库。这一步会生成安卓平台的.so文件。
我使用的编译环境是Ubuntu 18.04, amd64 Desktop版本，NDK是android-ndk-r19c，64位版。编译命令如下：
```
    export ANDROID_NDK=/home/gj/android-ndk-r19c
    export PATH=/home/gj/android-ndk-r19c/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
    ./Configure android-arm shared
    make SHLIB_EXT=.so -j8
```

编译成功后会生成.so文件，我们可以把它复制出来保存一下。

如果想生成其他架构的.so，例如arm64架构，可以重新运行配置脚本并再次运行make命令重新生成：
```
    make clean
    ./Configure android-arm64 shared
    make SHLIB_EXT=.so -j8
```

源码中我预先编译了arm, arm64, armeabi, x86, x86_64 这几种ABI的.so库（cpp/libs文件夹下），并复制armeabi文件夹为armeabi-v7a，复制arm64文件夹为arm64-v8a，
因为Android Studio不再支持armeabi, arm64两种ABI了。参见build.gradle文件下, 'abiFilters'列出的几种ABI。