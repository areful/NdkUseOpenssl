# NdkUseOpenssl
## How to build Openssl .so library:
### Download Openssl source and run configure script for Android platform, then compile source code. This step makes .so files for Android.
I compile source code on Ubuntu 18.04 amd64 Desktop System, Use command below:
```
    export ANDROID_NDK=/home/gj/android-ndk-r19c
    export PATH=/home/gj/android-ndk-r19c/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
    ./Configure android-arm shared
    make SHLIB_EXT=.so -j8
```

after build we can copy and save the output .so file.

If want to build .so for other ABIs, you can run 'make clean' and rerun '.Configure' command with ABI argument like this:
```
	make clean
    ./Configure android-arm64 shared
    make SHLIB_EXT=.so -j8
```

I built .so files for arm, arm64, armeabi, x86, x86_64 ABI（under directory 'cpp/libs'）, and copy armeabi directory as armeabi-v7a,
arm64 directory as arm64-v8a, for Android Studio not support armeabi, arm64 ABI any more. See build.gradle file, section 'abiFilters'.