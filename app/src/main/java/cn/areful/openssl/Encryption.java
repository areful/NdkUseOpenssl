package cn.areful.openssl;

public class Encryption {
    static {
        String[] libs = new String[]{
                "crypto",
                "ssl",
                "native-lib",
        };
        for (String lib : libs) {
            System.loadLibrary(lib);
        }
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public static native String stringFromJNI();

    public static native String encode(String content, int type);

    public static native String decode(String content, int type);
}
