package cn.areful.encrypt;

public class PaymentSecureManager {

    private PaymentSecureManager() {
    }

    public static native String nativeEncrypt(String key, String content);

    public static native boolean nativeVerify(String key, String content, byte[] signBytes);

    public static String encrypt(String key, String content) {
        return nativeEncrypt(key, content);
    }

    public static boolean verify(String key, String content, byte[] sign) {
        return nativeVerify(key, content, sign);
    }

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

}