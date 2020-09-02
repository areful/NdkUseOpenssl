package cn.areful.openssl;

public class PaymentSecureManager {

    public static native String nativeEncrypt(String key, String content);

    public static native boolean nativeVerify(String key, String content, byte[] signBytes);

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