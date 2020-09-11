package cn.areful.openssl;

import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import cn.areful.encrypt.Encryption;
import cn.areful.encrypt.PaymentSecureManager;

/**
 * created by areful, 2020/7/24.<p>
 * Sample use of Openssl with NDK.
 */
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        tv.setText(Encryption.stringFromJNI());

        EditText editText = findViewById(R.id.editText);
        findViewById(R.id.okBtn).setOnClickListener(v -> {
            String content = editText.getText().toString().trim();
            String cipherText = Encryption.encode(content, 2);
            String plainText = Encryption.decode(cipherText, 2);
            String text = String.format("cipherText:\n\t\t%s\n\nplainText:\n\t\t%s", cipherText, plainText);
            tv.setText(text);

            String msg = "Hello, RSA sign and verify within key strings!";
            String publicKeyStr = "-----BEGIN PUBLIC KEY-----\n" +
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJnB+YXiGyEhuK0xGkEEDtieUw\n" +
                    "k8ZrWGupzKzJ1irzRyXEnXoZGpTTAi3ldIokEoHwH0K6+TRJtOSMviEQSiZBisJ+\n" +
                    "TzwDMD0yMRtxO6Ek8Ml6dsWE8HfjiFMFTGe4juAIDHCSrlDYeDRDf80xuprkAzlO\n" +
                    "WNEGIY87QI534WMB5QIDAQAB\n" +
                    "-----END PUBLIC KEY-----";
            String cipher = PaymentSecureManager.nativeEncrypt(publicKeyStr, msg);
            Log.e("gj--", "encrypt result:\t" + cipher);

            boolean verify = PaymentSecureManager.nativeVerify("abc", "def", new byte[]{});
            Log.e("gj--", "verify result:\t" + verify);
        });
    }
}