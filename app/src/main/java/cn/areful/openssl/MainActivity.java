package cn.areful.openssl;

import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.chebada.encrypt.Encryption;

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
        });
    }
}