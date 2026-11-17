package com.shree.itassets;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;

public class ServerSetupActivity extends Activity {
    private EditText urlInput;
    private CheckBox bgAlertsCheck;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        urlInput = findViewById(R.id.serverUrlInput);
        bgAlertsCheck = findViewById(R.id.bgAlertsCheck);
        Button connectBtn = findViewById(R.id.connectServerBtn);

        String saved = CertPinStore.getServerUrl(this);
        if (!saved.isEmpty()) {
            urlInput.setText(saved);
        } else {
            urlInput.setText("https://192.168.130.31:8849");
        }
        bgAlertsCheck.setChecked(CertPinStore.isBgAlertsEnabled(this));

        connectBtn.setOnClickListener(v -> saveAndConnect());
    }

    private void saveAndConnect() {
        String raw = urlInput.getText() == null ? "" : urlInput.getText().toString().trim();
        if (raw.isEmpty()) {
            Toast.makeText(this, "Enter server URL", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
            raw = raw.endsWith(":8848") || raw.endsWith(":8898") ? ("http://" + raw) : ("https://" + raw);
        }
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        android.net.Uri uri = android.net.Uri.parse(raw);
        if (uri == null || uri.getHost() == null || uri.getHost().isEmpty()) {
            Toast.makeText(this, "Enter a valid server address", Toast.LENGTH_SHORT).show();
            return;
        }
        CertPinStore.setServerUrl(this, raw);
        CertPinStore.setBgAlertsEnabled(this, bgAlertsCheck.isChecked());

        Intent i = new Intent(this, MainActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        finish();
    }
}
