package com.shree.itassets;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.SslErrorHandler;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    public static volatile boolean isAppInForeground = false;
    private static final int REQ_FILE_CHOOSER = 4001;
    private static final int REQ_NOTIF_PERM = 4002;
    private static final int REQ_CAMERA_PERM = 4003;
    private static final int REQ_CAMERA_CHOOSER = 4004;

    private WebView webView;
    private ProgressBar progressBar;
    private LinearLayout errorView;
    private TextView errorDetailText;

    private ValueCallback<Uri[]> fileUploadCallback = null;
    private PermissionRequest pendingPermissionRequest = null;
    private WebChromeClient.FileChooserParams pendingChooserParams = null;
    private Uri pendingCameraPhotoUri = null;
    private boolean sslDialogShowing = false;
    private final List<SslErrorHandler> pendingSslHandlers = new ArrayList<>();
    private String configuredHost = "";

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String serverUrl = CertPinStore.getServerUrl(this);
        if (serverUrl.isEmpty()) {
            startActivity(new Intent(this, ServerSetupActivity.class));
            finish();
            return;
        }

        Uri parsed = Uri.parse(serverUrl);
        configuredHost = parsed != null && parsed.getHost() != null ? parsed.getHost() : "";

        setContentView(R.layout.activity_main);
        webView = findViewById(R.id.webView);
        progressBar = findViewById(R.id.progressBar);
        errorView = findViewById(R.id.errorView);
        errorDetailText = findViewById(R.id.errorDetailText);
        Button retryBtn = findViewById(R.id.retryBtn);
        Button changeServerBtn = findViewById(R.id.changeServerBtn);

        retryBtn.setOnClickListener(v -> {
            errorView.setVisibility(View.GONE);
            webView.setVisibility(View.VISIBLE);
            webView.reload();
        });
        changeServerBtn.setOnClickListener(v -> openServerSetup());

        NotificationHelper.ensureChannels(this);
        requestNotificationPermissionIfNeeded();
        setupWebView(serverUrl);
    }

    private void requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF_PERM);
            }
        }
    }

    private void startMonitorServiceIfEnabled() {
        if (!CertPinStore.isBgAlertsEnabled(this)) return;
        try {
            Intent svc = new Intent(this, AlertMonitorService.class);
            if (Build.VERSION.SDK_INT >= 26) {
                startForegroundService(svc);
            } else {
                startService(svc);
            }
        } catch (Exception ignored) {
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView(String initialUrl) {
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(webView, true);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setSupportZoom(false);

        webView.addJavascriptInterface(new ShreeBridge(), "ShreeAndroid");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri == null) return false;
                String host = uri.getHost();
                if (host != null && (host.equalsIgnoreCase(configuredHost) || configuredHost.isEmpty())) {
                    return false;
                }
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    return true;
                } catch (Exception e) {
                    return false;
                }
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                CookieManager.getInstance().flush();
                progressBar.setVisibility(View.GONE);
                startMonitorServiceIfEnabled();
                handleDeepLinkIntent(getIntent());
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                super.onReceivedError(view, request, error);
                if (request != null && request.isForMainFrame()) {
                    webView.setVisibility(View.GONE);
                    errorView.setVisibility(View.VISIBLE);
                    if (error != null && Build.VERSION.SDK_INT >= 23 && error.getDescription() != null) {
                        errorDetailText.setText("Server: " + initialUrl + "\nError: " + error.getDescription());
                    }
                }
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                X509Certificate x509 = CertPinStore.extractX509(error.getCertificate());
                String fp = CertPinStore.sha256Fingerprint(x509);
                Uri errUri = Uri.parse(error.getUrl());
                String errHost = errUri != null && errUri.getHost() != null ? errUri.getHost() : configuredHost;

                if (!fp.isEmpty() && CertPinStore.isCertPinned(MainActivity.this, errHost, fp)) {
                    handler.proceed();
                    return;
                }

                synchronized (pendingSslHandlers) {
                    pendingSslHandlers.add(handler);
                    if (sslDialogShowing) {
                        return;
                    }
                    sslDialogShowing = true;
                }

                runOnUiThread(() -> showSslTrustDialog(errHost, fp));
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (newProgress < 100) {
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(newProgress);
                } else {
                    progressBar.setVisibility(View.GONE);
                }
            }

            @Override
            public void onPermissionRequest(PermissionRequest request) {
                runOnUiThread(() -> {
                    String[] resources = request.getResources();
                    boolean wantsVideo = false;
                    for (String res : resources) {
                        if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(res)) {
                            wantsVideo = true;
                        }
                    }
                    if (!wantsVideo) {
                        request.deny();
                        return;
                    }
                    if (Build.VERSION.SDK_INT >= 23 && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                        if (pendingPermissionRequest != null) {
                            try { pendingPermissionRequest.deny(); } catch (Exception ignored) {}
                        }
                        pendingPermissionRequest = request;
                        requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA_PERM);
                    } else {
                        request.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                    }
                });
            }

            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, FileChooserParams fileChooserParams) {
                if (fileUploadCallback != null) {
                    fileUploadCallback.onReceiveValue(null);
                }
                fileUploadCallback = filePathCallback;
                if (acceptsImageTypes(fileChooserParams)
                        && Build.VERSION.SDK_INT >= 23
                        && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                    pendingChooserParams = fileChooserParams;
                    requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA_CHOOSER);
                    return true;
                }
                launchFileChooserWithCamera(fileChooserParams);
                return true;
            }
        });

        webView.setDownloadListener((url, userAgent, contentDisposition, mimetype, contentLength) -> {
            try {
                DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url));
                if (mimetype != null) req.setMimeType(mimetype);
                String cookies = CookieManager.getInstance().getCookie(url);
                if (cookies != null) req.addRequestHeader("Cookie", cookies);
                req.addRequestHeader("User-Agent", userAgent);
                String fileName = URLUtil.guessFileName(url, contentDisposition, mimetype);
                req.setTitle(fileName);
                req.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                req.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName);
                DownloadManager dm = (DownloadManager) getSystemService(DOWNLOAD_SERVICE);
                if (dm != null) {
                    dm.enqueue(req);
                    Toast.makeText(this, "Downloading " + fileName, Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                } catch (Exception ignored) {
                }
            }
        });

        webView.loadUrl(initialUrl);
    }

    private void showSslTrustDialog(String host, String fp) {
        String msg = "Your office server presented a private SSL certificate:\n\n"
                + "Host: " + host + "\n"
                + "SHA-256: " + (fp.isEmpty() ? "(unavailable)" : fp) + "\n\n"
                + "Trust & pin this certificate so you don't need manual CA installation?";

        new AlertDialog.Builder(this)
                .setTitle("Trust Office Server?")
                .setMessage(msg)
                .setCancelable(false)
                .setPositiveButton("Trust & Connect", (d, w) -> {
                    if (!fp.isEmpty()) {
                        CertPinStore.savePinnedCert(MainActivity.this, host, fp);
                    }
                    synchronized (pendingSslHandlers) {
                        for (SslErrorHandler h : pendingSslHandlers) {
                            h.proceed();
                        }
                        pendingSslHandlers.clear();
                        sslDialogShowing = false;
                    }
                })
                .setNegativeButton("Cancel", (d, w) -> {
                    synchronized (pendingSslHandlers) {
                        for (SslErrorHandler h : pendingSslHandlers) {
                            h.cancel();
                        }
                        pendingSslHandlers.clear();
                        sslDialogShowing = false;
                    }
                })
                .show();
    }

    private void handleDeepLinkIntent(Intent intent) {
        if (intent == null || webView == null) return;
        String targetView = intent.getStringExtra("targetView");
        String targetId = intent.getStringExtra("targetId");
        if (targetView != null && !targetView.isEmpty()) {
            intent.removeExtra("targetView");
            intent.removeExtra("targetId");
            String js = "if(typeof window.go==='function'){window.go(" + org.json.JSONObject.quote(targetView) + ");}";
            if (targetId != null && !targetId.isEmpty()) {
                js += "if(typeof window.jumpToTicketInQueue==='function'){setTimeout(function(){window.jumpToTicketInQueue(" + org.json.JSONObject.quote(targetId) + ");},300);}";
            }
            webView.evaluateJavascript(js, null);
        }
    }

    private void openServerSetup() {
        startActivity(new Intent(this, ServerSetupActivity.class));
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleDeepLinkIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        isAppInForeground = true;
    }

    @Override
    protected void onPause() {
        super.onPause();
        isAppInForeground = false;
        CookieManager.getInstance().flush();
    }

    private boolean acceptsImageTypes(WebChromeClient.FileChooserParams params) {
        if (params == null) return false;
        String[] types = params.getAcceptTypes();
        if (types == null) return false;
        for (String t : types) {
            if (t != null && (t.contains("image") || t.contains(".jpg") || t.contains(".jpeg") || t.contains(".png"))) {
                return true;
            }
        }
        return false;
    }

    private void launchFileChooserWithCamera(WebChromeClient.FileChooserParams fileChooserParams) {
        pendingCameraPhotoUri = null;
        try {
            Intent contentIntent = fileChooserParams != null
                    ? fileChooserParams.createIntent()
                    : new Intent(Intent.ACTION_GET_CONTENT).setType("image/*");
            List<Intent> extraIntents = new ArrayList<>();
            if (acceptsImageTypes(fileChooserParams)
                    && (Build.VERSION.SDK_INT < 23 || checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)) {
                try {
                    Intent camIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
                    ContentValues cv = new ContentValues();
                    cv.put(MediaStore.Images.Media.DISPLAY_NAME, "SHREE_GATE_" + System.currentTimeMillis() + ".jpg");
                    cv.put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg");
                    Uri uri = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cv);
                    if (uri != null) {
                        pendingCameraPhotoUri = uri;
                        camIntent.putExtra(MediaStore.EXTRA_OUTPUT, uri);
                        camIntent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
                        extraIntents.add(camIntent);
                    }
                } catch (Exception ignored) {
                }
            }
            Intent chooser = Intent.createChooser(contentIntent, "Camera or Select Photo");
            if (!extraIntents.isEmpty()) {
                chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS, extraIntents.toArray(new Intent[0]));
            }
            startActivityForResult(chooser, REQ_FILE_CHOOSER);
        } catch (Exception e) {
            if (fileUploadCallback != null) {
                fileUploadCallback.onReceiveValue(null);
                fileUploadCallback = null;
            }
            Toast.makeText(MainActivity.this, "Cannot open camera or file picker", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
        if (requestCode == REQ_CAMERA_PERM && pendingPermissionRequest != null) {
            PermissionRequest req = pendingPermissionRequest;
            pendingPermissionRequest = null;
            if (granted) {
                req.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
            } else {
                req.deny();
            }
        } else if (requestCode == REQ_CAMERA_CHOOSER) {
            WebChromeClient.FileChooserParams cp = pendingChooserParams;
            pendingChooserParams = null;
            launchFileChooserWithCamera(cp);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_FILE_CHOOSER && fileUploadCallback != null) {
            Uri[] result = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
            if ((result == null || result.length == 0) && resultCode == RESULT_OK && pendingCameraPhotoUri != null) {
                result = new Uri[]{pendingCameraPhotoUri};
            }
            pendingCameraPhotoUri = null;
            fileUploadCallback.onReceiveValue(result);
            fileUploadCallback = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    private final class ShreeBridge {
        @JavascriptInterface
        public void notify(String title, String body, String targetView, String targetId) {
            NotificationHelper.showAlert(MainActivity.this, title, body, targetView, targetId);
        }

        @JavascriptInterface
        public void openServerSettings() {
            runOnUiThread(() -> openServerSetup());
        }

        @JavascriptInterface
        public String getAppVersion() {
            return "1.0.2";
        }

        @JavascriptInterface
        public boolean hasCameraSupport() {
            return true;
        }
    }
}
