package com.shree.itassets;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.ClipData;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.media.ExifInterface;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Base64;
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

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    public static volatile boolean isAppInForeground = false;
    private static final int REQ_FILE_CHOOSER = 4001;
    private static final int REQ_STARTUP_PERM = 4002;
    private static final int REQ_CAMERA_PERM = 4003;
    private static final int REQ_CAMERA_CHOOSER = 4004;
    private static final int REQ_CAMERA_NATIVE = 4005;
    private static final int REQ_NATIVE_CAMERA = 4006;

    private WebView webView;
    private ProgressBar progressBar;
    private LinearLayout errorView;
    private TextView errorDetailText;

    private ValueCallback<Uri[]> fileUploadCallback = null;
    private PermissionRequest pendingPermissionRequest = null;
    private WebChromeClient.FileChooserParams pendingChooserParams = null;
    private Uri pendingCameraPhotoUri = null;
    private File pendingCameraPhotoFile = null;
    private String pendingNativeFacing = "environment";
    private String pendingNativeCallbackId = "";
    private Uri pendingNativePhotoUri = null;
    private File pendingNativePhotoFile = null;
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
        requestStartupPermissionsIfNeeded();
        setupWebView(serverUrl);
    }

    private void requestStartupPermissionsIfNeeded() {
        if (Build.VERSION.SDK_INT < 23) return;
        List<String> needed = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.POST_NOTIFICATIONS);
        }
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.CAMERA);
        }
        if (!needed.isEmpty()) {
            requestPermissions(needed.toArray(new String[0]), REQ_STARTUP_PERM);
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

    private void grantUriPermissionsForIntent(Intent intent, Uri uri) {
        try {
            List<ResolveInfo> resInfos = getPackageManager().queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
            for (ResolveInfo ri : resInfos) {
                grantUriPermission(ri.activityInfo.packageName, uri,
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            }
        } catch (Exception ignored) {
        }
    }

    private Intent buildCameraCaptureIntent(Uri outputUri, String facing) {
        Intent camIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        camIntent.putExtra(MediaStore.EXTRA_OUTPUT, outputUri);
        camIntent.setClipData(ClipData.newRawUri("", outputUri));
        camIntent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        if ("user".equalsIgnoreCase(facing)) {
            camIntent.putExtra("android.intent.extras.CAMERA_FACING", 1);
            camIntent.putExtra("android.intent.extras.LENS_FACING_FRONT", 1);
            camIntent.putExtra("android.intent.extra.USE_FRONT_CAMERA", true);
        } else {
            camIntent.putExtra("android.intent.extras.CAMERA_FACING", 0);
            camIntent.putExtra("android.intent.extras.LENS_FACING_FRONT", 0);
            camIntent.putExtra("android.intent.extra.USE_FRONT_CAMERA", false);
        }
        grantUriPermissionsForIntent(camIntent, outputUri);
        return camIntent;
    }

    private void startNativeCameraCapture(String facing, String callbackId) {
        if (Build.VERSION.SDK_INT >= 23 && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingNativeFacing = facing != null ? facing : "environment";
            pendingNativeCallbackId = callbackId != null ? callbackId : "";
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA_NATIVE);
            return;
        }
        launchDirectCameraIntent(facing, callbackId);
    }

    private void launchDirectCameraIntent(String facing, String callbackId) {
        pendingNativeCallbackId = callbackId != null ? callbackId : "";
        pendingNativePhotoUri = null;
        pendingNativePhotoFile = null;
        try {
            String fname = "shree_cam_" + System.currentTimeMillis() + ".jpg";
            File photoFile = PhotoContentProvider.getPhotoFile(this, fname);
            Uri photoUri = PhotoContentProvider.getContentUri(this, fname);
            pendingNativePhotoFile = photoFile;
            pendingNativePhotoUri = photoUri;
            Intent camIntent = buildCameraCaptureIntent(photoUri, facing);
            startActivityForResult(camIntent, REQ_NATIVE_CAMERA);
        } catch (Exception e) {
            deliverNativePhoto(pendingNativeCallbackId, "");
            Toast.makeText(this, "Cannot open device camera: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void deliverNativePhoto(String callbackId, String dataUrl) {
        if (webView == null || callbackId == null || callbackId.isEmpty()) return;
        String js = "if(typeof window.__shreeReceiveNativePhoto==='function'){window.__shreeReceiveNativePhoto("
                + JSONObject.quote(callbackId) + "," + JSONObject.quote(dataUrl != null ? dataUrl : "") + ");}";
        runOnUiThread(() -> {
            if (webView != null) {
                webView.evaluateJavascript(js, null);
            }
        });
    }

    private String encodeFileOrBitmapToDataUrl(File file, Bitmap inlineBmp) {
        try {
            Bitmap bmp = null;
            if (file != null && file.exists() && file.length() > 0) {
                BitmapFactory.Options bounds = new BitmapFactory.Options();
                bounds.inJustDecodeBounds = true;
                BitmapFactory.decodeFile(file.getAbsolutePath(), bounds);
                int maxDim = Math.max(bounds.outWidth, bounds.outHeight);
                int sample = 1;
                while (maxDim / sample > 2048) {
                    sample *= 2;
                }
                BitmapFactory.Options opts = new BitmapFactory.Options();
                opts.inSampleSize = sample;
                bmp = BitmapFactory.decodeFile(file.getAbsolutePath(), opts);
                if (bmp != null) {
                    try {
                        ExifInterface exif = new ExifInterface(file.getAbsolutePath());
                        int orient = exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL);
                        int deg = 0;
                        if (orient == ExifInterface.ORIENTATION_ROTATE_90) deg = 90;
                        else if (orient == ExifInterface.ORIENTATION_ROTATE_180) deg = 180;
                        else if (orient == ExifInterface.ORIENTATION_ROTATE_270) deg = 270;
                        if (deg != 0) {
                            Matrix m = new Matrix();
                            m.postRotate(deg);
                            Bitmap rotated = Bitmap.createBitmap(bmp, 0, 0, bmp.getWidth(), bmp.getHeight(), m, true);
                            if (rotated != bmp) {
                                bmp.recycle();
                                bmp = rotated;
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            } else if (inlineBmp != null) {
                bmp = inlineBmp;
            }
            if (bmp == null) return "";
            int w = bmp.getWidth(), h = bmp.getHeight();
            int target = 1280;
            if (w > target || h > target) {
                int nw = w >= h ? target : Math.max(1, Math.round(w * (target / (float) h)));
                int nh = h > w ? target : Math.max(1, Math.round(h * (target / (float) w)));
                Bitmap scaled = Bitmap.createScaledBitmap(bmp, nw, nh, true);
                if (scaled != bmp) {
                    bmp.recycle();
                    bmp = scaled;
                }
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            bmp.compress(Bitmap.CompressFormat.JPEG, 82, baos);
            bmp.recycle();
            return "data:image/jpeg;base64," + Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP);
        } catch (Exception e) {
            return "";
        } finally {
            if (file != null && file.exists()) {
                try { file.delete(); } catch (Exception ignored) {}
            }
        }
    }

    private void launchFileChooserWithCamera(WebChromeClient.FileChooserParams fileChooserParams) {
        pendingCameraPhotoUri = null;
        pendingCameraPhotoFile = null;
        try {
            Intent contentIntent = fileChooserParams != null
                    ? fileChooserParams.createIntent()
                    : new Intent(Intent.ACTION_GET_CONTENT).setType("image/*");
            if (fileChooserParams != null && fileChooserParams.getMode() == WebChromeClient.FileChooserParams.MODE_OPEN_MULTIPLE) {
                contentIntent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
            }
            List<Intent> extraIntents = new ArrayList<>();
            if (acceptsImageTypes(fileChooserParams)
                    && (Build.VERSION.SDK_INT < 23 || checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)) {
                try {
                    String fname = "shree_pick_" + System.currentTimeMillis() + ".jpg";
                    File pf = PhotoContentProvider.getPhotoFile(this, fname);
                    Uri uri = PhotoContentProvider.getContentUri(this, fname);
                    pendingCameraPhotoFile = pf;
                    pendingCameraPhotoUri = uri;
                    extraIntents.add(buildCameraCaptureIntent(uri, "environment"));
                } catch (Exception ignored) {
                }
            }
            Intent chooser = Intent.createChooser(contentIntent, "Camera or Select Photos");
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
        } else if (requestCode == REQ_CAMERA_NATIVE) {
            String cbId = pendingNativeCallbackId;
            String facing = pendingNativeFacing;
            pendingNativeCallbackId = "";
            if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                launchDirectCameraIntent(facing, cbId);
            } else {
                deliverNativePhoto(cbId, "");
                Toast.makeText(this, "Allow Camera permission in App Settings to capture photos.", Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_NATIVE_CAMERA) {
            final String cbId = pendingNativeCallbackId;
            final File photoFile = pendingNativePhotoFile;
            pendingNativeCallbackId = "";
            pendingNativePhotoUri = null;
            pendingNativePhotoFile = null;
            if (resultCode != RESULT_OK) {
                if (photoFile != null && photoFile.exists()) {
                    try { photoFile.delete(); } catch (Exception ignored) {}
                }
                deliverNativePhoto(cbId, "");
                return;
            }
            Bitmap thumb = null;
            if (data != null && data.getExtras() != null) {
                Object raw = data.getExtras().get("data");
                if (raw instanceof Bitmap) thumb = (Bitmap) raw;
            }
            final Bitmap finalThumb = thumb;
            new Thread(() -> {
                String dataUrl = encodeFileOrBitmapToDataUrl(photoFile, finalThumb);
                deliverNativePhoto(cbId, dataUrl);
            }, "shree-cam-encode").start();
            return;
        }
        if (requestCode == REQ_FILE_CHOOSER && fileUploadCallback != null) {
            Uri[] result = null;
            if (resultCode == RESULT_OK) {
                if (data != null && data.getClipData() != null && data.getClipData().getItemCount() > 0) {
                    ClipData clip = data.getClipData();
                    List<Uri> uris = new ArrayList<>();
                    for (int i = 0; i < clip.getItemCount(); i++) {
                        Uri u = clip.getItemAt(i).getUri();
                        if (u != null) uris.add(u);
                    }
                    if (!uris.isEmpty()) result = uris.toArray(new Uri[0]);
                }
                if (result == null) {
                    result = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
                }
                if ((result == null || result.length == 0) && pendingCameraPhotoUri != null
                        && pendingCameraPhotoFile != null && pendingCameraPhotoFile.exists() && pendingCameraPhotoFile.length() > 0) {
                    result = new Uri[]{pendingCameraPhotoUri};
                }
            }
            pendingCameraPhotoUri = null;
            pendingCameraPhotoFile = null;
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
            return "1.0.4";
        }

        @JavascriptInterface
        public boolean hasCameraSupport() {
            return true;
        }

        @JavascriptInterface
        public boolean hasNativeCamera() {
            return true;
        }

        @JavascriptInterface
        public void captureCameraPhoto(String facing, String callbackId) {
            runOnUiThread(() -> startNativeCameraCapture(facing, callbackId));
        }
    }
}
