package com.shree.itassets;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.http.SslCertificate;
import android.os.Build;
import android.os.Bundle;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class CertPinStore {
    private static final String PREFS_NAME = "shree_it_prefs";
    private static final String KEY_SERVER_URL = "server_url";
    private static final String KEY_PIN_FP = "pinned_cert_sha256";
    private static final String KEY_PIN_HOST = "pinned_host";
    private static final String KEY_BG_ALERTS = "bg_alerts_enabled";

    private CertPinStore() {}

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static String getServerUrl(Context ctx) {
        return prefs(ctx).getString(KEY_SERVER_URL, "").trim();
    }

    public static void setServerUrl(Context ctx, String url) {
        prefs(ctx).edit().putString(KEY_SERVER_URL, url == null ? "" : url.trim()).apply();
    }

    public static boolean isBgAlertsEnabled(Context ctx) {
        return prefs(ctx).getBoolean(KEY_BG_ALERTS, true);
    }

    public static void setBgAlertsEnabled(Context ctx, boolean enabled) {
        prefs(ctx).edit().putBoolean(KEY_BG_ALERTS, enabled).apply();
    }

    public static void savePinnedCert(Context ctx, String host, String sha256) {
        prefs(ctx).edit()
                .putString(KEY_PIN_HOST, host == null ? "" : host.toLowerCase(Locale.US))
                .putString(KEY_PIN_FP, sha256 == null ? "" : sha256.toUpperCase(Locale.US))
                .apply();
    }

    public static boolean isCertPinned(Context ctx, String host, String sha256) {
        if (host == null || sha256 == null || sha256.isEmpty()) return false;
        String savedHost = prefs(ctx).getString(KEY_PIN_HOST, "");
        String savedFp = prefs(ctx).getString(KEY_PIN_FP, "");
        return !savedFp.isEmpty()
                && savedHost.equalsIgnoreCase(host)
                && savedFp.equalsIgnoreCase(sha256);
    }

    public static X509Certificate extractX509(SslCertificate sslCert) {
        if (sslCert == null) return null;
        if (Build.VERSION.SDK_INT >= 29) {
            X509Certificate cert = sslCert.getX509Certificate();
            if (cert != null) return cert;
        }
        try {
            Bundle bundle = SslCertificate.saveState(sslCert);
            if (bundle != null) {
                byte[] bytes = bundle.getByteArray("x509-certificate");
                if (bytes != null && bytes.length > 0) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static String sha256Fingerprint(X509Certificate cert) {
        if (cert == null) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format(Locale.US, "%02X", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public static SSLSocketFactory buildPinnedSslSocketFactory(Context ctx, String targetHost) {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((java.security.KeyStore) null);
            X509TrustManager sysTm = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    sysTm = (X509TrustManager) tm;
                    break;
                }
            }
            final X509TrustManager defaultTm = sysTm;
            final Context appCtx = ctx.getApplicationContext();

            TrustManager[] wrapped = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                            if (defaultTm != null) defaultTm.checkClientTrusted(chain, authType);
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                            if (chain == null || chain.length == 0) {
                                throw new java.security.cert.CertificateException("Empty server certificate chain");
                            }
                            String leafFp = sha256Fingerprint(chain[0]);
                            if (isCertPinned(appCtx, targetHost, leafFp)) {
                                return;
                            }
                            if (defaultTm != null) {
                                defaultTm.checkServerTrusted(chain, authType);
                                return;
                            }
                            throw new java.security.cert.CertificateException("Untrusted certificate");
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return defaultTm != null ? defaultTm.getAcceptedIssuers() : new X509Certificate[0];
                        }
                    }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, wrapped, null);
            return sc.getSocketFactory();
        } catch (Exception e) {
            return null;
        }
    }

    public static HostnameVerifier buildPinnedHostnameVerifier(Context ctx, String targetHost) {
        final Context appCtx = ctx.getApplicationContext();
        final HostnameVerifier defaultHv = HttpsURLConnection.getDefaultHostnameVerifier();
        return (hostname, session) -> {
            if (defaultHv != null && defaultHv.verify(hostname, session)) {
                return true;
            }
            try {
                java.security.cert.Certificate[] certs = session.getPeerCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    String fp = sha256Fingerprint((X509Certificate) certs[0]);
                    return hostname != null && hostname.equalsIgnoreCase(targetHost) && isCertPinned(appCtx, targetHost, fp);
                }
            } catch (Exception ignored) {
            }
            return false;
        };
    }
}
