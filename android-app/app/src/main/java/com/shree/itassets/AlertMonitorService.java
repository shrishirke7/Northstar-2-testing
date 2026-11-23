package com.shree.itassets;

import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.webkit.CookieManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

public class AlertMonitorService extends Service {
    private volatile boolean running = false;
    private Thread pollThread = null;
    private String lastHistoryRev = "";
    private String lastTicketRev = "";
    private String lastNotifRev = "";
    private String lastAlertId = "";

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(
                        NotificationHelper.FOREGROUND_ID,
                        NotificationHelper.buildForegroundNotification(this),
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                );
            } else {
                startForeground(
                        NotificationHelper.FOREGROUND_ID,
                        NotificationHelper.buildForegroundNotification(this)
                );
            }
        } catch (Exception ignored) {
        }
        running = true;
        pollThread = new Thread(this::pollLoop, "shree-alert-poll");
        pollThread.start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        if (pollThread != null) {
            pollThread.interrupt();
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private String fetchJson(String fullUrl, String baseUrl) throws Exception {
        URL u = new URL(fullUrl);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("X-Requested-With", "NorthstarIT");

        if (conn instanceof HttpsURLConnection) {
            String host = u.getHost();
            SSLSocketFactory sf = CertPinStore.buildPinnedSslSocketFactory(this, host);
            HostnameVerifier hv = CertPinStore.buildPinnedHostnameVerifier(this, host);
            if (sf != null) ((HttpsURLConnection) conn).setSSLSocketFactory(sf);
            if (hv != null) ((HttpsURLConnection) conn).setHostnameVerifier(hv);
        }

        try {
            String cookie = CookieManager.getInstance().getCookie(baseUrl);
            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }
        } catch (Exception ignored) {
        }

        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            conn.disconnect();
            return null;
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
        }
        conn.disconnect();
        return sb.toString();
    }

    private void pollLoop() {
        while (running) {
            try {
                if (CertPinStore.isBgAlertsEnabled(this)) {
                    String baseUrl = CertPinStore.getServerUrl(this);
                    if (!baseUrl.isEmpty()) {
                        Uri parsed = Uri.parse(baseUrl);
                        String origin = parsed.getScheme() + "://" + parsed.getAuthority();
                        String rawPulse = fetchJson(origin + "/api/live-pulse", origin);
                        if (rawPulse != null) {
                            JSONObject obj = new JSONObject(rawPulse);
                            String histRev = obj.optString("historyRev", "");
                            String tickRev = obj.optString("ticketRev", "");
                            String notifRev = obj.optString("notificationsRev", "");

                            boolean changed = (!lastHistoryRev.isEmpty() && !histRev.equals(lastHistoryRev))
                                    || (!lastTicketRev.isEmpty() && !tickRev.equals(lastTicketRev))
                                    || (!lastNotifRev.isEmpty() && !notifRev.equals(lastNotifRev));

                            if (!histRev.isEmpty()) lastHistoryRev = histRev;
                            if (!tickRev.isEmpty()) lastTicketRev = tickRev;
                            if (!notifRev.isEmpty()) lastNotifRev = notifRev;

                            if (changed && !MainActivity.isAppInForeground) {
                                checkLatestNotification(origin);
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    private void checkLatestNotification(String origin) {
        try {
            String rawHist = fetchJson(origin + "/api/notifications/history", origin);
            if (rawHist == null) return;
            JSONObject obj = new JSONObject(rawHist);
            JSONArray events = obj.optJSONArray("events");
            if (events == null || events.length() == 0) return;
            JSONObject latest = events.optJSONObject(0);
            if (latest == null) return;
            String id = latest.optString("id", "");
            if (id.isEmpty() || id.equals(lastAlertId)) return;
            lastAlertId = id;

            if (obj.optBoolean("silentMode", false)) return;
            if (latest.optBoolean("read", false)) return;

            String title = latest.optString("title", "Shree IT Alert");
            String body = latest.optString("body", "New IT update received");
            String kind = latest.optString("kind", "").trim().toLowerCase(java.util.Locale.ROOT);
            String devType = latest.optString("deviceType", "").trim().toLowerCase(java.util.Locale.ROOT);
            String devSub = latest.optString("deviceSubtype", "").trim().toLowerCase(java.util.Locale.ROOT);

            // Sync mute rules (per device type & event category) with logged-in user's server config
            try {
                String rawSounds = fetchJson(origin + "/api/notifications/sounds", origin);
                if (rawSounds != null) {
                    JSONObject sObj = new JSONObject(rawSounds);
                    JSONObject soundAlerts = sObj.optJSONObject("soundAlerts");
                    if (soundAlerts != null) {
                        JSONObject evMap = soundAlerts.optJSONObject("events");
                        String evKey = ("material_request".equals(kind) || "helpdesk_message".equals(kind)) ? "ticket" : kind;
                        if (evMap != null && !evKey.isEmpty()) {
                            JSONObject evRule = evMap.optJSONObject(evKey);
                            if (evRule != null && !evRule.optBoolean("enabled", true)) {
                                return;
                            }
                        }
                        JSONObject devRules = soundAlerts.optJSONObject("deviceRules");
                        if (devRules != null) {
                            if ("visitor".equals(kind)) {
                                JSONObject vRule = devRules.optJSONObject("visitor pass");
                                if (vRule != null && vRule.optBoolean("silent", false)) {
                                    return;
                                }
                            } else if ("gatepass".equals(kind)) {
                                JSONObject gRule = devRules.optJSONObject("material entry");
                                if (gRule == null) gRule = devRules.optJSONObject("material gate entry");
                                if (gRule != null && gRule.optBoolean("silent", false)) {
                                    return;
                                }
                            }
                        }
                        boolean isDeviceEv = !devType.isEmpty() || !devSub.isEmpty()
                                || "online".equals(kind) || "offline".equals(kind) || "critical".equals(kind);
                        boolean anyMatched = false;
                        if (devRules != null) {
                            String hay = (devSub + " " + devType + " " + title + " " + body).toLowerCase(java.util.Locale.ROOT);
                            java.util.Iterator<String> keys = devRules.keys();
                            while (keys.hasNext()) {
                                String rk = keys.next();
                                JSONObject rule = devRules.optJSONObject(rk);
                                if (rule == null || rk == null || rk.trim().isEmpty()) continue;
                                String kn = rk.trim().toLowerCase(java.util.Locale.ROOT);
                                boolean matched = kn.equals(devSub) || kn.equals(devType)
                                        || java.util.regex.Pattern.compile("(?:^|[^a-z0-9])" + java.util.regex.Pattern.quote(kn) + "(?:$|[^a-z0-9])")
                                                .matcher(hay).find();
                                if (matched) {
                                    anyMatched = true;
                                    if (rule.optBoolean("silent", false)) {
                                        return;
                                    }
                                }
                            }
                        }
                        if (isDeviceEv && !anyMatched && soundAlerts.optBoolean("defaultNewTypeSilent", false)) {
                            return;
                        }
                    }
                }
            } catch (Exception ignored) {
            }

            String targetView = latest.optString("targetView", "notifications");
            String targetId = latest.optString("targetId", "");
            String targetThreadId = latest.optString("targetThreadId", "");
            String targetTicketId = latest.optString("targetTicketId", "");
            if (!targetThreadId.isEmpty() || "ticket".equals(kind) || "material_request".equals(kind) || "helpdesk_message".equals(kind)) {
                targetView = "messages";
                if (!targetThreadId.isEmpty()) targetId = targetThreadId;
                else if (targetId.isEmpty() && !targetTicketId.isEmpty()) targetId = targetTicketId;
            }
            NotificationHelper.showAlert(this, title, body, targetView, targetId);
        } catch (Exception ignored) {
        }
    }
}
