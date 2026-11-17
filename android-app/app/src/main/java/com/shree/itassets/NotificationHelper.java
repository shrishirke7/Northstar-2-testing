package com.shree.itassets;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.media.AudioAttributes;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;

import java.util.concurrent.atomic.AtomicInteger;

public final class NotificationHelper {
    public static final String CHANNEL_ALERTS = "shree_alerts";
    public static final String CHANNEL_MONITOR = "shree_bg_monitor";
    public static final int FOREGROUND_ID = 1001;
    private static final AtomicInteger NEXT_ID = new AtomicInteger(2000);

    private NotificationHelper() {}

    public static void ensureChannels(Context ctx) {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        if (nm.getNotificationChannel(CHANNEL_ALERTS) == null) {
            NotificationChannel alertCh = new NotificationChannel(
                    CHANNEL_ALERTS,
                    "IT & Device Alerts",
                    NotificationManager.IMPORTANCE_HIGH
            );
            alertCh.setDescription("Real-time IT tickets and device online/offline alerts");
            alertCh.enableLights(true);
            alertCh.setLightColor(Color.parseColor("#157a54"));
            alertCh.enableVibration(true);
            alertCh.setVibrationPattern(new long[]{0, 220, 100, 220});
            Uri sound = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
            AudioAttributes attrs = new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build();
            alertCh.setSound(sound, attrs);
            nm.createNotificationChannel(alertCh);
        }

        if (nm.getNotificationChannel(CHANNEL_MONITOR) == null) {
            NotificationChannel bgCh = new NotificationChannel(
                    CHANNEL_MONITOR,
                    "Background Live Connection",
                    NotificationManager.IMPORTANCE_MIN
            );
            bgCh.setDescription("Maintains live Shree IT alert monitoring");
            bgCh.setShowBadge(false);
            nm.createNotificationChannel(bgCh);
        }
    }

    public static Notification buildForegroundNotification(Context ctx) {
        ensureChannels(ctx);
        Intent intent = new Intent(ctx, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        PendingIntent pi = PendingIntent.getActivity(ctx, 1, intent, flags);

        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(ctx, CHANNEL_MONITOR)
                : new Notification.Builder(ctx);
        b.setContentTitle("Shree IT Connected")
                .setContentText("Real-time alert monitor is active")
                .setSmallIcon(R.drawable.ic_stat_shree)
                .setColor(android.graphics.Color.parseColor("#051433"))
                .setLargeIcon(android.graphics.BitmapFactory.decodeResource(ctx.getResources(), R.mipmap.ic_launcher))
                .setOngoing(true)
                .setContentIntent(pi);
        if (Build.VERSION.SDK_INT < 26) {
            b.setPriority(Notification.PRIORITY_MIN);
        }
        return b.build();
    }

    public static void showAlert(Context ctx, String title, String body, String targetView, String targetId) {
        ensureChannels(ctx);
        NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        int nid = NEXT_ID.incrementAndGet();
        Intent intent = new Intent(ctx, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        if (targetView != null) intent.putExtra("targetView", targetView);
        if (targetId != null) intent.putExtra("targetId", targetId);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        PendingIntent pi = PendingIntent.getActivity(ctx, nid, intent, flags);

        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(ctx, CHANNEL_ALERTS)
                : new Notification.Builder(ctx);
        b.setContentTitle(title == null || title.isEmpty() ? "Shree IT Alert" : title)
                .setContentText(body == null ? "" : body)
                .setStyle(new Notification.BigTextStyle().bigText(body == null ? "" : body))
                .setSmallIcon(R.drawable.ic_stat_shree)
                .setColor(android.graphics.Color.parseColor("#051433"))
                .setLargeIcon(android.graphics.BitmapFactory.decodeResource(ctx.getResources(), R.mipmap.ic_launcher))
                .setAutoCancel(true)
                .setContentIntent(pi);
        if (Build.VERSION.SDK_INT < 26) {
            b.setPriority(Notification.PRIORITY_HIGH);
            b.setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION));
            b.setVibrate(new long[]{0, 220, 100, 220});
        }
        try {
            nm.notify(nid, b.build());
        } catch (SecurityException ignored) {
        }
    }
}
