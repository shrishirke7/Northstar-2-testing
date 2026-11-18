package com.shree.itassets;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

public class PhotoContentProvider extends ContentProvider {
    private static final String[] COLUMNS = {
            OpenableColumns.DISPLAY_NAME,
            OpenableColumns.SIZE
    };

    public static File getPhotoFile(Context ctx, String fileName) {
        File dir = new File(ctx.getCacheDir(), "cam_photos");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return new File(dir, fileName);
    }

    public static Uri getContentUri(Context ctx, String fileName) {
        return Uri.parse("content://" + ctx.getPackageName() + ".photoprovider/cam/" + fileName);
    }

    private File resolveSafeFile(Uri uri) throws FileNotFoundException {
        Context ctx = getContext();
        if (ctx == null || uri == null) {
            throw new FileNotFoundException("Invalid context or URI");
        }
        String name = uri.getLastPathSegment();
        if (name == null || !name.matches("^[A-Za-z0-9_.-]+\\.(jpg|jpeg|png)$")) {
            throw new FileNotFoundException("Invalid camera filename");
        }
        return getPhotoFile(ctx, name);
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public String getType(Uri uri) {
        return "image/jpeg";
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File file = resolveSafeFile(uri);
        int pfdMode;
        try {
            pfdMode = ParcelFileDescriptor.parseMode(mode != null && !mode.isEmpty() ? mode : "r");
        } catch (Exception e) {
            pfdMode = ParcelFileDescriptor.MODE_READ_WRITE | ParcelFileDescriptor.MODE_CREATE;
        }
        if ((pfdMode & ParcelFileDescriptor.MODE_WRITE_ONLY) != 0
                || (pfdMode & ParcelFileDescriptor.MODE_READ_WRITE) != 0) {
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
        }
        return ParcelFileDescriptor.open(file, pfdMode);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        String[] cols = (projection != null && projection.length > 0) ? projection : COLUMNS;
        MatrixCursor cursor = new MatrixCursor(cols, 1);
        try {
            File file = resolveSafeFile(uri);
            Object[] row = new Object[cols.length];
            for (int i = 0; i < cols.length; i++) {
                if (OpenableColumns.DISPLAY_NAME.equals(cols[i])) {
                    row[i] = file.getName();
                } else if (OpenableColumns.SIZE.equals(cols[i])) {
                    row[i] = file.exists() ? file.length() : 0L;
                }
            }
            cursor.addRow(row);
        } catch (Exception ignored) {
        }
        return cursor;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        try {
            File file = resolveSafeFile(uri);
            return file.exists() && file.delete() ? 1 : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
