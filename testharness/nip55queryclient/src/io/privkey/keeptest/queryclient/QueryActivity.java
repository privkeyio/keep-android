package io.privkey.keeptest.queryclient;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.util.LinkedHashSet;

/**
 * Cross-process NIP-55 query driver for keep-android instrumented tests (#374).
 * Distinct applicationId => its own UID and debug signature, so keep's
 * getVerifiedCaller() treats it as a real external caller (not same-UID).
 * Reports the resulting cursor (columns + row0) back to the orchestrating test via a
 * broadcast to keep, and to logcat tag KEEPQC for diagnostics.
 *
 * Extras: authority, projection (String[]), reqid, repeat (per-thread), threads.
 * When run with several threads it reports the first observed single-column "error"
 * cursor if any (so the rate-limit reject is surfaced deterministically), else the last
 * cursor seen.
 */
public class QueryActivity extends Activity {
    private static final String TAG = "KEEPQC";
    private static final String RESULT_ACTION = "io.privkey.keeptest.QUERY_RESULT";
    private static final String KEEP_PKG = "io.privkey.keep";

    private final Object lock = new Object();
    private String errorResult = null;
    private String lastResult = null;
    private final LinkedHashSet<String> seen = new LinkedHashSet<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        final String reqid = intent.getStringExtra("reqid");
        final String authority = intent.getStringExtra("authority");
        final String[] projection = intent.getStringArrayExtra("projection");
        final int repeat = intent.getIntExtra("repeat", 1);
        final int threads = intent.getIntExtra("threads", 1);
        final boolean collect = intent.getBooleanExtra("collect", false);
        lastResult = "reqid=" + reqid + " cursor=null";
        final Uri uri = Uri.parse("content://" + authority);

        Runnable task = new Runnable() {
            @Override public void run() {
                for (int r = 0; r < repeat; r++) {
                    String desc;
                    boolean isError = false;
                    try {
                        Cursor c = getContentResolver().query(uri, projection, null, null, null);
                        try {
                            desc = describe(reqid, c);
                            if (c != null) {
                                String[] names = c.getColumnNames();
                                isError = names.length == 1 && "error".equals(names[0]);
                            }
                        } finally {
                            if (c != null) c.close();
                        }
                    } catch (Throwable t) {
                        desc = "reqid=" + reqid + " exception=" + t.getClass().getName() + ":" + t.getMessage();
                    }
                    synchronized (lock) {
                        lastResult = desc;
                        if (isError && errorResult == null) errorResult = desc;
                        seen.add(desc.replaceFirst("^reqid=\\S+ ", ""));
                    }
                }
            }
        };

        if (threads <= 1) {
            task.run();
        } else {
            Thread[] ts = new Thread[threads];
            for (int i = 0; i < threads; i++) { ts[i] = new Thread(task); ts[i].start(); }
            for (Thread t : ts) { try { t.join(); } catch (InterruptedException e) { /* ignore */ } }
        }

        String result;
        if (collect) {
            StringBuilder sb = new StringBuilder("reqid=" + reqid + " seen={");
            boolean first = true;
            synchronized (lock) {
                for (String s : seen) {
                    if (!first) sb.append(" || ");
                    sb.append(s);
                    first = false;
                }
            }
            sb.append("}");
            result = sb.toString();
        } else {
            result = errorResult != null ? errorResult : lastResult;
        }
        // Redact row0 contents from logcat only: on an auto-approve path row0 can carry a
        // real signature/pubkey (a SIGN_EVENT success row0 is signed-event JSON, which itself
        // contains ']'). Match greedily to the last bracket so such payloads are fully
        // redacted, failing safe toward more redaction. The broadcast below is
        // setPackage(KEEP_PKG)-scoped and carries the complete payload for the test to parse.
        Log.i(TAG, result.replaceAll("row0=\\[[\\s\\S]*\\]", "row0=[<redacted>]"));
        Intent back = new Intent(RESULT_ACTION);
        back.setPackage(KEEP_PKG);
        back.putExtra("reqid", reqid);
        back.putExtra("result", result);
        sendBroadcast(back);
        finish();
    }

    private String describe(String reqid, Cursor c) {
        if (c == null) return "reqid=" + reqid + " cursor=null";
        StringBuilder cols = new StringBuilder();
        String[] names = c.getColumnNames();
        for (int i = 0; i < names.length; i++) {
            if (i > 0) cols.append(",");
            cols.append(names[i]);
        }
        StringBuilder row0 = new StringBuilder();
        if (c.moveToFirst()) {
            for (int i = 0; i < c.getColumnCount(); i++) {
                row0.append(c.getString(i));
            }
        }
        return "reqid=" + reqid + " count=" + c.getCount() + " cols=[" + cols + "] row0=[" + row0 + "]";
    }
}
