package io.privkey.keep.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.privkey.keep.KeepMobileApp

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val app = context.applicationContext as? KeepMobileApp ?: return

        if (app.getForegroundServiceStore()?.isEnabled() == true) {
            KeepAliveService.start(context)
            return
        }

        if (app.getAutoStartStore()?.isEnabled() != true) return
        app.reconnectRelays()
    }
}
