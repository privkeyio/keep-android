package io.privkey.keep.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest

class NetworkConnectivityManager(
    context: Context,
    private val onNetworkChanged: () -> Unit
) {
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    @Volatile private var lastNetwork: Network? = null
    @Volatile private var isRegistered = false
    @Volatile private var lastReconnectTime = 0L

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (lastNetwork != null && lastNetwork != network) {
                val now = System.currentTimeMillis()
                if (now - lastReconnectTime >= DEBOUNCE_INTERVAL_MS) {
                    lastReconnectTime = now
                    onNetworkChanged()
                }
            }
            lastNetwork = network
        }

        override fun onLost(network: Network) {
            lastNetwork = null
        }
    }

    fun register() {
        if (isRegistered) return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, networkCallback)
        isRegistered = true
    }

    fun unregister() {
        if (!isRegistered) return
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        isRegistered = false
        lastNetwork = null
    }

    companion object {
        private const val DEBOUNCE_INTERVAL_MS = 5000L
    }
}
