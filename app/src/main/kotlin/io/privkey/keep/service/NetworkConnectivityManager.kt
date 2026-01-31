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
    private val lock = Any()
    private var lastNetwork: Network? = null
    private var isRegistered = false
    private var lastReconnectTime = 0L

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val shouldReconnect = synchronized(lock) {
                if (lastNetwork == network) return@synchronized false
                lastNetwork = network

                val now = System.currentTimeMillis()
                if (now - lastReconnectTime < DEBOUNCE_INTERVAL_MS) return@synchronized false
                lastReconnectTime = now
                true
            }
            if (shouldReconnect) onNetworkChanged()
        }

        override fun onLost(network: Network) {
            synchronized(lock) {
                if (lastNetwork == network) lastNetwork = null
            }
        }
    }

    fun register() {
        synchronized(lock) {
            if (isRegistered) return
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
            isRegistered = true
        }
    }

    fun unregister() {
        synchronized(lock) {
            if (!isRegistered) return
            runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
            isRegistered = false
            lastNetwork = null
        }
    }

    companion object {
        private const val DEBOUNCE_INTERVAL_MS = 5000L
    }
}
