package com.siem.androidagent.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.siem.androidagent.collector.AndroidLogCollector
import com.siem.androidagent.config.ConfigRepository
import com.siem.androidagent.network.SiemAgentClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class AppChangeReceiver : BroadcastReceiver() {

    override fun onReceive(
        context: Context,
        intent: Intent
    ) {

        Log.e(
            "AppChangeReceiver",
            "BROADCAST RECEIVED: action=${intent.action}, data=${intent.data}"
        )

        val packageName =
            intent.data?.schemeSpecificPart

        if (packageName == null) {
            Log.e(
                "AppChangeReceiver",
                "No package name found in broadcast"
            )
            return
        }

        val action = intent.action

        if (action == null) {
            Log.e(
                "AppChangeReceiver",
                "No action found in broadcast"
            )
            return
        }

        Log.e(
            "AppChangeReceiver",
            "App change detected: $action - $packageName"
        )

        val pendingResult = goAsync()

        CoroutineScope(Dispatchers.IO).launch {

            try {

                val configRepository =
                    ConfigRepository(context.applicationContext)

                val config =
                    configRepository.config.first()

                if (
                    config.ipAddress.isBlank() ||
                    config.port.isBlank() ||
                    config.collectorId.isBlank()
                ) {
                    Log.e(
                        "AppChangeReceiver",
                        "SIEM configuration is incomplete"
                    )
                    return@launch
                }

                val collector =
                    AndroidLogCollector(config.collectorId)

                val event =
                    when (action) {

                        Intent.ACTION_PACKAGE_ADDED ->
                            collector.collectAppInstalledEvent(
                                packageName
                            )

                        Intent.ACTION_PACKAGE_REMOVED ->
                            collector.collectAppUninstalledEvent(
                                packageName
                            )

                        else -> {
                            Log.d(
                                "AppChangeReceiver",
                                "Ignoring action: $action"
                            )
                            return@launch
                        }
                    }

                val client =
                    SiemAgentClient()

                val response =
                    client.sendEvent(
                        ipAddress = config.ipAddress,
                        port = config.port,
                        event = event
                    )

                Log.d(
                    "AppChangeReceiver",
                    "SIEM response: $response"
                )

            } catch (e: Exception) {

                Log.e(
                    "AppChangeReceiver",
                    "Failed to process app change",
                    e
                )

            } finally {

                pendingResult.finish()
            }
        }
    }
}