package com.siem.androidagent.collector

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.siem.androidagent.config.ConfigRepository
import com.siem.androidagent.network.SiemAgentClient
import kotlinx.coroutines.flow.first

class ApplicationSecurityWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(
    appContext,
    workerParams
) {

    companion object {
        private const val TAG =
            "ApplicationSecurityWorker"
    }

    override suspend fun doWork(): Result {

        Log.d(
            TAG,
            "Starting background application-security scan"
        )

        return try {

            val context =
                applicationContext

            val configRepository =
                ConfigRepository(context)

            val config =
                configRepository.config.first()

            if (
                config.ipAddress.isBlank() ||
                config.port.isBlank() ||
                config.collectorId.isBlank()
            ) {

                Log.e(
                    TAG,
                    "SIEM configuration is incomplete"
                )

                return Result.failure()
            }

            val analyzer =
                AppSecurityAnalyzer(context)

            val findings =
                analyzer.analyzeInstalledApplications()

            Log.d(
                TAG,
                "Background scan completed: " +
                        "${findings.size} finding(s)"
            )

            if (findings.isEmpty()) {
                return Result.success()
            }

            val collector =
                AndroidLogCollector(
                    config.collectorId
                )

            val client =
                SiemAgentClient()

            var successful = 0
            var failed = 0

            for (finding in findings) {

                try {

                    val event =
                        collector.collectApplicationSecurityEvent(
                            finding
                        )

                    Log.d(
                        TAG,
                        "Sending application-security event: " +
                                event.message
                    )

                    val response =
                        client.sendEvent(
                            ipAddress = config.ipAddress,
                            port = config.port,
                            event = event
                        )

                    Log.d(
                        TAG,
                        "SIEM response: $response"
                    )

                    if (response.startsWith("HTTP 200")) {
                        successful++
                    } else {
                        failed++
                    }

                } catch (e: Exception) {

                    failed++

                    Log.e(
                        TAG,
                        "Failed to send application-security event",
                        e
                    )
                }
            }

            Log.d(
                TAG,
                "Background application-security scan finished: " +
                        "$successful sent, $failed failed"
            )

            if (failed > 0 && successful == 0) {
                Result.retry()
            } else {
                Result.success()
            }

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Background application-security scan failed",
                e
            )

            Result.retry()
        }
    }
}
