package com.siem.androidagent.collector

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

object AppSecurityScheduler {

    private const val WORK_NAME =
        "android_application_security_monitor"

    fun schedule(context: Context) {

        val workRequest =
            PeriodicWorkRequestBuilder<ApplicationSecurityWorker>(
                15,
                TimeUnit.MINUTES
            ).build()

        WorkManager
            .getInstance(context.applicationContext)
            .enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                workRequest
            )
    }
}
