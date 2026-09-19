package com.siem.androidagent.collector

import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

data class AndroidLogEvent(
    val timestamp: String,
    val eventId: String,
    val generatorId: String,
    val hostname: String,
    val message: String
)

class AndroidLogCollector(
    private val collectorId: String
) {

    fun collectStartupEvent(): AndroidLogEvent {
        return createEvent("Android SIEM collector started")
    }

    fun collectTestEvent(): AndroidLogEvent {
        return createEvent(
            "Failed password for testuser from 192.168.1.50 port 22"
        )
    }

    // Simulates a failed-login event for SIEM testing.
    fun collectFailedLoginEvent(): AndroidLogEvent {
        return createEvent(
            "Failed password for testuser from 192.168.1.50 port 22"
        )
    }

    // Simulates a port-scan event for SIEM testing.
    fun collectPortScanEvent(): AndroidLogEvent {
        return createEvent(
            "Port scan detected from 192.168.1.50 against 192.168.1.171"
        )
    }

    // Simulates suspicious application activity.
    fun collectSuspiciousAppEvent(): AndroidLogEvent {
        return createEvent(
            "Suspicious application activity detected on Android device"
        )
    }

    fun collectAppInstalledEvent(
        packageName: String
    ): AndroidLogEvent {
        return createEvent(
            "Application installed on Android device: $packageName"
        )
    }

    fun collectAppUninstalledEvent(
        packageName: String
    ): AndroidLogEvent {
        return createEvent(
            "Application uninstalled from Android device: $packageName"
        )
    }

    /*
     * Creates a structured application-security event.
     *
     * The existing SIEM Agent protocol is preserved.
     * The structured security information is placed inside
     * the existing "message" field.
     */
    fun collectApplicationSecurityEvent(
        finding: AppSecurityFinding
    ): AndroidLogEvent {

        val messageJson = JSONObject().apply {

            put("event_type", "application_security")

            put(
                "event_category",
                "android_application"
            )

            put(
                "severity",
                finding.severity.name.lowercase(Locale.US)
            )

            put(
                "application_name",
                finding.applicationName
            )

            put(
                "package_name",
                finding.packageName
            )

            put(
                "application_type",
                finding.applicationType
            )

            put(
                "requested_sensitive_permissions",
                JSONArray(finding.requestedSensitivePermissions)
            )

            put(
                "granted_sensitive_permissions",
                JSONArray(finding.grantedSensitivePermissions)
            )

            put(
                "is_new_application",
                finding.isNewApplication
            )

            put(
                "permissions_changed",
                finding.permissionsChanged
            )

            put(
                "reason",
                finding.reason
            )
        }

        return createEvent(
            messageJson.toString()
        )
    }

    private fun createEvent(
        message: String
    ): AndroidLogEvent {

        return AndroidLogEvent(
            timestamp = getSiemTimestamp(),
            eventId = "ANDROID-" + UUID.randomUUID(),
            generatorId = collectorId,
            hostname = "Samsung-SM-F926B",
            message = message
        )
    }

    private fun getSiemTimestamp(): String {

        val formatter = SimpleDateFormat(
            "dd/MM/yyyy HH:mm:ss",
            Locale.US
        )

        formatter.timeZone =
            TimeZone.getTimeZone("Africa/Douala")

        return formatter.format(Date())
    }
}