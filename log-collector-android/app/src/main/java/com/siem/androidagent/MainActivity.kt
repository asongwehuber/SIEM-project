package com.siem.androidagent

import android.os.Bundle
import android.util.Log

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding

import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue

import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

import com.siem.androidagent.collector.AndroidLogCollector
import com.siem.androidagent.collector.AppInventoryCollector
import com.siem.androidagent.collector.AppSecurityAnalyzer
import com.siem.androidagent.collector.AppSecuritySeverity
import com.siem.androidagent.config.AgentConfig
import com.siem.androidagent.config.ConfigRepository
import com.siem.androidagent.network.SiemAgentClient
import com.siem.androidagent.ui.theme.AndroidSIEMAgentTheme
import com.siem.androidagent.collector.AppSecurityScheduler

import kotlinx.coroutines.launch

import java.net.HttpURLConnection
import java.net.URL


class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {

        super.onCreate(savedInstanceState)

        enableEdgeToEdge()

        AppSecurityScheduler.schedule(applicationContext)

        setContent {

            AndroidSIEMAgentTheme {

                SiemConfigurationScreen()
            }
        }
    }
}


@Composable
fun SiemConfigurationScreen() {

    val context =
        LocalContext.current


    val repository =
        remember {
            ConfigRepository(context)
        }


    val siemAgentClient =
        remember {
            SiemAgentClient()
        }


    val appInventoryCollector =
        remember {
            AppInventoryCollector(context)
        }


    val appSecurityAnalyzer =
        remember {
            AppSecurityAnalyzer(context)
        }


    val savedConfig by
    repository.config.collectAsState(
        initial = AgentConfig()
    )


    val coroutineScope =
        rememberCoroutineScope()


    var ipAddress by
    remember {
        mutableStateOf(
            savedConfig.ipAddress
        )
    }


    var port by
    remember {
        mutableStateOf(
            savedConfig.port
        )
    }


    var collectorId by
    remember {
        mutableStateOf(
            savedConfig.collectorId
        )
    }


    var status by
    remember {
        mutableStateOf(
            "Not Connected"
        )
    }


    /*
     * Stores the local application-security
     * analysis result.
     */
    var securityAnalysis by
    remember {
        mutableStateOf(
            "Application security analysis not performed"
        )
    }


    /*
     * Keep the UI synchronized with
     * the saved configuration.
     */
    LaunchedEffect(savedConfig) {

        ipAddress =
            savedConfig.ipAddress

        port =
            savedConfig.port

        collectorId =
            savedConfig.collectorId
    }


    /*
     * Send startup event when configuration
     * becomes available.
     */
    LaunchedEffect(savedConfig.collectorId) {

        if (
            savedConfig.collectorId.isBlank() ||
            savedConfig.ipAddress.isBlank() ||
            savedConfig.port.isBlank()
        ) {

            return@LaunchedEffect
        }


        Thread {

            try {

                val collector =
                    AndroidLogCollector(
                        savedConfig.collectorId
                    )


                val event =
                    collector.collectStartupEvent()


                val response =
                    siemAgentClient.sendEvent(

                        ipAddress =
                            savedConfig.ipAddress,

                        port =
                            savedConfig.port,

                        event =
                            event
                    )


                Log.d(
                    "MainActivity",
                    "Android startup event response: $response"
                )

            } catch (e: Exception) {

                Log.e(
                    "MainActivity",
                    "Android startup event failed",
                    e
                )
            }

        }.start()
    }


    /*
     * Generic security-event sender.
     *
     * This is currently used only by the
     * existing TEST buttons.
     */
    fun sendSecurityEvent(
        event:
        com.siem.androidagent.collector.AndroidLogEvent,

        eventName: String
    ) {

        status =
            "Sending $eventName..."


        Thread {

            try {

                val response =
                    siemAgentClient.sendEvent(

                        ipAddress =
                            ipAddress,

                        port =
                            port,

                        event =
                            event
                    )


                Log.d(
                    "MainActivity",
                    "Android $eventName response: $response"
                )


                (context as? ComponentActivity)
                    ?.runOnUiThread {

                        status =
                            if (
                                response.startsWith(
                                    "HTTP 200"
                                )
                            ) {

                                "$eventName accepted by SIEM Agent"

                            } else {

                                "$eventName rejected\n$response"
                            }
                    }


            } catch (e: Exception) {

                (context as? ComponentActivity)
                    ?.runOnUiThread {

                        status =
                            "$eventName failed: ${e.message}"
                    }
            }

        }.start()
    }


    /*
     * Scan installed applications and send
     * detected changes to the SIEM Agent.
     */
    fun scanApplicationChanges() {

        status =
            "Scanning installed applications..."


        Thread {

            try {

                val changes =
                    appInventoryCollector
                        .detectApplicationChanges()


                if (changes.isEmpty()) {

                    (context as? ComponentActivity)
                        ?.runOnUiThread {

                            status =
                                "Application scan completed - no changes detected"
                        }

                    return@Thread
                }


                var successful =
                    0


                var failed =
                    0


                val collector =
                    AndroidLogCollector(
                        collectorId
                    )


                for (change in changes) {

                    try {

                        val event =

                            when (
                                change.type
                            ) {

                                com.siem.androidagent.collector
                                    .AppInventoryEventType.INSTALLED ->

                                    collector
                                        .collectAppInstalledEvent(
                                            change.packageName
                                        )


                                com.siem.androidagent.collector
                                    .AppInventoryEventType.UNINSTALLED ->

                                    collector
                                        .collectAppUninstalledEvent(
                                            change.packageName
                                        )
                            }


                        Log.d(
                            "MainActivity",
                            "Sending application event: " +
                                    event.message
                        )


                        val response =
                            siemAgentClient.sendEvent(

                                ipAddress =
                                    ipAddress,

                                port =
                                    port,

                                event =
                                    event
                            )


                        Log.d(
                            "MainActivity",
                            "Application event response: $response"
                        )


                        if (
                            response.startsWith(
                                "HTTP 200"
                            )
                        ) {

                            successful++

                        } else {

                            failed++
                        }


                    } catch (e: Exception) {

                        failed++

                        Log.e(
                            "MainActivity",
                            "Failed to send application change",
                            e
                        )
                    }
                }


                (context as? ComponentActivity)
                    ?.runOnUiThread {

                        status =
                            "Application scan completed: " +
                                    "$successful event(s) sent, " +
                                    "$failed failed"
                    }


            } catch (e: Exception) {

                Log.e(
                    "MainActivity",
                    "Application scan failed",
                    e
                )


                (context as? ComponentActivity)
                    ?.runOnUiThread {

                        status =
                            "Application scan failed: ${e.message}"
                    }
            }

        }.start()
    }


    /*
     * =====================================================
     * REAL APPLICATION SECURITY ANALYSIS
     * =====================================================
     *
     * This reads actual application information from
     * PackageManager through AppSecurityAnalyzer.
     *
     * Findings are now also sent to the SIEM Agent.
     */
    fun analyzeApplicationSecurity() {

        status =
            "Analyzing installed applications..."


        securityAnalysis =
            "Analyzing applications..."


        Thread {

            try {

                val findings =
                    appSecurityAnalyzer
                        .analyzeInstalledApplications()


                /*
                 * Count findings by severity.
                 */
                val lowCount =
                    findings.count {
                        it.severity ==
                                AppSecuritySeverity.LOW
                    }


                val mediumCount =
                    findings.count {
                        it.severity ==
                                AppSecuritySeverity.MEDIUM
                    }


                val highCount =
                    findings.count {
                        it.severity ==
                                AppSecuritySeverity.HIGH
                    }


                /*
                 * Build a readable local report.
                 */
                val report =
                    if (findings.isEmpty()) {

                        "No application security findings detected."

                    } else {

                        buildString {

                            append(
                                "Security findings: " +
                                        findings.size
                            )

                            append("\n")

                            append(
                                "LOW: $lowCount   "
                            )

                            append(
                                "MEDIUM: $mediumCount   "
                            )

                            append(
                                "HIGH: $highCount"
                            )

                            append("\n\n")


                            findings
                                .take(10)
                                .forEachIndexed {
                                        index,
                                        finding ->

                                    append(
                                        "${index + 1}. "
                                    )

                                    append(
                                        finding.applicationName
                                    )

                                    append("\n")

                                    append(
                                        finding.packageName
                                    )

                                    append("\n")

                                    append(
                                        "Severity: "
                                    )

                                    append(
                                        finding.severity
                                    )

                                    append("\n")

                                    append(
                                        finding.reason
                                    )

                                    append("\n\n")
                                }


                            if (
                                findings.size > 10
                            ) {

                                append(
                                    "...and " +
                                            (findings.size - 10) +
                                            " more finding(s)."
                                )
                            }
                        }
                    }


                /*
                 * Log every finding for verification
                 * in Android Studio Logcat.
                 */
                for (finding in findings) {

                    Log.d(
                        "AppSecurityAnalyzer",

                        "SECURITY FINDING | " +
                                "application=${finding.applicationName} | " +
                                "package=${finding.packageName} | " +
                                "severity=${finding.severity} | " +
                                "reason=${finding.reason}"
                    )
                }


                /*
                 * =================================================
                 * SEND APPLICATION SECURITY FINDINGS TO SIEM
                 * =================================================
                 *
                 * Each finding is converted into an
                 * AndroidLogEvent.
                 *
                 * AndroidLogCollector creates the structured
                 * application-security JSON inside the message
                 * field.
                 *
                 * SiemAgentClient then uses the existing HMAC
                 * signing and sends the normal SIEM JSON envelope.
                 */
                var successful =
                    0


                var failed =
                    0


                val collector =
                    AndroidLogCollector(
                        collectorId
                    )


                for (finding in findings) {

                    try {

                        val event =
                            collector
                                .collectApplicationSecurityEvent(
                                    finding
                                )


                        /*
                         * Print the exact JSON message
                         * before sending it.
                         */
                        Log.d(
                            "MainActivity",
                            "APPLICATION SECURITY JSON: " +
                                    event.message
                        )


                        val response =
                            siemAgentClient.sendEvent(

                                ipAddress =
                                    ipAddress,

                                port =
                                    port,

                                event =
                                    event
                            )


                        Log.d(
                            "MainActivity",
                            "Application security event response: " +
                                    response
                        )


                        if (
                            response.startsWith(
                                "HTTP 200"
                            )
                        ) {

                            successful++

                        } else {

                            failed++
                        }


                    } catch (e: Exception) {

                        failed++

                        Log.e(
                            "MainActivity",
                            "Failed to send application security event",
                            e
                        )
                    }
                }


                /*
                 * Update the UI.
                 */
                (context as? ComponentActivity)
                    ?.runOnUiThread {

                        securityAnalysis =
                            report

                        status =
                            "Application security analysis completed: " +
                                    "${findings.size} finding(s), " +
                                    "$successful sent, " +
                                    "$failed failed"
                    }


            } catch (e: Exception) {

                Log.e(
                    "MainActivity",
                    "Application security analysis failed",
                    e
                )


                (context as? ComponentActivity)
                    ?.runOnUiThread {

                        securityAnalysis =
                            "Analysis failed: ${e.message}"

                        status =
                            "Application security analysis failed"
                    }
            }

        }.start()
    }


    Column(

        modifier =
            Modifier
                .fillMaxSize()
                .padding(24.dp),

        verticalArrangement =
            Arrangement.Center
    ) {


        Text(

            text =
                "Android SIEM Agent",

            style =
                MaterialTheme.typography
                    .headlineMedium
        )


        Spacer(
            modifier =
                Modifier.height(24.dp)
        )


        OutlinedTextField(

            value =
                ipAddress,

            onValueChange = {

                ipAddress =
                    it
            },

            label = {

                Text(
                    "SIEM Agent IP Address"
                )
            },

            modifier =
                Modifier.fillMaxWidth(),

            singleLine = true
        )


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        OutlinedTextField(

            value =
                port,

            onValueChange = {

                port =
                    it
            },

            label = {

                Text(
                    "Port"
                )
            },

            modifier =
                Modifier.fillMaxWidth(),

            singleLine = true
        )


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        OutlinedTextField(

            value =
                collectorId,

            onValueChange = {

                collectorId =
                    it
            },

            label = {

                Text(
                    "Collector ID"
                )
            },

            modifier =
                Modifier.fillMaxWidth(),

            singleLine = true
        )


        Spacer(
            modifier =
                Modifier.height(20.dp)
        )


        /*
         * Save configuration.
         */
        Button(

            onClick = {

                coroutineScope.launch {

                    repository.saveConfig(

                        AgentConfig(

                            ipAddress =
                                ipAddress,

                            port =
                                port,

                            collectorId =
                                collectorId
                        )
                    )


                    status =
                        "Configuration saved"
                }
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Save Configuration"
            )
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        /*
         * Test SIEM Agent connection.
         */
        Button(

            onClick = {

                status =
                    "Testing connection..."


                Thread {

                    try {

                        val url =
                            URL(
                                "http://$ipAddress:$port/health"
                            )


                        val connection =
                            url.openConnection()
                                    as HttpURLConnection


                        connection.requestMethod =
                            "GET"


                        connection.connectTimeout =
                            5000


                        connection.readTimeout =
                            5000


                        val responseCode =
                            connection.responseCode


                        connection.disconnect()


                        (context as? ComponentActivity)
                            ?.runOnUiThread {

                                if (
                                    responseCode == 200
                                ) {

                                    status =
                                        "Connected - SIEM Agent healthy"

                                } else {

                                    status =
                                        "Server responded - HTTP $responseCode"
                                }
                            }


                    } catch (e: Exception) {

                        (context as? ComponentActivity)
                            ?.runOnUiThread {

                                status =
                                    "Connection failed: ${e.message}"
                            }
                    }

                }.start()
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Test Connection"
            )
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        /*
         * Normal test log.
         */
        Button(

            onClick = {

                status =
                    "Sending test log..."


                Thread {

                    try {

                        val collector =
                            AndroidLogCollector(
                                collectorId
                            )


                        val event =
                            collector
                                .collectTestEvent()


                        val response =
                            siemAgentClient.sendEvent(

                                ipAddress =
                                    ipAddress,

                                port =
                                    port,

                                event =
                                    event
                            )


                        Log.d(
                            "MainActivity",
                            "Android SIEM response: $response"
                        )


                        (context as? ComponentActivity)
                            ?.runOnUiThread {

                                status =

                                    if (
                                        response.startsWith(
                                            "HTTP 200"
                                        )
                                    ) {

                                        "Test log accepted by SIEM Agent"

                                    } else {

                                        "Test log rejected\n$response"
                                    }
                            }


                    } catch (e: Exception) {

                        (context as? ComponentActivity)
                            ?.runOnUiThread {

                                status =
                                    "Send failed: ${e.message}"
                            }
                    }

                }.start()
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Send Test Log"
            )
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        /*
         * Application inventory scanner.
         */
        Button(

            onClick = {

                scanApplicationChanges()
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Scan Application Changes"
            )
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        /*
         * REAL APPLICATION SECURITY ANALYSIS
         */
        Button(

            onClick = {

                analyzeApplicationSecurity()
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Analyze Application Security"
            )
        }


        Spacer(
            modifier =
                Modifier.height(12.dp)
        )


        /*
         * Display the local security-analysis result.
         */
        Text(

            text =
                securityAnalysis,

            style =
                MaterialTheme.typography.bodySmall
        )


        Spacer(
            modifier =
                Modifier.height(16.dp)
        )


        /*
         * Security testing buttons.
         */
        Text(

            text =
                "Security Event Testing",

            style =
                MaterialTheme.typography
                    .titleMedium
        )


        Spacer(
            modifier =
                Modifier.height(8.dp)
        )


        /*
         * Failed login TEST.
         */
        Button(

            onClick = {

                val collector =
                    AndroidLogCollector(
                        collectorId
                    )


                sendSecurityEvent(

                    event =
                        collector
                            .collectFailedLoginEvent(),

                    eventName =
                        "Failed Login TEST"
                )
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Send Failed Login TEST"
            )
        }


        Spacer(
            modifier =
                Modifier.height(8.dp)
        )


        /*
         * Port scan TEST.
         */
        Button(

            onClick = {

                val collector =
                    AndroidLogCollector(
                        collectorId
                    )


                sendSecurityEvent(

                    event =
                        collector
                            .collectPortScanEvent(),

                    eventName =
                        "Port Scan TEST"
                )
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Send Port Scan TEST"
            )
        }


        Spacer(
            modifier =
                Modifier.height(8.dp)
        )


        /*
         * Suspicious application TEST.
         */
        Button(

            onClick = {

                val collector =
                    AndroidLogCollector(
                        collectorId
                    )


                sendSecurityEvent(

                    event =
                        collector
                            .collectSuspiciousAppEvent(),

                    eventName =
                        "Suspicious App TEST"
                )
            },

            modifier =
                Modifier.fillMaxWidth()

        ) {

            Text(
                "Send Suspicious App TEST"
            )
        }


        Spacer(
            modifier =
                Modifier.height(16.dp)
        )


        Text(

            text =
                "Connection Status: $status",

            style =
                MaterialTheme.typography
                    .bodyLarge
        )
    }
}