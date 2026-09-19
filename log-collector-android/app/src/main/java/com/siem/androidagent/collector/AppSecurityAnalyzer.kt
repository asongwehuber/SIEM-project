package com.siem.androidagent.collector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.util.Log

data class AppSecurityFinding(
    val applicationName: String,
    val packageName: String,
    val applicationType: String,
    val requestedSensitivePermissions: List<String>,
    val grantedSensitivePermissions: List<String>,
    val severity: AppSecuritySeverity,
    val reason: String,
    val isNewApplication: Boolean = false,
    val permissionsChanged: Boolean = false
)

enum class AppSecuritySeverity {
    LOW,
    MEDIUM,
    HIGH
}

class AppSecurityAnalyzer(
    private val context: Context
) {

    companion object {

        private const val TAG =
            "AppSecurityAnalyzer"

        private val SENSITIVE_PERMISSIONS =
            setOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_PHONE_STATE",
                "android.permission.CALL_PHONE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.BLUETOOTH_CONNECT",
                "android.permission.BLUETOOTH_SCAN"
            )
    }

    private val packageManager: PackageManager =
        context.packageManager

    private val profileStore =
        AppSecurityProfileStore(
            context.applicationContext
        )

    fun analyzeInstalledApplications(): List<AppSecurityFinding> {

        val applications: List<ApplicationInfo>

        try {

            applications =
                packageManager.getInstalledApplications(
                    PackageManager.GET_META_DATA
                )

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Unable to read installed applications",
                e
            )

            return emptyList()
        }

        val baselineInitialized =
            profileStore.isBaselineInitialized()

        Log.d(
            TAG,
            "=========================================="
        )

        Log.d(
            TAG,
            "Starting application security analysis"
        )

        Log.d(
            TAG,
            "Applications discovered: ${applications.size}"
        )

        Log.d(
            TAG,
            "Baseline initialized: $baselineInitialized"
        )

        Log.d(
            TAG,
            "=========================================="
        )

        val findings =
            mutableListOf<AppSecurityFinding>()

        val currentPackages =
            mutableSetOf<String>()

        for (application in applications) {

            val packageName =
                application.packageName

            currentPackages.add(packageName)

            val applicationName =
                try {

                    packageManager
                        .getApplicationLabel(application)
                        .toString()

                } catch (e: Exception) {

                    packageName
                }

            val applicationType =
                if (
                    application.flags and
                    ApplicationInfo.FLAG_SYSTEM != 0 ||
                    application.flags and
                    ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
                ) {
                    "SYSTEM"
                } else {
                    "USER"
                }

            val packageInfo: PackageInfo

            try {

                packageInfo =
                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.GET_PERMISSIONS
                    )

            } catch (e: Exception) {

                Log.e(
                    TAG,
                    "Unable to read package information: $packageName",
                    e
                )

                continue
            }

            val requestedPermissions =
                packageInfo
                    .requestedPermissions
                    ?.filter { permission ->
                        permission in SENSITIVE_PERMISSIONS
                    }
                    ?.sorted()
                    ?: emptyList()

            val grantedPermissions =
                getGrantedSensitivePermissions(
                    packageInfo
                )

            if (requestedPermissions.isNotEmpty()) {

                Log.d(
                    TAG,
                    "APPLICATION | " +
                            "name=$applicationName | " +
                            "package=$packageName | " +
                            "type=$applicationType | " +
                            "requested=${requestedPermissions.size} | " +
                            "granted=${grantedPermissions.size}"
                )

                Log.d(
                    TAG,
                    "REQUESTED | " +
                            "package=$packageName | " +
                            requestedPermissions.joinToString(",")
                )

                Log.d(
                    TAG,
                    "GRANTED | " +
                            "package=$packageName | " +
                            if (grantedPermissions.isEmpty()) {
                                "none"
                            } else {
                                grantedPermissions.joinToString(",")
                            }
                )
            }

            val currentProfile =
                buildSecurityProfile(
                    packageName = packageName,
                    applicationType = applicationType,
                    requestedPermissions = requestedPermissions,
                    grantedPermissions = grantedPermissions
                )

            val previousProfile =
                profileStore.getProfile(packageName)

            /*
             * First scan:
             * store the current state as the baseline.
             */
            if (!baselineInitialized) {

                profileStore.saveProfile(
                    packageName = packageName,
                    profile = currentProfile
                )

                continue
            }

            /*
             * New application.
             */
            if (previousProfile == null) {

                Log.d(
                    TAG,
                    "NEW APPLICATION SECURITY PROFILE | " +
                            "package=$packageName"
                )

                val finding =
                    createFinding(
                        applicationName = applicationName,
                        packageName = packageName,
                        applicationType = applicationType,
                        requestedPermissions = requestedPermissions,
                        grantedPermissions = grantedPermissions,
                        isNewApplication = true,
                        permissionsChanged = false
                    )

                if (finding != null) {
                    findings.add(finding)
                }

            }

            /*
             * Existing application whose security
             * profile has changed.
             */
            else if (previousProfile != currentProfile) {

                Log.d(
                    TAG,
                    "SECURITY PROFILE CHANGED | " +
                            "package=$packageName"
                )

                val finding =
                    createFinding(
                        applicationName = applicationName,
                        packageName = packageName,
                        applicationType = applicationType,
                        requestedPermissions = requestedPermissions,
                        grantedPermissions = grantedPermissions,
                        isNewApplication = false,
                        permissionsChanged = true
                    )

                if (finding != null) {
                    findings.add(finding)
                }
            }

            /*
             * Update the stored profile.
             */
            profileStore.saveProfile(
                packageName = packageName,
                profile = currentProfile
            )
        }

        /*
         * Detect applications that have been removed.
         */
        if (baselineInitialized) {

            val storedPackages =
                profileStore.getStoredPackages()

            val removedPackages =
                storedPackages - currentPackages

            for (packageName in removedPackages.sorted()) {

                Log.d(
                    TAG,
                    "APPLICATION REMOVED | " +
                            "package=$packageName"
                )

                findings.add(
                    AppSecurityFinding(
                        applicationName = packageName,
                        packageName = packageName,
                        applicationType = "UNKNOWN",
                        requestedSensitivePermissions =
                            emptyList(),
                        grantedSensitivePermissions =
                            emptyList(),
                        severity =
                            AppSecuritySeverity.MEDIUM,
                        reason =
                            "Application was removed from the device",
                        isNewApplication = false,
                        permissionsChanged = false
                    )
                )

                profileStore.removeProfile(
                    packageName
                )
            }
        }

        /*
         * Complete first baseline.
         */
        if (!baselineInitialized) {

            profileStore.markBaselineInitialized()

            Log.d(
                TAG,
                "=========================================="
            )

            Log.d(
                TAG,
                "INITIAL SECURITY BASELINE CREATED"
            )

            Log.d(
                TAG,
                "Applications stored: ${currentPackages.size}"
            )

            Log.d(
                TAG,
                "No security findings generated"
            )

            Log.d(
                TAG,
                "=========================================="
            )

            return emptyList()
        }

        Log.d(
            TAG,
            "=========================================="
        )

        Log.d(
            TAG,
            "Application security analysis completed"
        )

        Log.d(
            TAG,
            "Security findings: ${findings.size}"
        )

        Log.d(
            TAG,
            "=========================================="
        )

        for (finding in findings) {

            Log.d(
                TAG,
                "SECURITY FINDING | " +
                        "application=${finding.applicationName} | " +
                        "package=${finding.packageName} | " +
                        "type=${finding.applicationType} | " +
                        "severity=${finding.severity} | " +
                        "reason=${finding.reason}"
            )
        }

        return findings
    }

    /*
     * Compatibility method.
     */
    fun analyzeApplications(): List<AppSecurityFinding> {
        return analyzeInstalledApplications()
    }

    private fun getGrantedSensitivePermissions(
        packageInfo: PackageInfo
    ): List<String> {

        val requestedPermissions =
            packageInfo.requestedPermissions
                ?: return emptyList()

        val requestedPermissionFlags =
            packageInfo.requestedPermissionsFlags
                ?: return emptyList()

        val granted =
            mutableListOf<String>()

        for (index in requestedPermissions.indices) {

            val permission =
                requestedPermissions[index]

            if (permission !in SENSITIVE_PERMISSIONS) {
                continue
            }

            val flags =
                if (index < requestedPermissionFlags.size) {
                    requestedPermissionFlags[index]
                } else {
                    0
                }

            val isGranted =
                flags and
                        PackageInfo.REQUESTED_PERMISSION_GRANTED != 0

            if (isGranted) {
                granted.add(permission)
            }
        }

        return granted.sorted()
    }

    private fun buildSecurityProfile(
        packageName: String,
        applicationType: String,
        requestedPermissions: List<String>,
        grantedPermissions: List<String>
    ): String {

        return buildString {

            append("package=")
            append(packageName)

            append("|type=")
            append(applicationType)

            append("|requested=")
            append(
                requestedPermissions.joinToString(",")
            )

            append("|granted=")
            append(
                grantedPermissions.joinToString(",")
            )
        }
    }

    private fun createFinding(
        applicationName: String,
        packageName: String,
        applicationType: String,
        requestedPermissions: List<String>,
        grantedPermissions: List<String>,
        isNewApplication: Boolean,
        permissionsChanged: Boolean
    ): AppSecurityFinding? {

        /*
         * System applications are not classified as
         * suspicious simply because they have sensitive
         * permissions.
         */
        if (applicationType == "SYSTEM") {
            return null
        }

        /*
         * If no sensitive permission is actually granted,
         * there is nothing meaningful to report.
         */
        if (grantedPermissions.isEmpty()) {
            return null
        }

        val grantedCount =
            grantedPermissions.size

        val severity =
            when {

                grantedCount >= 4 ->
                    AppSecuritySeverity.HIGH

                grantedCount >= 2 ->
                    AppSecuritySeverity.MEDIUM

                else ->
                    AppSecuritySeverity.LOW
            }

        val reason =
            when {

                isNewApplication ->
                    "New user application has granted sensitive permissions"

                permissionsChanged ->
                    "User application security profile changed"

                else ->
                    "User application has granted sensitive permissions"
            }

        return AppSecurityFinding(
            applicationName =
                applicationName,

            packageName =
                packageName,

            applicationType =
                applicationType,

            requestedSensitivePermissions =
                requestedPermissions,

            grantedSensitivePermissions =
                grantedPermissions,

            severity =
                severity,

            reason =
                reason,

            isNewApplication =
                isNewApplication,

            permissionsChanged =
                permissionsChanged
        )
    }
}