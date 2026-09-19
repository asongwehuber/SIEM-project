package com.siem.androidagent.collector

data class PermissionRuleMatch(
    val ruleId: String,
    val severity: AppSecuritySeverity,
    val reason: String,
    val matchedPermissions: List<String>
)

class PermissionRuleEngine {

    companion object {

        private val RULES = listOf(

            PermissionRule(
                id = "PERM-R01",
                requiredPermissions = setOf(
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS"
                ),
                severity = AppSecuritySeverity.HIGH,
                reason =
                    "Application can read and send SMS messages"
            ),

            PermissionRule(
                id = "PERM-R02",
                requiredPermissions = setOf(
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS"
                ),
                severity = AppSecuritySeverity.HIGH,
                reason =
                    "Application can receive and read SMS messages"
            ),

            PermissionRule(
                id = "PERM-R03",
                requiredPermissions = setOf(
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION"
                ),
                severity = AppSecuritySeverity.HIGH,
                reason =
                    "Application combines microphone access with precise location access"
            ),

            PermissionRule(
                id = "PERM-R04",
                requiredPermissions = setOf(
                    "android.permission.CAMERA",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION"
                ),
                severity = AppSecuritySeverity.HIGH,
                reason =
                    "Application combines camera, microphone and precise location access"
            ),

            PermissionRule(
                id = "PERM-R05",
                requiredPermissions = setOf(
                    "android.permission.READ_CONTACTS",
                    "android.permission.READ_CALL_LOG"
                ),
                severity = AppSecuritySeverity.MEDIUM,
                reason =
                    "Application combines contact and call-history access"
            ),

            PermissionRule(
                id = "PERM-R06",
                requiredPermissions = setOf(
                    "android.permission.READ_SMS",
                    "android.permission.READ_CONTACTS",
                    "android.permission.ACCESS_FINE_LOCATION"
                ),
                severity = AppSecuritySeverity.HIGH,
                reason =
                    "Application combines SMS, contact and precise-location access"
            ),

            PermissionRule(
                id = "PERM-R07",
                requiredPermissions = setOf(
                    "android.permission.CALL_PHONE",
                    "android.permission.READ_CALL_LOG"
                ),
                severity = AppSecuritySeverity.MEDIUM,
                reason =
                    "Application can make calls and access call history"
            )
        )
    }

    fun evaluate(
        grantedPermissions: List<String>
    ): List<PermissionRuleMatch> {

        val granted =
            grantedPermissions.toSet()

        return RULES
            .filter { rule ->
                granted.containsAll(
                    rule.requiredPermissions
                )
            }
            .map { rule ->

                PermissionRuleMatch(
                    ruleId = rule.id,
                    severity = rule.severity,
                    reason = rule.reason,
                    matchedPermissions =
                        rule.requiredPermissions
                            .sorted()
                )
            }
    }
}

private data class PermissionRule(
    val id: String,
    val requiredPermissions: Set<String>,
    val severity: AppSecuritySeverity,
    val reason: String
)