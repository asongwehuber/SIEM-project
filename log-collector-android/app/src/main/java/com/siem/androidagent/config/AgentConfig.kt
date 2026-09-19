package com.siem.androidagent.config

data class AgentConfig(
    val ipAddress: String = "192.168.1.171",
    val port: String = "6000",
    val collectorId: String = "android-phone-01"
)