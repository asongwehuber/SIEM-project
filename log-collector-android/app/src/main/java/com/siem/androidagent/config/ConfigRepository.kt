package com.siem.androidagent.config

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(
    name = "siem_agent_config"
)

class ConfigRepository(
    private val context: Context
) {

    private object Keys {

        val IP_ADDRESS =
            stringPreferencesKey("ip_address")

        val PORT =
            stringPreferencesKey("port")

        val COLLECTOR_ID =
            stringPreferencesKey("collector_id")
    }

    val config: Flow<AgentConfig> =
        context.dataStore.data.map { preferences ->

            AgentConfig(
                ipAddress =
                    preferences[Keys.IP_ADDRESS]
                        ?: "192.168.1.171",

                port =
                    preferences[Keys.PORT]
                        ?: "6000",

                collectorId =
                    preferences[Keys.COLLECTOR_ID]
                        ?: "android-phone-01"
            )
        }

    suspend fun saveConfig(config: AgentConfig) {

        context.dataStore.edit { preferences ->

            preferences[Keys.IP_ADDRESS] =
                config.ipAddress

            preferences[Keys.PORT] =
                config.port

            preferences[Keys.COLLECTOR_ID] =
                config.collectorId
        }
    }
}