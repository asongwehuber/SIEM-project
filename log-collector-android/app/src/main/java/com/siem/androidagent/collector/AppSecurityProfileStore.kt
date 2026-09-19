package com.siem.androidagent.collector

import android.content.Context
import android.content.SharedPreferences

/**
 * Stores the security profile of installed applications.
 *
 * The store maintains a baseline of each application's
 * security-relevant information. The analyzer uses this
 * information to detect new applications and changes
 * to existing applications.
 */
class AppSecurityProfileStore(
    context: Context
) {

    companion object {

        private const val PREFS_NAME =
            "android_siem_security_profiles_v1"

        private const val KEY_BASELINE_INITIALIZED =
            "baseline_initialized"

        private const val KEY_PROFILE_PREFIX =
            "profile_"
    }

    private val preferences: SharedPreferences =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    /**
     * Checks whether the initial security baseline
     * has already been created.
     */
    fun isBaselineInitialized(): Boolean {
        return preferences.getBoolean(
            KEY_BASELINE_INITIALIZED,
            false
        )
    }

    /**
     * Marks the initial security baseline as created.
     */
    fun markBaselineInitialized() {
        preferences
            .edit()
            .putBoolean(
                KEY_BASELINE_INITIALIZED,
                true
            )
            .apply()
    }

    /**
     * Returns the stored security profile for an
     * application package.
     *
     * Returns null when no profile exists.
     */
    fun getProfile(
        packageName: String
    ): String? {

        return preferences.getString(
            profileKey(packageName),
            null
        )
    }

    /**
     * Saves the current security profile of an
     * application.
     */
    fun saveProfile(
        packageName: String,
        profile: String
    ) {

        preferences
            .edit()
            .putString(
                profileKey(packageName),
                profile
            )
            .apply()
    }

    /**
     * Removes the stored security profile of an
     * application.
     *
     * This is called when an application is
     * uninstalled from the device.
     */
    fun removeProfile(
        packageName: String
    ) {

        preferences
            .edit()
            .remove(
                profileKey(packageName)
            )
            .apply()
    }

    /**
     * Returns all application package names
     * currently stored in the security baseline.
     */
    fun getStoredPackages(): Set<String> {

        return preferences
            .all
            .keys
            .filter { key ->
                key.startsWith(
                    KEY_PROFILE_PREFIX
                )
            }
            .map { key ->
                key.removePrefix(
                    KEY_PROFILE_PREFIX
                )
            }
            .toSet()
    }

    /**
     * Creates the SharedPreferences key used
     * to store an application's profile.
     */
    private fun profileKey(
        packageName: String
    ): String {

        return KEY_PROFILE_PREFIX + packageName
    }
}