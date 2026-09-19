package com.siem.androidagent.collector

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.util.Log


data class AppInventoryEvent(
    val type: AppInventoryEventType,
    val packageName: String
)


enum class AppInventoryEventType {
    INSTALLED,
    UNINSTALLED
}


class AppInventoryCollector(
    private val context: Context
) {

    companion object {

        private const val TAG =
            "AppInventoryCollector"

        /*
         * Version 2 is intentional.
         *
         * We do not reuse the previous inventory because
         * the package visibility configuration changed during
         * development and could contain an incomplete baseline.
         */
        private const val PREFS_NAME =
            "android_siem_app_inventory_v2"

        private const val KEY_PACKAGES =
            "known_packages"

        /*
         * IMPORTANT:
         *
         * Do not use an empty package set to determine whether
         * a baseline exists.
         *
         * A separate flag tells us whether the first scan
         * has already been completed.
         */
        private const val KEY_BASELINE_INITIALIZED =
            "baseline_initialized"
    }


    /**
     * Scans the currently installed applications and compares
     * them with the previous inventory.
     *
     * FIRST SCAN:
     *     Creates a baseline silently.
     *     No events are generated.
     *
     * SUBSEQUENT SCANS:
     *     New package -> INSTALLED
     *     Missing package -> UNINSTALLED
     */
    fun detectApplicationChanges(): List<AppInventoryEvent> {

        val packageManager =
            context.packageManager


        val currentPackages: Set<String>

        try {

            currentPackages =
                packageManager
                    .getInstalledApplications(
                        PackageManager.GET_META_DATA
                    )
                    .map { applicationInfo ->
                        applicationInfo.packageName
                    }
                    .toSet()

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Unable to read installed applications",
                e
            )

            return emptyList()
        }


        val preferences =
            context.getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            )


        val baselineInitialized =
            preferences.getBoolean(
                KEY_BASELINE_INITIALIZED,
                false
            )


        /*
         * =====================================================
         * FIRST SCAN
         * =====================================================
         *
         * We simply store the current application inventory.
         *
         * Nothing is sent to the SIEM.
         */
        if (!baselineInitialized) {

            saveCurrentInventory(
                preferences = preferences,
                packages = currentPackages
            )

            Log.d(
                TAG,
                "=========================================="
            )

            Log.d(
                TAG,
                "Initial application inventory created"
            )

            Log.d(
                TAG,
                "Applications in baseline: ${currentPackages.size}"
            )

            Log.d(
                TAG,
                "No application events generated"
            )

            Log.d(
                TAG,
                "=========================================="
            )

            return emptyList()
        }


        /*
         * =====================================================
         * LOAD PREVIOUS INVENTORY
         * =====================================================
         */
        val previousPackages =
            preferences
                .getStringSet(
                    KEY_PACKAGES,
                    emptySet()
                )
                ?.toSet()
                ?: emptySet()


        /*
         * =====================================================
         * DETECT NEW APPLICATIONS
         * =====================================================
         */
        val installedPackages =
            currentPackages - previousPackages


        /*
         * =====================================================
         * DETECT REMOVED APPLICATIONS
         * =====================================================
         */
        val removedPackages =
            previousPackages - currentPackages


        val events =
            mutableListOf<AppInventoryEvent>()


        /*
         * Sort the results so that testing and log analysis
         * remain predictable.
         */
        for (packageName in installedPackages.sorted()) {

            Log.d(
                TAG,
                "NEW APPLICATION DETECTED: $packageName"
            )

            events.add(
                AppInventoryEvent(
                    type =
                        AppInventoryEventType.INSTALLED,

                    packageName =
                        packageName
                )
            )
        }


        for (packageName in removedPackages.sorted()) {

            Log.d(
                TAG,
                "APPLICATION REMOVED: $packageName"
            )

            events.add(
                AppInventoryEvent(
                    type =
                        AppInventoryEventType.UNINSTALLED,

                    packageName =
                        packageName
                )
            )
        }


        /*
         * =====================================================
         * UPDATE BASELINE
         * =====================================================
         *
         * The current package list becomes the new baseline.
         */
        saveCurrentInventory(
            preferences = preferences,
            packages = currentPackages
        )


        Log.d(
            TAG,
            "Application scan completed"
        )

        Log.d(
            TAG,
            "Previous applications: ${previousPackages.size}"
        )

        Log.d(
            TAG,
            "Current applications: ${currentPackages.size}"
        )

        Log.d(
            TAG,
            "New applications: ${installedPackages.size}"
        )

        Log.d(
            TAG,
            "Removed applications: ${removedPackages.size}"
        )

        Log.d(
            TAG,
            "Total changes: ${events.size}"
        )


        return events
    }


    /**
     * Saves the current application inventory and marks
     * the baseline as initialized.
     */
    private fun saveCurrentInventory(
        preferences: SharedPreferences,
        packages: Set<String>
    ) {

        preferences
            .edit()
            .putStringSet(
                KEY_PACKAGES,
                packages
            )
            .putBoolean(
                KEY_BASELINE_INITIALIZED,
                true
            )
            .apply()
    }
}

