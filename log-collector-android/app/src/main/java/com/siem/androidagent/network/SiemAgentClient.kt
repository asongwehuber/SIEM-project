package com.siem.androidagent.network

import android.util.Log

import com.siem.androidagent.BuildConfig
import com.siem.androidagent.collector.AndroidLogEvent

import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.json.JSONObject


class SiemAgentClient {

    fun sendEvent(
        ipAddress: String,
        port: String,
        event: AndroidLogEvent
    ): String {

        val signature =
            generateHmacSignature(
                timestamp = event.timestamp,
                eventId = event.eventId,
                generatorId = event.generatorId,
                hostname = event.hostname,
                message = event.message
            )


        val json =
            JSONObject().apply {

                put(
                    "timestamp",
                    event.timestamp
                )

                put(
                    "event_id",
                    event.eventId
                )

                put(
                    "generator_id",
                    event.generatorId
                )

                put(
                    "hostname",
                    event.hostname
                )

                put(
                    "message",
                    event.message
                )

                put(
                    "signature",
                    signature
                )
            }


        /*
         * Useful during testing:
         * this prints the exact outer JSON being sent.
         */
        Log.d(
            "SiemAgentClient",
            "Sending JSON: ${json.toString()}"
        )


        val url =
            URL(
                "http://$ipAddress:$port/receive-log"
            )


        val connection =
            url.openConnection()
                    as HttpURLConnection


        try {

            connection.requestMethod =
                "POST"

            connection.connectTimeout =
                5000

            connection.readTimeout =
                10000

            connection.doOutput =
                true


            connection.setRequestProperty(
                "Content-Type",
                "application/json"
            )


            connection.outputStream.use { output ->

                output.write(
                    json.toString()
                        .toByteArray(
                            StandardCharsets.UTF_8
                        )
                )
            }


            val responseCode =
                connection.responseCode


            val responseBody =

                try {

                    connection.inputStream
                        .bufferedReader()
                        .use {
                            it.readText()
                        }

                } catch (e: Exception) {

                    connection.errorStream
                        ?.bufferedReader()
                        ?.use {
                            it.readText()
                        }
                        ?: ""
                }


            return "HTTP $responseCode: $responseBody"


        } finally {

            connection.disconnect()
        }
    }


    private fun generateHmacSignature(
        timestamp: String,
        eventId: String,
        generatorId: String,
        hostname: String,
        message: String
    ): String {

        /*
         * MUST remain identical to the SIEM Agent verifier.
         */
        val data =
            "$timestamp|$eventId|$generatorId|$hostname|$message"


        val secretKey =
            BuildConfig.SIEM_SECRET_KEY


        val secretKeySpec =
            SecretKeySpec(
                secretKey.toByteArray(
                    StandardCharsets.UTF_8
                ),
                "HmacSHA256"
            )


        val mac =
            Mac.getInstance(
                "HmacSHA256"
            )


        mac.init(
            secretKeySpec
        )


        val hash =
            mac.doFinal(
                data.toByteArray(
                    StandardCharsets.UTF_8
                )
            )


        return hash.joinToString("") {

            "%02x".format(it)
        }
    }
}