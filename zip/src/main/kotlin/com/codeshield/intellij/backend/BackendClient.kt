package com.codeshield.intellij.backend

import com.google.gson.Gson
import com.google.gson.JsonParser
import com.intellij.openapi.vfs.VirtualFile
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

data class Finding(
    val ruleId: String,
    val title: String,
    val severity: String,
    val message: String,
    val line: Int,
    val column: Int,
    val file: VirtualFile? = null,
) {
    override fun toString(): String = "[$severity] $ruleId · line $line · $title — $message"
}

class BackendClient(baseUrl: String) {
    private val base = validateLoopbackBase(baseUrl)
    private val client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()
    private val gson = Gson()

    fun scan(language: String, filename: String, source: String): List<Finding> {
        val payload = mapOf("language" to language, "filename" to filename, "code" to source)
        val request = HttpRequest.newBuilder(URI.create("$base/scan"))
            .timeout(Duration.ofSeconds(45))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(payload)))
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            throw IllegalStateException("Backend returned HTTP ${response.statusCode()}: ${response.body().take(300)}")
        }

        val root = JsonParser.parseString(response.body()).asJsonObject
        val entries = root.getAsJsonArray("findings") ?: return emptyList()
        return entries.mapNotNull { entry ->
            if (!entry.isJsonObject) return@mapNotNull null
            val json = entry.asJsonObject
            Finding(
                ruleId = json.stringOr("rule_id", "UNKNOWN"),
                title = json.stringOr("title", "Security finding"),
                severity = json.stringOr("severity", "info").uppercase(),
                message = json.stringOr("message", "Review this finding."),
                line = json.intOr("line", 1),
                column = json.intOr("column", 0) + 1,
            )
        }
    }

    companion object {
        fun validateLoopbackBase(value: String): String {
            val uri = try {
                URI(value.trim().trimEnd('/'))
            } catch (_: Exception) {
                throw IllegalArgumentException("Enter a valid loopback URL such as http://127.0.0.1:8000")
            }
            val host = uri.host?.lowercase()
            if (uri.scheme != "http" || host !in setOf("localhost", "127.0.0.1", "::1") || uri.userInfo != null || uri.query != null || uri.fragment != null) {
                throw IllegalArgumentException("For safety, the backend URL must use HTTP on localhost or 127.0.0.1, without credentials or query parameters.")
            }
            return uri.toString().trimEnd('/')
        }

        private fun com.google.gson.JsonObject.stringOr(name: String, fallback: String): String =
            get(name)?.takeUnless { it.isJsonNull }?.asString ?: fallback

        private fun com.google.gson.JsonObject.intOr(name: String, fallback: Int): Int =
            get(name)?.takeUnless { it.isJsonNull }?.asInt ?: fallback
    }
}
