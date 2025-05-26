package it.sebi.client

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import it.sebi.JsonParser
import it.sebi.models.*
import it.sebi.utils.calculateMD5Hash
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.io.File
import java.lang.System.getenv
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

object StrapiClientTokenCache {
    private val cache = mutableMapOf<String, Pair<StrapiLoginData, Long>>()

    fun getCacheForClient(clientHash: String): Pair<StrapiLoginData, Long>? {
        return cache[clientHash]
    }

    fun setCacheForClient(clientHash: String, token: StrapiLoginData, timestamp: Long) {
        cache[clientHash] = Pair(token, timestamp)
    }

    fun clearCacheForClient(clientHash: String) {
        cache.remove(clientHash)
    }

    fun clearAllCache() {
        cache.clear()
    }
}


fun StrapiInstance.client(): StrapiClient = StrapiClient(this)


private fun buildClient(proxyConfig: ProxyConfig?): HttpClient = HttpClient(CIO) {

    install(ContentNegotiation) {
        json(JsonParser)
    }
    install(Logging) {
        level = LogLevel.INFO
    }
    expectSuccess = true
    engine {
        proxy = proxyConfig
        https {
            trustManager = object : X509TrustManager {
                override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {
                }

                override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {
                }

                override fun getAcceptedIssuers(): Array<X509Certificate>? = null

            }
        }
    }
}

class ClientSelector {

    private val clientNoProxy = buildClient(null)
    private val clientHttpsProxy: HttpClient?
    private val clientHttpProxy: HttpClient?
    private val noProxyList: List<String>?

    init {
        val httpProxy = getenv("HTTP_PROXY")
        val httpsProxy = getenv("HTTPS_PROXY")
        noProxyList = getenv("NO_PROXY")?.let { noProxyString -> noProxyString.split(",").map { it.trim() } }
        clientHttpProxy = if (httpProxy != null) {
            buildClient(ProxyBuilder.http(httpProxy))
        } else {
            null
        }
        clientHttpsProxy = if (httpsProxy != null) {
            buildClient(ProxyBuilder.http(httpsProxy))
        } else {
            null
        }
    }

    fun getClientForUrl(url: String): HttpClient {
        val urlObj = try {
            java.net.URL(url)
        } catch (e: Exception) {
            return clientHttpsProxy ?: clientNoProxy
        }
        val proxy by lazy { if (urlObj.protocol == "https") clientHttpsProxy else clientHttpProxy }

        return if (noProxyList?.any { urlObj.host.contains(it) } == true) {
            clientNoProxy
        } else {
            proxy ?: clientNoProxy
        }
    }

}


class StrapiClient(
    val name: String,
    private val baseUrl: String,
    private val apiKey: String,
    private val username: String,
    private val password: String
) {
    constructor(strapiInstance: StrapiInstance) : this(
        strapiInstance.name,
        strapiInstance.url,
        strapiInstance.apiKey,
        strapiInstance.username,
        strapiInstance.password
    )

    val clientHash = calculateMD5Hash(baseUrl + apiKey + username + password)

    val selector = ClientSelector()


    suspend fun getLoginToken(): StrapiLoginData {
        val now = System.currentTimeMillis()
        val cacheTimeout = 20 * 60 * 1000 // 20 minutes in milliseconds

        StrapiClientTokenCache.getCacheForClient(clientHash)?.let { (token, timestamp) ->
            if (now - timestamp < cacheTimeout) {
                return token
            }
        }

        val url = "$baseUrl/admin/login"
        val response = selector.getClientForUrl(url).post(url) {

            setBody(buildJsonObject {
                put("email", username)
                put("password", password)
            })
            headers {
                append(HttpHeaders.ContentType, "application/json")
            }
        }.body<StrapiLoginResponse>()
        StrapiClientTokenCache.setCacheForClient(clientHash, response.data, now)
        return response.data
    }

    suspend fun getContentTypes(): List<StrapiContentType> {
        val url = "$baseUrl/api/content-type-builder/content-types"
        val response: ContentTypeResponse = selector.getClientForUrl(url).get(url) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $apiKey")
            }
        }.body()

        return response.data
    }

    suspend fun getComponentSchema(): List<StrapiComponent> {
        val url = "$baseUrl/api/content-type-builder/content-types/components"
        val response: ComponentResponse = selector.getClientForUrl(url).get(url) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $apiKey")
            }
        }.body()

        return response.data
    }

    /**
     * Get files from the upload API
     */
    suspend fun getFiles(): List<StrapiImage> {
        val token = getLoginToken().token
        val allResults = mutableListOf<StrapiImage>()
        var currentPage = 1

        do {
            val url = "$baseUrl/upload/files"
            val response: JsonObject = selector.getClientForUrl(url).get("$baseUrl/upload/files") {
                headers {
                    append(HttpHeaders.Authorization, "Bearer $token")
                }
                parameter("sort", "createdAt:DESC")
                parameter("page", currentPage)
                parameter("pageSize", 50)
            }.body()

            val strapiImages = response["results"]?.jsonArray?.map { imageRaw ->
                val strapiImageMetadata: StrapiImageMetadata = JsonParser.decodeFromJsonElement(imageRaw)
                StrapiImage(strapiImageMetadata, imageRaw.jsonObject)

            }
            val pageCount =
                response["pagination"]?.jsonObject?.let { pagination -> pagination["pageCount"]?.jsonPrimitive?.int }
                    ?: 0


            strapiImages?.let { allResults.addAll(it) }
            currentPage++
        } while (currentPage <= pageCount)

        return allResults.toList()
    }

    suspend fun getFolders(): List<StrapiFolder> {

        val token = getLoginToken().token
        val url = "$baseUrl/upload/folders"
        val response: FolderResponse = selector.getClientForUrl(url).get(url) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $token")
            }
        }.body()
        val folders = response.data
        val folderByPathId = folders.associateBy { it.pathId }


        val folderFix = folders.map { folder ->
            val parts = folder.path.split("/").filter { it.isNotEmpty() }
            val mapped = parts.mapNotNull { pathElement ->
                val pathId = pathElement.toInt()
                if (pathId == folder.pathId) null
                else
                    folderByPathId[pathId]?.name
            }
            val fullPath = if (mapped.isEmpty())
                "/" + folder.name
            else {
                val prefix = mapped.joinToString("/", prefix = "/", postfix = "/")
                prefix + folder.name
            }
            folder.copy(pathFull = fullPath)
        }

        return folderFix

    }

    /**
     * Create a folder in Strapi
     * @param name The name of the folder
     * @param parent The parent of the folder
     * @return The created folder
     */
    suspend fun createFolder(name: String, parent: Int?): StrapiFolder {
        val token = getLoginToken().token
        val url = "$baseUrl/upload/folders"
        val response = selector.getClientForUrl(url).post(url) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $token")
                append(HttpHeaders.ContentType, "application/json")
            }
            setBody(
                JsonObject(
                    mapOf(
                        "name" to JsonPrimitive(name),
                        "parent" to (parent?.let { JsonPrimitive(parent) } ?: JsonNull)
                    )
                )
            )
        }.body<JsonObject>()

        // Extract the folder data from the response
        val folderData = response["data"]?.jsonObject ?: throw IllegalStateException("Failed to create folder")
        return StrapiFolder(
            id = folderData["id"]?.jsonPrimitive?.int ?: 0,
            documentId = folderData["documentId"]?.jsonPrimitive?.content ?: "",
            name = folderData["name"]?.jsonPrimitive?.content ?: "",
            pathId = folderData["pathId"]?.jsonPrimitive?.int ?: 0,
            path = folderData["path"]?.jsonPrimitive?.content ?: ""
        )
    }

    suspend fun downloadFile(strapiImage: StrapiImage): File {

        val file = withContext(Dispatchers.IO) {
            File.createTempFile(strapiImage.metadata.name, strapiImage.metadata.ext)
        }
        val url = strapiImage.metadata.url

        val response = if (url.startsWith("http"))
            selector.getClientForUrl(url).get(url)
        else selector.getClientForUrl(strapiImage.downloadUrl(baseUrl)).get(strapiImage.downloadUrl(baseUrl)) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $apiKey")
            }
        }

        file.writeBytes(response.bodyAsBytes())

        return file

    }

    suspend fun uploadFile(
        id: Int?,
        fileName: String,
        file: File,
        mimeType: String,
        caption: String? = null,
        alternativeText: String? = null,
        folder: Int? = null
    ): StrapiFileUploadResponse {
        // Crea il client HTTP
        val token = getLoginToken().token

        val fileInfo = buildJsonObject {
            put("name", fileName)
            caption?.let { put("caption", it) }
            alternativeText?.let { put("alternativeText", it) }
            folder?.let { put("folder", it) }
        }.toString()
        val url = "$baseUrl/upload" + (id?.let { "?id=$it" } ?: "")

        // Esegui la richiesta
        val response = selector.getClientForUrl(url).submitFormWithBinaryData(
            url = url,
            formData = formData {
                append("files", file.readBytes(), Headers.build {
                    append(HttpHeaders.ContentType, mimeType)
                    append(HttpHeaders.ContentDisposition, "form-data; name=\"files\"; filename=\"$fileName\"")
                })
                append("fileInfo", fileInfo)
            }
        ) {
            headers {
                append(
                    HttpHeaders.Authorization,
                    "Bearer $token"
                )
            }
        }

        // Gestisci la risposta qui
        val responseBody = response.body<JsonElement>()
        val uploadedFile = when (responseBody) {
            is JsonArray -> responseBody.jsonArray[0].jsonObject
            is JsonObject -> responseBody.jsonObject
            else -> throw IllegalStateException("Unexpected response body type: ${responseBody::class.simpleName}")
        }

        val targetDocumentId = uploadedFile["documentId"]?.jsonPrimitive?.content!!
        val targetId = uploadedFile["id"]?.jsonPrimitive?.content?.toInt()!!


        return StrapiFileUploadResponse(targetId, targetDocumentId)
    }


    /**
     * Delete a file
     */
    suspend fun deleteFile(fileId: String): JsonObject {
        return try {
            val url = "$baseUrl/api/upload/files/$fileId"
            selector.getClientForUrl(url).delete(url) {
                headers {
                    append(HttpHeaders.Authorization, "Bearer $apiKey")
                }
            }.body()
        } catch (e: io.ktor.client.plugins.ClientRequestException) {
            if (e.response.status == HttpStatusCode.NotFound) {
                JsonObject(emptyMap())
            } else {
                throw e
            }
        }
    }


    suspend fun getContentEntries(
        contentType: StrapiContentType,
        mappings: List<MergeRequestDocumentMapping>?
    ): List<EntryElement> {
        val url = "$baseUrl/api/${contentType.schema.queryName}"
        val response: JsonObject = try {
            selector.getClientForUrl(url).get(url) {
                headers {
                    append(HttpHeaders.Authorization, "Bearer $apiKey")
                }
                url {
                    contentType.schema.attributes.forEach { (key, attribute) ->
                        when (attribute.type) {
                            "component", "dynamiczone", "media", "relation" -> {
                                println("[DEBUG_LOG] Adding parameter for $key")
                                parameters.append("populate[$key][populate]", "*")
                            }
                        }
                    }
                }
            }.body()
        } catch (e: io.ktor.client.plugins.ClientRequestException) {
            if (e.response.status == HttpStatusCode.NotFound) {
                return emptyList()
            }
            throw e
        }


        val dataElement = response["data"]

        val entries = when {
            dataElement == null -> emptyList()
            dataElement is JsonNull -> emptyList()
            contentType.schema.kind == StrapiContentTypeKind.SingleType && dataElement is JsonObject -> listOf(
                dataElement
            )

            contentType.schema.kind == StrapiContentTypeKind.CollectionType && dataElement is JsonArray -> dataElement.map { it.jsonObject }
            contentType.schema.kind == StrapiContentTypeKind.CollectionType && dataElement !is JsonArray ->
                if (dataElement is JsonObject) listOf(dataElement) else dataElement.jsonArray.map { it.jsonObject }

            else -> if (dataElement is JsonObject) listOf(dataElement) else dataElement.jsonArray.map { it.jsonObject }
        }

        return entries.map { entry ->
            val id = entry["id"]!!.jsonPrimitive.content.toInt()
            val documentId = entry["documentId"]!!.jsonPrimitive.content
            val mappedEntry = mappings?.let { mappings ->
                var base = entry.toString()
                mappings.forEach { mapping ->
                    if (mapping.targetDocumentId != null && mapping.sourceDocumentId != null)
                        base = base.replace(mapping.targetDocumentId, mapping.sourceDocumentId)
                }
                JsonParser.decodeFromString<JsonObject>(base)
            } ?: entry
            val cleanupStrapiJson = cleanupStrapiJson(mappedEntry)
            val content = StrapiContent(StrapiContentMetadata(id, documentId), entry, cleanupStrapiJson.jsonObject)



            EntryElement(content, cleanupStrapiJson.jsonObject.generateHash())
        }
    }


    suspend fun createContentEntry(contentType: String, data: JsonObject, kind: StrapiContentTypeKind): JsonObject {
        val url = "$baseUrl/api/$contentType"

        println("[DEBUG_LOG] Creating content entry for $contentType with kind $kind")
        println("[DEBUG_LOG] Data: $data")

        val response = selector.getClientForUrl(url).request(url) {
            method = if (kind == StrapiContentTypeKind.SingleType) HttpMethod.Put else HttpMethod.Post
            headers {
                append(HttpHeaders.Authorization, "Bearer $apiKey")
                contentType(io.ktor.http.ContentType.Application.Json)
            }
            setBody(buildJsonObject {
                put("data", data)
            })
        }.body<JsonObject>()

        println("[DEBUG_LOG] Response: $response")
        return response
    }

    suspend fun updateContentEntry(
        contentType: String,
        id: String,
        data: JsonObject,
        kind: StrapiContentTypeKind
    ): JsonObject {
        val url = if (kind == StrapiContentTypeKind.SingleType) {
            "$baseUrl/api/$contentType"
        } else {
            "$baseUrl/api/$contentType/$id"
        }

        println("[DEBUG_LOG] Updating content entry for $contentType with kind $kind")
        println("[DEBUG_LOG] URL: $url")
        println("[DEBUG_LOG] Data: $data")


        return selector.getClientForUrl(url).put(url) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $apiKey")
                contentType(io.ktor.http.ContentType.Application.Json)
            }
            setBody(buildJsonObject {
                put("data", data)
            })
        }.body()
    }

    suspend fun deleteContentEntry(contentType: String, id: String, kind: String = "collectionType"): JsonObject {
        val url = if (kind == "singleType") {
            "$baseUrl/api/$contentType"
        } else {
            "$baseUrl/api/$contentType/$id"
        }

        return selector.getClientForUrl(url).delete(url) {
            headers {
                append(HttpHeaders.Authorization, "Bearer $apiKey")
            }
        }.body()
    }


    fun cleanupStrapiJson(element: JsonElement): JsonElement {
        // Lista dei campi tecnici da rimuovere
        val technicalFields = setOf(
            "id",
            "url",
            "formats",
            "related",
            "createdAt",
            "updatedAt",
            "publishedAt",
            "provider",
            "provider_metadata",
            "hash",
            "ext",
            "mime",
            "size",
            "previewUrl",
            "path",
            "sizeInBytes",
            "__component"
        )

        return when (element) {

            is JsonObject -> {
                JsonObject(
                    element.entries
                        .filter { (key, value) -> key !in technicalFields && value !is JsonNull && (value !is JsonObject || value.isNotEmpty()) }
                        .associate { (key, value) -> key to cleanupStrapiJson(value) }
                )
            }

            is JsonArray -> {
                JsonArray(element.map { cleanupStrapiJson(it) }.sortedBy { it.toString() })
            }

            else -> element
        }
    }


    private fun JsonObject.generateHash(fieldsToIgnore: List<String> = listOf()): String {
        fun filterRecursively(element: JsonElement): JsonElement = when (element) {
            is JsonObject -> JsonObject(element.filterKeys { it !in fieldsToIgnore }
                .mapValues { (_, v) -> filterRecursively(v) })

            is JsonArray -> JsonArray(element.map { filterRecursively(it) })
            else -> element
        }

        val filteredObject = filterRecursively(this) as JsonObject
        val jsonString = filteredObject.toString()
        val bytes = MessageDigest.getInstance("SHA-256").digest(jsonString.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }

    }
}
