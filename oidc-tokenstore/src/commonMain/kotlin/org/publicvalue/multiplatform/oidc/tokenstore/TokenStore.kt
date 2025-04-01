package org.publicvalue.multiplatform.oidc.tokenstore

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.datetime.Clock
import org.publicvalue.multiplatform.oidc.ExperimentalOpenIdConnect
import org.publicvalue.multiplatform.oidc.types.remote.AccessTokenResponse
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Concurrency-safe Token Store implementations.
 *
 * Android Implementation: [org.publicvalue.multiplatform.oidc.tokenstore.AndroidSettingsTokenStore]
 * iOS implementation: [KeychainTokenStore]
 */
@ExperimentalOpenIdConnect
@OptIn(ExperimentalObjCName::class)
@ObjCName("TokenStoreProtocol", "TokenStoreProtocol", exact = true)
// not an interface to support extension methods in swift
abstract class TokenStore {
    abstract suspend fun getAccessToken(): String?
    abstract suspend fun getRefreshToken(): String?
    abstract suspend fun getIdToken(): String?
    abstract suspend fun getExpiresIn(): Int?
    abstract suspend fun getRefreshTokenExpiresIn(): Int?
    abstract suspend fun getReceivedAt(): Long?

    abstract val accessTokenFlow: Flow<String?>
    abstract val refreshTokenFlow: Flow<String?>
    abstract val idTokenFlow: Flow<String?>
    abstract val expiresInFlow: Flow<Int?>
    abstract val refreshTokenExpiresInFlow: Flow<Int?>
    abstract val receivedAtFlow: Flow<Long?>

    abstract suspend fun removeAccessToken()
    abstract suspend fun removeRefreshToken()
    abstract suspend fun removeIdToken()
    abstract suspend fun removeExpiresIn()
    abstract suspend fun removeRefreshTokenExpiresIn()
    abstract suspend fun removeReceivedAt()

    abstract suspend fun saveTokens(
        accessToken: String, 
        refreshToken: String?, 
        idToken: String?,
        expiresIn: Int?,
        refreshTokenExpiresIn: Int?,
        receivedAt: Long
    )
}

// extension method so no need to overwrite in swift subclasses
@ExperimentalOpenIdConnect
suspend fun TokenStore.saveTokens(tokens: AccessTokenResponse) {
    saveTokens(
        accessToken = tokens.access_token,
        refreshToken = tokens.refresh_token,
        idToken = tokens.id_token,
        expiresIn = tokens.expires_in,
        refreshTokenExpiresIn = tokens.refresh_token_expires_in,
        receivedAt = tokens.received_at
    )
}

// extension method so no need to overwrite in swift subclasses
@ExperimentalOpenIdConnect
suspend fun TokenStore.removeTokens() {
    removeAccessToken()
    removeIdToken()
    removeRefreshToken()
    removeExpiresIn()
    removeRefreshTokenExpiresIn()
    removeReceivedAt()
}

// extension method so no need to overwrite in swift subclasses
@ExperimentalOpenIdConnect
suspend fun TokenStore.getTokens(): OauthTokens? {
    val accessToken = getAccessToken()
    val refreshToken = getRefreshToken()
    val idToken = getIdToken()
    val expiresIn = getExpiresIn()
    val refreshTokenExpiresIn = getRefreshTokenExpiresIn()
    val receivedAt = getReceivedAt() ?: Clock.System.now().epochSeconds

    return if (accessToken != null) {
        OauthTokens(
            accessToken = accessToken,
            refreshToken = refreshToken,
            idToken = idToken,
            expiresIn = expiresIn,
            refreshTokenExpiresIn = refreshTokenExpiresIn,
            receivedAt = receivedAt
        )
    } else {
        null
    }
}

@ExperimentalOpenIdConnect
val TokenStore.tokensFlow: Flow<OauthTokens?>
    get() = combine(
        accessTokenFlow, 
        refreshTokenFlow, 
        idTokenFlow,
        expiresInFlow,
        refreshTokenExpiresInFlow,
        receivedAtFlow
    ) { values ->
        val accessToken = values[0] as String?
        val refreshToken = values[1] as String?
        val idToken = values[2] as String?
        val expiresIn = values[3] as Int?
        val refreshTokenExpiresIn = values[4] as Int?
        val receivedAt = values[5] as Long?
        
        if (accessToken != null) {
            OauthTokens(
                accessToken = accessToken,
                refreshToken = refreshToken,
                idToken = idToken,
                expiresIn = expiresIn,
                refreshTokenExpiresIn = refreshTokenExpiresIn,
                receivedAt = receivedAt ?: Clock.System.now().epochSeconds
            )
        } else {
            null
        }
    }