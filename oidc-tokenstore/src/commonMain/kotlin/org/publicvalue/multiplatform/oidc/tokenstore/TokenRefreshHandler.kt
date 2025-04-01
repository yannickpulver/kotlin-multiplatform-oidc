package org.publicvalue.multiplatform.oidc.tokenstore

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.publicvalue.multiplatform.oidc.ExperimentalOpenIdConnect
import org.publicvalue.multiplatform.oidc.OpenIdConnectClient
import org.publicvalue.multiplatform.oidc.OpenIdConnectException
import org.publicvalue.multiplatform.oidc.types.remote.AccessTokenResponse
import kotlin.coroutines.cancellation.CancellationException
import kotlin.experimental.ExperimentalObjCName
import kotlin.experimental.ExperimentalObjCRefinement
import kotlin.native.HiddenFromObjC
import kotlin.native.ObjCName
import kotlin.time.Duration.Companion.minutes

/**
 * Concurrency-safe Token Refresh Handler.
 */
@ExperimentalOpenIdConnect
@OptIn(ExperimentalObjCName::class, ExperimentalObjCRefinement::class)
@ObjCName("TokenRefreshHandler", "TokenRefreshHandler", exact = true)
@Suppress("unused")
class TokenRefreshHandler(
    private val tokenStore: TokenStore,
) {
    private val mutex = Mutex()

    /**
     * Thread-safe refresh the tokens and save to store.
     * @return The new tokens
     */
    @Throws(OpenIdConnectException::class, CancellationException::class)
    suspend fun refreshAndSaveToken(client: OpenIdConnectClient, oldAccessToken: String): OauthTokens {
        return refreshAndSaveToken(client::refreshToken, oldAccessToken)
    }

    /**
     * Thread-safe refresh the tokens and save to store.
     *
     * @param oldAccessToken The access token that was used for the previous get request that failed with 401.
     * Required to avoid multiple refresh calls when calls return 401 simultaneously.
     *
     * @return The new access token
     */
    @Throws(OpenIdConnectException::class, CancellationException::class)
    @HiddenFromObjC
    suspend fun refreshAndSaveToken(refreshCall: suspend (String) -> AccessTokenResponse, oldAccessToken: String): OauthTokens {
        mutex.withLock {
            val currentTokens = tokenStore.getTokens()
            return if (currentTokens != null && currentTokens.accessToken != oldAccessToken) {
                currentTokens
            } else {
                val refreshToken = tokenStore.getRefreshToken()
                var newTokens = refreshCall(refreshToken ?: "")
                if (newTokens.refresh_token == null) {
                    newTokens = newTokens.copy(refresh_token = refreshToken)
                }
                tokenStore.saveTokens(newTokens)

                OauthTokens(
                    accessToken = newTokens.access_token,
                    refreshToken = newTokens.refresh_token,
                    idToken = newTokens.id_token,
                    expiresIn = newTokens.expires_in,
                    refreshTokenExpiresIn = newTokens.refresh_token_expires_in,
                    receivedAt = newTokens.received_at
                )
            }
        }
    }

    /**
     * Executes the provided action with fresh tokens, refreshing them first if needed.
     *
     * @param client The OpenIdConnectClient used to refresh tokens if needed
     * @param minValiditySeconds The minimum number of seconds the access token should be valid for (default: 300 seconds / 5 minutes)
     * @param action The action to execute with fresh tokens. Receives the current tokens as a parameter.
     * @return The result of the action execution
     */
    @Throws(OpenIdConnectException::class, CancellationException::class)
    suspend fun <T> performWithFreshTokens(
        client: OpenIdConnectClient,
        minValiditySeconds: Long = 300, // 5 minutes
        action: suspend (tokens: OauthTokens) -> T
    ): T {
        val tokens = mutex.withLock {
            val currentTokens =
                tokenStore.getTokens() ?: throw IllegalStateException("No tokens available")

            // Check if token needs refreshing
            val needsRefresh = currentTokens.isTokenRefreshNeeded(minValiditySeconds)

            if (needsRefresh) {
                refreshAndSaveToken(client, currentTokens.accessToken)
            } else {
                currentTokens
            }
        }

        // Execute the action with the fresh tokens
        return action(tokens)
    }

    /**
     * Executes the provided action with fresh tokens, refreshing them first if needed.
     *
     * @param refreshCall The function to call to refresh tokens if needed
     * @param minValiditySeconds The minimum number of seconds the access token should be valid for (default: 300 seconds / 5 minutes)
     * @param action The action to execute with fresh tokens. Receives the current tokens as a parameter.
     * @return The result of the action execution
     */
    @Throws(OpenIdConnectException::class, CancellationException::class)
    @HiddenFromObjC
    suspend fun <T> performWithFreshTokens(
        refreshCall: suspend (String) -> AccessTokenResponse,
        minValiditySeconds: Long = 5.minutes.inWholeSeconds,
        action: suspend (tokens: OauthTokens) -> T
    ): T {
        val tokens = mutex.withLock {
            val currentTokens = tokenStore.getTokens() ?: throw IllegalStateException("No tokens available")

            val needsRefresh = currentTokens.isTokenRefreshNeeded(minValiditySeconds)
            if (needsRefresh) {
                refreshAndSaveToken(refreshCall, currentTokens.accessToken)
            } else {
                currentTokens
            }
        }

        // Execute the action with the fresh tokens
        return action(tokens)
    }
}
