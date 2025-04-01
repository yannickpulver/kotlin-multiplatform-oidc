package org.publicvalue.multiplatform.oidc.tokenstore

import kotlinx.datetime.Clock

data class OauthTokens(
    val accessToken: String,
    val refreshToken: String?,
    val idToken: String?,
    val expiresIn: Int? = null,
    val refreshTokenExpiresIn: Int? = null,
    val receivedAt: Long = clock.now().epochSeconds,
    val clock: Clock = Clock.System,
) {
    fun isAccessTokenValid(): Boolean {
        return expiresIn != null && receivedAt + expiresIn > clock.now().epochSeconds
    }
    
    fun isRefreshTokenValid(): Boolean {
        return refreshToken != null && refreshTokenExpiresIn != null && 
               receivedAt + refreshTokenExpiresIn > clock.now().epochSeconds
    }

    fun isTokenRefreshNeeded(minValiditySeconds: Long = 0L): Boolean {
        val expiresIn = expiresIn ?: return true
        val receivedAt = receivedAt
        val now = clock.now().epochSeconds

        return (receivedAt + expiresIn) <= (now + minValiditySeconds)
    }
}