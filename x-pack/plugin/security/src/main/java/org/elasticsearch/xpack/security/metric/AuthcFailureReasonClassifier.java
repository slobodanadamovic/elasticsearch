/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.metric;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;

/**
 * Per-authenticator strategy for determining the failure reason of an authentication attempt.
 *
 * <p>The default implementations cover the common case: non-authenticated results are attributed to the client,
 * and exceptions are classified by HTTP status code (4xx → client, everything else → server). Authenticators
 * that need finer-grained classification (e.g. distinguishing invalid credentials from expired keys) can
 * override either or both methods.
 */
public interface AuthcFailureReasonClassifier {

    /**
     * A shared instance that uses the default classification logic for both methods.
     */
    AuthcFailureReasonClassifier DEFAULT = new AuthcFailureReasonClassifier() {};

    /**
     * Determines the failure reason for a non-authenticated {@link AuthenticationResult} (status CONTINUE or TERMINATE).
     * If the result carries an exception, delegates to {@link #fromException(Throwable)} to classify it.
     * Otherwise defaults to {@link AuthcFailureReason#CLIENT_AUTHENTICATION_FAILED}.
     */
    default AuthcFailureReason fromResult(AuthenticationResult<?> result) {
        assert result.isAuthenticated() == false : "fromResult should only be called for non-authenticated results";
        final Exception ex = result.getException();
        if (ex != null) {
            return fromException(ex);
        }
        return AuthcFailureReason.CLIENT_AUTHENTICATION_FAILED;
    }

    /**
     * Determines the failure reason for an exception received on the {@code onFailure} path.
     * Defaults to {@link AuthcFailureReason#CLIENT_AUTHENTICATION_FAILED} for 4xx {@link ElasticsearchException}s,
     * and {@link AuthcFailureReason#SERVER_INTERNAL_ERROR} for everything else.
     */
    default AuthcFailureReason fromException(Throwable t) {
        if (t instanceof ElasticsearchException ese && ese.status().getStatus() >= 400 && ese.status().getStatus() < 500) {
            return AuthcFailureReason.CLIENT_AUTHENTICATION_FAILED;
        }
        return AuthcFailureReason.SERVER_INTERNAL_ERROR;
    }
}
