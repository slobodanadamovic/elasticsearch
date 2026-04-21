/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.metric;

/**
 * Marker interface for low-cardinality authentication failure reasons. Values follow the
 * {@code {attribution}.{detail}} naming convention:
 * <ul>
 *   <li>{@code client.*} — failures caused by the client (invalid credentials, expired tokens, etc.)</li>
 *   <li>{@code server.*} — failures caused by server-side issues (infrastructure errors)</li>
 * </ul>
 *
 * <p>Default constants ({@link #CLIENT_AUTHENTICATION_FAILED}, {@link #SERVER_INTERNAL_ERROR}) cover common cases.
 * Authenticators that need finer-grained reasons can define their own enum implementing this interface.
 *
 * <p>The {@link #value()} string is recorded as a metric attribute value and must remain stable and low-cardinality.
 */
public interface AuthcFailureReason {

    /**
     * Client-supplied credentials were rejected. This is the default client-side failure reason.
     */
    AuthcFailureReason CLIENT_AUTHENTICATION_FAILED = () -> "client.authentication_failed";

    /**
     * An unexpected server-side error occurred during authentication.
     */
    AuthcFailureReason SERVER_INTERNAL_ERROR = () -> "server.internal_error";

    /**
     * Returns the stable string value recorded on failure metrics.
     */
    String value();
}
