/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.metric;

import java.util.Map;

/**
 * Builds metric attributes for authentication failure recordings, including the failure category.
 * This allows each authenticator to produce the full attribute map (base attributes + category) in a single
 * allocation, avoiding an intermediate copy.
 *
 * @param <C> The type of context object which is used to attach additional attributes to collected metrics.
 */
@FunctionalInterface
public interface SecurityMetricFailureAttributesBuilder<C> {

    /**
     * Builds the complete attribute map for a failure metric recording.
     *
     * @param context  The context object (may be {@code null} if context is unavailable at failure time).
     * @param reason The failure reason for this failure.
     * @return an immutable map of attribute key-value pairs.
     */
    Map<String, Object> build(C context, AuthcFailureReason reason);

}
