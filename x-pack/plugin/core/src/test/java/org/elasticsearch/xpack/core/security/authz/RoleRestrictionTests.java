/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.ByteBufferStreamInput;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.NamedWriteableAwareStreamInput;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xcontent.ToXContent;
import org.elasticsearch.xcontent.XContentParser;
import org.elasticsearch.xcontent.XContentParserConfiguration;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.XPackClientPlugin;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor.Restriction;

import java.io.IOException;

import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

public class RoleRestrictionTests extends ESTestCase {

    public void testParse() throws Exception {
        final String json = """
            {
                "workflows": ["search_application"]
            }
            """;
        Restriction r = Restriction.parse("test_restriction", createJsonParser(json));
        assertThat(r.getWorkflows(), arrayContainingInAnyOrder("search_application"));
        assertThat(r.hasWorkflows(), equalTo(true));
        assertThat(r.isEmpty(), equalTo(false));

        var e = expectThrows(ElasticsearchParseException.class, () -> Restriction.parse("test_restriction", createJsonParser("{}")));
        assertThat(
            e.getMessage(),
            containsString("failed to parse restriction for role [test_restriction]. missing required [workflows] field")
        );

        e = expectThrows(ElasticsearchParseException.class, () -> Restriction.parse("test_restriction", createJsonParser("""
             {
                 "workflows": []
             }
            """)));
        assertThat(
            e.getMessage(),
            containsString("failed to parse restriction for role [test_restriction]. [workflows] cannot be an empty array")
        );
    }

    public void testToXContent() throws Exception {
        final Restriction restriction = randomWorkflowsRestriction(1, 5);
        final XContentType xContentType = randomFrom(XContentType.values());
        final BytesReference xContentValue = toShuffledXContent(restriction, xContentType, ToXContent.EMPTY_PARAMS, false);
        final XContentParser parser = xContentType.xContent().createParser(XContentParserConfiguration.EMPTY, xContentValue.streamInput());
        final Restriction parsed = Restriction.parse(randomAlphaOfLengthBetween(3, 6), parser);
        assertThat(parsed, equalTo(restriction));
    }

    public void testSerialization() throws IOException {
        final BytesStreamOutput out = new BytesStreamOutput();
        final Restriction original = randomWorkflowsRestriction(0, 3);
        original.writeTo(out);

        final NamedWriteableRegistry registry = new NamedWriteableRegistry(new XPackClientPlugin().getNamedWriteables());
        StreamInput in = new NamedWriteableAwareStreamInput(ByteBufferStreamInput.wrap(BytesReference.toBytes(out.bytes())), registry);
        final Restriction actual = new Restriction(in);

        assertThat(actual, equalTo(original));
    }

    public void testIsEmpty() {
        String[] workflows = new String[] {};
        Restriction r = new Restriction(workflows);
        assertThat(r.isEmpty(), equalTo(true));
        assertThat(r.hasWorkflows(), equalTo(false));

        workflows = randomWorkflowNames(1, 2);
        r = new Restriction(workflows);
        assertThat(r.isEmpty(), equalTo(false));
        assertThat(r.hasWorkflows(), equalTo(true));
    }

    private static XContentParser createJsonParser(String json) throws IOException {
        return XContentType.JSON.xContent().createParser(XContentParserConfiguration.EMPTY, new BytesArray(json).streamInput());
    }

    public static Restriction randomWorkflowsRestriction(int min, int max) {
        return new Restriction(randomWorkflowNames(min, max));
    }

    public static String[] randomWorkflowNames(int min, int max) {
        // TODO: Change this to use actual workflow names instead of random ones.
        return randomArray(min, max, String[]::new, () -> randomAlphaOfLengthBetween(3, 6));
    }
}
