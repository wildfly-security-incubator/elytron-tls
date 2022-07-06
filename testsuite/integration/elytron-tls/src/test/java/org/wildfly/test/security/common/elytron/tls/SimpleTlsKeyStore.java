/*
 * Copyright 2017 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.test.security.common.elytron.tls;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.wildfly.test.security.common.elytron.AbstractConfigurableElement;
import org.wildfly.test.security.common.elytron.CredentialReference;

/**
 * Elytron TLS key-store configuration implementation.
 *
 * @author Josef Cacek
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class SimpleTlsKeyStore extends AbstractConfigurableElement {

    private final CliPath path;
    private final CredentialReference credentialReference;
    private final String type;
    private final boolean required;

    private SimpleTlsKeyStore(Builder builder) {
        super(builder);
        this.path = defaultIfNull(builder.path, CliPath.EMPTY);
        this.credentialReference = defaultIfNull(builder.credentialReference, CredentialReference.EMPTY);
        this.type = defaultIfNull(builder.type, "JKS");
        this.required = builder.required;
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        // /subsystem=elytron-tls/key-store=httpsKS:add(path=keystore.jks,relative-to=jboss.server.config.dir,
        // credential-reference={clear-text=secret},type=JKS,required=false)
        cli.sendLine(String.format("/subsystem=elytron-tls/key-store=%s:add(%s%stype=\"%s\",required=%s)", name, path.asString(),
                credentialReference.asString(), type, required));
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        cli.sendLine(String.format("/subsystem=elytron-tls/key-store=%s:remove()", name));
    }

    /**
     * Creates builder to build {@link SimpleTlsKeyStore}.
     *
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link SimpleTlsKeyStore}.
     */
    public static final class Builder extends AbstractConfigurableElement.Builder<Builder> {
        private CliPath path;
        private CredentialReference credentialReference;
        private String type;
        private boolean required;

        private Builder() {
        }

        public Builder withPath(CliPath path) {
            this.path = path;
            return this;
        }

        public Builder withCredentialReference(CredentialReference credentialReference) {
            this.credentialReference = credentialReference;
            return this;
        }

        public Builder withType(String type) {
            this.type = type;
            return this;
        }

        public Builder withRequired(boolean required) {
            this.required = required;
            return this;
        }

        public SimpleTlsKeyStore build() {
            return new SimpleTlsKeyStore(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
