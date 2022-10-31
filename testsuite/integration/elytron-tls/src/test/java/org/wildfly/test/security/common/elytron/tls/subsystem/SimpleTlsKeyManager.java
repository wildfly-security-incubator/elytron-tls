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
package org.wildfly.test.security.common.elytron.tls.subsystem;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.wildfly.common.Assert.checkNotNullParamWithNullPointerException;

import javax.net.ssl.KeyManagerFactory;

import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.wildfly.test.security.common.elytron.AbstractConfigurableElement;
import org.wildfly.test.security.common.elytron.CredentialReference;

/**
 * Elytron TLS key-manager configuration implementation.
 *
 * @author Josef Cacek
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class SimpleTlsKeyManager extends AbstractConfigurableElement {

    private final String keyStore;
    private final CredentialReference credentialReference;

    private SimpleTlsKeyManager(Builder builder) {
        super(builder);
        this.keyStore = checkNotNullParamWithNullPointerException("builder.keyStore", builder.keyStore);
        this.credentialReference = defaultIfNull(builder.credentialReference, CredentialReference.EMPTY);
    }

    @Override
    public void create(ModelControllerClient client, CLIWrapper cli) throws Exception {
        // /subsystem=elytron-tls/key-manager=httpsKM:add(key-store=httpsKS,algorithm="SunX509",credential-reference={clear-text=secret})

        cli.sendLine(String.format("/subsystem=elytron-tls/key-manager=%s:add(key-store=\"%s\",algorithm=\"%s\", %s)", name,
                keyStore, KeyManagerFactory.getDefaultAlgorithm(), credentialReference.asString()));
    }

    @Override
    public void remove(ModelControllerClient client, CLIWrapper cli) throws Exception {
        cli.sendLine(String.format("/subsystem=elytron-tls/key-manager=%s:remove()", name));
    }

    /**
     * Creates builder to build {@link SimpleTlsKeyManager}.
     *
     * @return created builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder to build {@link SimpleTlsKeyManager}.
     */
    public static final class Builder extends AbstractConfigurableElement.Builder<Builder> {
        private String keyStore;
        private CredentialReference credentialReference;

        private Builder() {
        }

        public Builder withKeyStore(String keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        public Builder withCredentialReference(CredentialReference credentialReference) {
            this.credentialReference = credentialReference;
            return this;
        }

        public SimpleTlsKeyManager build() {
            return new SimpleTlsKeyManager(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
