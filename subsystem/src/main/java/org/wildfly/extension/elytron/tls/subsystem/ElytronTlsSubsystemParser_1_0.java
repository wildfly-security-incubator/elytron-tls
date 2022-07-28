/*
 * Copyright 2022 Red Hat, Inc.
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

package org.wildfly.extension.elytron.tls.subsystem;

import org.jboss.as.controller.AttributeMarshallers;
import org.jboss.as.controller.AttributeParsers;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.PersistentResourceXMLParser;

import static org.wildfly.extension.elytron.tls.subsystem.Constants.SECURITY_PROPERTY;

/**
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 */
public class ElytronTlsSubsystemParser_1_0 extends PersistentResourceXMLParser {

    PersistentResourceXMLDescription getServerSSLContextParser() {
        return new SSLContextParser().serverSslContextParser_1_0;
    }

    PersistentResourceXMLDescription getClientSSLContextParser() {
        return new SSLContextParser().clientSslContextParser_1_0;
    }

    PersistentResourceXMLDescription getKeyStoreParser() {
        return new KeyStoreParser().keyStoreParser_1_0;
    }
    PersistentResourceXMLDescription getCredentialStoresParser() {
        return new CredentialStoreParser().credentialStoresParser_1_0;
    }

    PersistentResourceXMLDescription getKeyManagerParser() {
        return new ManagerParser().keyManagerParser_1_0;
    }
    PersistentResourceXMLDescription getTrustManagerParser() {
        return new ManagerParser().trustManagerParser_1_0;
    }

    PersistentResourceXMLDescription getProviderParser() {
        return new ProviderParser().providerParser_1_0;
    }

    PersistentResourceXMLDescription getExpressionResolverParser() {
        return new ExpressionResolverParser().expressionResolverParser_1_0;
    }

    String getNameSpace() {
        return ElytronTlsExtension.NAMESPACE_1_0;
    }

    @Override
    public PersistentResourceXMLDescription getParserDescription() {
        return PersistentResourceXMLDescription.builder(ElytronTlsExtension.SUBSYSTEM_PATH, getNameSpace())
                .addAttribute(ElytronTlsSubsystemDefinition.SECURITY_PROPERTIES,
                        new AttributeParsers.PropertiesParser(null, SECURITY_PROPERTY, true),
                        new AttributeMarshallers.PropertiesAttributeMarshaller(null, SECURITY_PROPERTY, true))
                .addAttribute(ElytronTlsSubsystemDefinition.INITIAL_PROVIDERS)
                .addAttribute(ElytronTlsSubsystemDefinition.FINAL_PROVIDERS)
                .addAttribute(ElytronTlsSubsystemDefinition.DISALLOWED_PROVIDERS)
                .addAttribute(ElytronTlsSubsystemDefinition.DEFAULT_SSL_CONTEXT)
                .addChild(getServerSSLContextParser())
                .addChild(getClientSSLContextParser())
                .addChild(getKeyStoreParser())
                .addChild(getCredentialStoresParser())
                .addChild(getKeyManagerParser())
                .addChild(getTrustManagerParser())
                .addChild(getProviderParser())
                .addChild(getExpressionResolverParser())
                .build();
    }

}
