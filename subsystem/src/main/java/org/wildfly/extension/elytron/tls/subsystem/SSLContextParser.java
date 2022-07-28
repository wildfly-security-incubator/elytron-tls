/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron.tls.subsystem;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;

import static org.wildfly.extension.elytron.tls.subsystem.Constants.CLIENT_SSL_CONTEXTS;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.SERVER_SSL_CONTEXTS;

class SSLContextParser {

    final PersistentResourceXMLDescription clientSslContextParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(Constants.CLIENT_SSL_CONTEXT))
            .setXmlWrapperElement(CLIENT_SSL_CONTEXTS)
            .addAttribute(SSLContextDefinitions.CIPHER_SUITE_FILTER)
            .addAttribute(SSLContextDefinitions.CIPHER_SUITE_NAMES)
            .addAttribute(SSLContextDefinitions.PROTOCOLS)
//            .addAttribute(SSLContextDefinitions.KEY_MANAGER)
            .addAttribute(SSLContextDefinitions.KEY_MANAGER_REFERENCE)
//            .addAttribute(SSLContextDefinitions.TRUST_MANAGER)
            .addAttribute(SSLContextDefinitions.TRUST_MANAGER_REFERENCE)
            .addAttribute(SSLContextDefinitions.PROVIDERS)
            .addAttribute(SSLContextDefinitions.PROVIDER_NAME)
            .build();

    final PersistentResourceXMLDescription serverSslContextParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(Constants.SERVER_SSL_CONTEXT))
            .setXmlWrapperElement(SERVER_SSL_CONTEXTS)
            .addAttribute(SSLContextDefinitions.CIPHER_SUITE_FILTER)
            .addAttribute(SSLContextDefinitions.CIPHER_SUITE_NAMES)
            .addAttribute(SSLContextDefinitions.PROTOCOLS)
            .addAttribute(SSLContextDefinitions.WANT_CLIENT_AUTH)
            .addAttribute(SSLContextDefinitions.NEED_CLIENT_AUTH)
            .addAttribute(SSLContextDefinitions.AUTHENTICATION_OPTIONAL)
            .addAttribute(SSLContextDefinitions.USE_CIPHER_SUITES_ORDER)
            .addAttribute(SSLContextDefinitions.MAXIMUM_SESSION_CACHE_SIZE)
            .addAttribute(SSLContextDefinitions.SESSION_TIMEOUT)
            .addAttribute(SSLContextDefinitions.WRAP)
//            .addAttribute(SSLContextDefinitions.KEY_MANAGER)
            .addAttribute(SSLContextDefinitions.KEY_MANAGER_REFERENCE)
//            .addAttribute(SSLContextDefinitions.TRUST_MANAGER)
            .addAttribute(SSLContextDefinitions.TRUST_MANAGER_REFERENCE)
            .addAttribute(SSLContextDefinitions.PROVIDERS)
            .addAttribute(SSLContextDefinitions.PROVIDER_NAME)
            .build();

}
