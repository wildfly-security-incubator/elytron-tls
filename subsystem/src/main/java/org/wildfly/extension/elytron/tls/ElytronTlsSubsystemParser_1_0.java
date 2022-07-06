/*
 * Copyright 2023 Red Hat, Inc.
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

package org.wildfly.extension.elytron.tls;

import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.PersistentResourceXMLParser;

/**
 * A parser for the Elytron TLS subsystem.
 * 
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsSubsystemParser_1_0 extends PersistentResourceXMLParser {

    String getNamespace() {
        return ElytronTlsExtension.NAMESPACE_1_0;
    }

    @Override
    public PersistentResourceXMLDescription getParserDescription() {
        return PersistentResourceXMLDescription.builder(ElytronTlsExtension.SUBSYSTEM_PATH, getNamespace())
                .addAttribute(ElytronTlsSubsystemDefinition.DEFAULT_SSL_CONTEXT)
                .build();
    }

    /* TODO add resources for attributes and resources added in ElytronTlsSubsystemDefinitions
        Unmodified definitions will use standard parsers (reference TlsParser in the Elytron subsystem of WildFly Core).
        New classes from Elytron TLS will need to be laid out to match their layout in the code, and not to add elements to the XML.*/
}
