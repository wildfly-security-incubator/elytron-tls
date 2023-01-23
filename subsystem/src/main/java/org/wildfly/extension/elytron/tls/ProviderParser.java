/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.extension.elytron.tls;

import static org.wildfly.extension.elytron.tls.Constants.AGGREGATE_PROVIDERS;
import static org.wildfly.extension.elytron.tls.Constants.PROVIDERS;
import static org.wildfly.extension.elytron.tls.Constants.PROVIDER_LOADER;

import org.jboss.as.controller.AttributeMarshallers;
import org.jboss.as.controller.AttributeParsers;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;

/**
 * XML Parser and Marshaller for Provider configuration.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author Tomaz Cerar
 */
class ProviderParser {

    private final PersistentResourceXMLDescription providerLoaderParser = PersistentResourceXMLDescription.builder(PathElement.pathElement(PROVIDER_LOADER))
            .setUseElementsForGroups(false)
            .addAttributes(ClassLoadingAttributeDefinitions.MODULE, ClassLoadingAttributeDefinitions.CLASS_NAMES, ProviderDefinitions.PATH, ProviderDefinitions.RELATIVE_TO,
                    ProviderDefinitions.ARGUMENT, ProviderDefinitions.CONFIGURATION)
            .build();
    private final PersistentResourceXMLDescription aggregateProviders = PersistentResourceXMLDescription.builder(PathElement.pathElement(AGGREGATE_PROVIDERS))
            .addAttribute(ProviderDefinitions.REFERENCES,
                    new AttributeParsers.NamedStringListParser(PROVIDERS),
                    new AttributeMarshallers.NamedStringListMarshaller(PROVIDERS))
            .build();
    final PersistentResourceXMLDescription providerParser_1_0 = PersistentResourceXMLDescription.decorator(PROVIDERS)
            .addChild(aggregateProviders)
            .addChild(providerLoaderParser)
            .build();
}
