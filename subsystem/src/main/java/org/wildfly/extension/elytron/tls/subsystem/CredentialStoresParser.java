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

import static org.wildfly.extension.elytron.tls.subsystem.Constants.CREDENTIAL_STORE;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.CREDENTIAL_STORES;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.SECRET_KEY_CREDENTIAL_STORE;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;

public class CredentialStoresParser {

    final PersistentResourceXMLDescription credentialStoreParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(CREDENTIAL_STORE))
            .setUseElementsForGroups(false)
            .addAttribute(CredentialStoreResourceDefinition.IMPLEMENTATION_PROPERTIES)
            .addAttribute(CredentialStoreResourceDefinition.CREDENTIAL_REFERENCE)
            .addAttribute(CredentialStoreResourceDefinition.TYPE)
            .addAttribute(CredentialStoreResourceDefinition.PROVIDER_NAME)
            .addAttribute(CredentialStoreResourceDefinition.PROVIDERS)
            .addAttribute(CredentialStoreResourceDefinition.OTHER_PROVIDERS)
            .addAttribute(CredentialStoreResourceDefinition.RELATIVE_TO)
            .addAttribute(CredentialStoreResourceDefinition.LOCATION)
            .addAttribute(CredentialStoreResourceDefinition.PATH)
            .addAttribute(CredentialStoreResourceDefinition.MODIFIABLE)
            .addAttribute(CredentialStoreResourceDefinition.CREATE)
            .build();

    final PersistentResourceXMLDescription secretKeyCredentialStoreParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(SECRET_KEY_CREDENTIAL_STORE))
            .setUseElementsForGroups(false)
            .addAttributes(SecretKeyCredentialStoreDefinition.CONFIG_ATTRIBUTES)
            .build();

    final PersistentResourceXMLDescription credentialStoresParser_1_0 = PersistentResourceXMLDescription.decorator(CREDENTIAL_STORES)
            .addChild(credentialStoreParser_1_0)
            .addChild(secretKeyCredentialStoreParser_1_0)
            .build();
}
