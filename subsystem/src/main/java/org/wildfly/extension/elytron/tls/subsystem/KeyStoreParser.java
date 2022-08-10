package org.wildfly.extension.elytron.tls.subsystem;

import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_STORE_OBJECT;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_STORES;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.security.CredentialReference;

class KeyStoreParser {

    final PersistentResourceXMLDescription keyStoreParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(KEY_STORE_OBJECT))
            .setXmlWrapperElement(KEY_STORES)
            .addAttribute(KeyStoreDefinition.CREDENTIAL_REFERENCE)
            .addAttribute(KeyStoreDefinition.TYPE)
            .addAttribute(FileAttributeDefinitions.PATH)
            .addAttribute(FileAttributeDefinitions.RELATIVE_TO)
            .addAttribute(KeyStoreDefinition.ALIAS_FILTER)
            .addAttribute(KeyStoreDefinition.PROVIDERS)
            .addAttribute(KeyStoreDefinition.PROVIDER_NAME)
            .addAttribute(KeyStoreDefinition.REQUIRED)
            .addAttribute(CredentialReference.getAttributeDefinition())
            .build();
}
