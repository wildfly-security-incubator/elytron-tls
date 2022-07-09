package org.wildfly.extension.elytron.tls.subsystem;

import static org.wildfly.extension.elytron.tls.subsystem.Constants.KEY_STORE;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.security.CredentialReference;

class KeyStoreParser {

    final PersistentResourceXMLDescription keyStoreParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(KEY_STORE))
            .addAttribute(SSLContextDefinitions.TYPE)
//            .addAttribute(SSLContextDefinitions.PROVIDERS)
            .addAttribute(SSLContextDefinitions.PROVIDER_NAME)
            .addAttribute(SSLContextDefinitions.CREDENTIAL_REFERENCE)
            .addAttribute(SSLContextDefinitions.ALIAS_FILTER)
            .addAttribute(SSLContextDefinitions.REQUIRED)
            .addAttribute(FileAttributeDefinitions.PATH)
            .addAttribute(FileAttributeDefinitions.RELATIVE_TO)
            .addAttribute(CredentialReference.getAttributeDefinition())
            .build();
}
