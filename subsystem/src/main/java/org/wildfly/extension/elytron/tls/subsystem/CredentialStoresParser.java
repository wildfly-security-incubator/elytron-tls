package org.wildfly.extension.elytron.tls.subsystem;

import static org.jboss.as.controller.PersistentResourceXMLDescription.builder;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;

public class CredentialStoresParser {

    final PersistentResourceXMLDescription credentialStoreParser_1_0 = builder(PathElement.pathElement(Constants.CREDENTIAL_STORE))
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

    final PersistentResourceXMLDescription secretKeyCredentialStoreParser_1_0 = builder(PathElement.pathElement(Constants.SECRET_KEY_CREDENTIAL_STORE))
            .setUseElementsForGroups(false)
            .addAttributes(SecretKeyCredentialStoreDefinition.CONFIG_ATTRIBUTES)
            .build();

    final PersistentResourceXMLDescription credentialStoresParser_1_0 = builder(PathElement.pathElement(Constants.CREDENTIAL_STORES))
            .addChild(credentialStoreParser_1_0)
            .addChild(secretKeyCredentialStoreParser_1_0)
            .build();
}
