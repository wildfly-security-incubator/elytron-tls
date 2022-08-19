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

import static org.wildfly.extension.elytron.tls.subsystem.Constants.CERTIFICATE_AUTHORITIES;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.CERTIFICATE_AUTHORITY;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.CERTIFICATE_AUTHORITY_ACCOUNT;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.CERTIFICATE_AUTHORITY_ACCOUNTS;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;

class CAParsers {
    final PersistentResourceXMLDescription certificateAuthorityParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(CERTIFICATE_AUTHORITY))
            .setXmlWrapperElement(CERTIFICATE_AUTHORITIES)
            .addAttribute(CertificateAuthorityDefinition.URL)
            .addAttribute(CertificateAuthorityDefinition.STAGING_URL)
            .build();

    final PersistentResourceXMLDescription certificateAuthorityAccountParser_1_0 = PersistentResourceXMLDescription.builder(PathElement.pathElement(CERTIFICATE_AUTHORITY_ACCOUNT))
            .setXmlWrapperElement(CERTIFICATE_AUTHORITY_ACCOUNTS)
            .addAttribute(CertificateAuthorityAccountDefinition.CERTIFICATE_AUTHORITY)
            .addAttribute(CertificateAuthorityAccountDefinition.CONTACT_URLS)
            .addAttribute(CertificateAuthorityAccountDefinition.KEY_STORE)
            .addAttribute(CertificateAuthorityAccountDefinition.ALIAS)
            .addAttribute(CertificateAuthorityAccountDefinition.CREDENTIAL_REFERENCE)
            .build();
}
