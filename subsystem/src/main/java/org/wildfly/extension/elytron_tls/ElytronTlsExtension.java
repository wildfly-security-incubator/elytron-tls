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

package org.wildfly.extension.elytron_tls;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;

import javax.net.ssl.SSLContext;

import org.jboss.as.controller.Extension;
import org.jboss.as.controller.ExtensionContext;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SubsystemRegistration;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.operations.common.GenericSubsystemDescribeHandler;
import org.jboss.as.controller.parsing.ExtensionParsingContext;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.server.deployment.AttachmentKey;
import org.jboss.msc.service.ServiceName;
import org.wildfly.extension.elytron.common.ElytronCommonDefinitions;

/**
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsExtension implements Extension {

    /**
     * The namespaces used for the Elytron TLS subsystem.
     */

    public static final String NAMESPACE_1_0 = "urn:wildfly:elytron-tls:1.0";

    /**
     * The name of our subsystem within the model.
     */
    public static final String SUBSYSTEM_NAME = "elytron-tls";

    public static final AttachmentKey<SSLContext> SSL_CONTEXT_KEY = AttachmentKey.create(SSLContext.class);

    protected static final ModelVersion VERSION_1_0_0 = ModelVersion.create(1, 0, 0);

    private static final ModelVersion CURRENT_MODEL_VERSION = VERSION_1_0_0;

    protected static final PathElement SUBSYSTEM_PATH = PathElement.pathElement(SUBSYSTEM, SUBSYSTEM_NAME);
    static final ServiceName BASE_SERVICE_NAME = ServiceName.of(SUBSYSTEM_NAME);


    static StandardResourceDescriptionResolver getResourceDescriptionResolver(final String... keyPrefixes) {
        return ElytronCommonDefinitions.getResourceDescriptionResolver(ElytronTlsExtension.class, keyPrefixes);
    }

    @Override
    public void initializeParsers(ExtensionParsingContext context) {
        context.setSubsystemXmlMapping(SUBSYSTEM_NAME, NAMESPACE_1_0, ElytronTlsSubsystemParser_1_0::new);
    }


    @Override
    public void initialize(ExtensionContext extensionContext) {
        final SubsystemRegistration sr =  extensionContext.registerSubsystem(SUBSYSTEM_NAME, CURRENT_MODEL_VERSION);

        final ManagementResourceRegistration root = sr.registerSubsystemModel(new ElytronTlsSubsystemDefinition());
        root.registerOperationHandler(GenericSubsystemDescribeHandler.DEFINITION, GenericSubsystemDescribeHandler.INSTANCE);
        sr.registerXMLElementWriter(ElytronTlsSubsystemParser_1_0::new);
    }
}
