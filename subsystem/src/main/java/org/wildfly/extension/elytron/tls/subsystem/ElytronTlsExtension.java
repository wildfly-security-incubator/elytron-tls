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

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;

import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import org.jboss.as.controller.Extension;
import org.jboss.as.controller.ExtensionContext;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SubsystemRegistration;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.extension.ExpressionResolverExtension;
import org.jboss.as.controller.operations.common.GenericSubsystemDescribeHandler;
import org.jboss.as.controller.parsing.ExtensionParsingContext;
import org.jboss.as.controller.registry.ImmutableManagementResourceRegistration;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.server.deployment.AttachmentKey;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;

/**
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsExtension implements Extension {

    /**
     * The namespaces used for the TLS subsystem.
     */

    public static final String NAMESPACE_1_0 = "urn:wildfly:elytron-tls-subsystem:1.0";

    public static final String CURRENT_NAMESPACE = NAMESPACE_1_0;

    private static final ElytronTlsSubsystemParser_1_0 CURRENT_PARSER = new ElytronTlsSubsystemParser_1_0();

    /**
     * The name of our subsystem within the model.
     */
    public static final String SUBSYSTEM_NAME = "elytron-tls";

    protected static final PathElement SUBSYSTEM_PATH = PathElement.pathElement(SUBSYSTEM, SUBSYSTEM_NAME);

    static final ServiceName BASE_SERVICE_NAME = ServiceName.of(SUBSYSTEM_NAME);

    public static final String WELD_CAPABILITY_NAME = "org.wildfly.weld";

    public static final AttachmentKey<SSLContext> SSL_CONTEXT_KEY = AttachmentKey.create(SSLContext.class);

    private static final String RESOURCE_NAME = ElytronTlsExtension.class.getPackage().getName() + ".LocalDescriptions";

    protected static final ModelVersion VERSION_1_0_0 = ModelVersion.create(1, 0, 0);
    private static final ModelVersion CURRENT_MODEL_VERSION = VERSION_1_0_0;

    static final String ISO_8601_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

    static StandardResourceDescriptionResolver getResourceDescriptionResolver(final String... keyPrefix) {
        return getResourceDescriptionResolver(false, keyPrefix);

    }

    static StandardResourceDescriptionResolver getResourceDescriptionResolver(final boolean useUnprefixedChildTypes, final String... keyPrefix) {
        StringBuilder prefix = new StringBuilder(ElytronTlsExtension.SUBSYSTEM_NAME);
        for (String kp : keyPrefix) {
            prefix.append('.').append(kp);
        }
        return new StandardResourceDescriptionResolver(prefix.toString(), RESOURCE_NAME, ElytronTlsExtension.class.getClassLoader(), true, useUnprefixedChildTypes);
    }

    static boolean isServerOrHostController(ImmutableManagementResourceRegistration resourceRegistration) {
        return resourceRegistration.getProcessType().isServer() || !ModelDescriptionConstants.PROFILE.equals(resourceRegistration.getPathAddress().getElement(0).getKey());
    }

    @Override
    public void initialize(ExtensionContext extensionContext) {
        final SubsystemRegistration sr =  extensionContext.registerSubsystem(SUBSYSTEM_NAME, CURRENT_MODEL_VERSION);

        AtomicReference<ExpressionResolverExtension> resolverRef = new AtomicReference<>();
        final ManagementResourceRegistration root = sr.registerSubsystemModel(new ElytronTlsSubsystemDefinition(resolverRef));
        root.registerOperationHandler(GenericSubsystemDescribeHandler.DEFINITION, GenericSubsystemDescribeHandler.INSTANCE, false);
        sr.registerXMLElementWriter(CURRENT_PARSER);

        extensionContext.registerExpressionResolverExtension(resolverRef::get, ExpressionResolverResourceDefinition.INITIAL_PATTERN, false);
    }

    @SuppressWarnings("unchecked")
    static <T> ServiceController<T> getRequiredService(ServiceRegistry serviceRegistry, ServiceName serviceName, Class<T> serviceType) {
        ServiceController<?> controller = serviceRegistry.getRequiredService(serviceName);
        return (ServiceController<T>) controller;
    }

    @Override
    public void initializeParsers(ExtensionParsingContext extensionParsingContext) {
        extensionParsingContext.setSubsystemXmlMapping(SUBSYSTEM_NAME, CURRENT_NAMESPACE, CURRENT_PARSER);
    }

    static public String getCurrentXsdPath() {
        StringBuilder xsdPath = new StringBuilder("schema/elytron-tls-subsystem_");
        String pathVersionNumber = CURRENT_NAMESPACE.split(":")[3].replace('.', '_');
        return xsdPath.append(pathVersionNumber).append(".xsd").toString();
    }
}
