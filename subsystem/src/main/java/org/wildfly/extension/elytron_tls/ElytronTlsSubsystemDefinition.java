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

package org.wildfly.extension.elytron_tls;

import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron_tls.Capabilities.ELYTRON_TLS_RUNTIME_CAPABILITY;

import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.jboss.as.controller.AbstractBoottimeAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.AbstractWriteAttributeHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.CapabilityServiceTarget;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationContext.Stage;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.access.constraint.ApplicationTypeConfig;
import org.jboss.as.controller.access.constraint.SensitivityClassification;
import org.jboss.as.controller.access.management.ApplicationTypeAccessConstraintDefinition;
import org.jboss.as.controller.access.management.SensitiveTargetAccessConstraintDefinition;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.server.AbstractDeploymentChainStep;
import org.jboss.as.server.DeploymentProcessorTarget;
import org.jboss.as.server.deployment.Phase;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.wildfly.extension.elytron.common.AdvancedModifiableKeyStoreDecorator;
import org.wildfly.extension.elytron.common.CertificateAuthorityAccountDefinition;
import org.wildfly.extension.elytron.common.CertificateAuthorityDefinition;
import org.wildfly.extension.elytron.common.ElytronCommonConstants;
import org.wildfly.extension.elytron.common.ElytronCommonDefinitions;
import org.wildfly.extension.elytron.common.ElytronOperationStepHandler;
import org.wildfly.extension.elytron.common.FilteringKeyStoreDefinition;
import org.wildfly.extension.elytron.common.KeyStoreDefinition;
import org.wildfly.extension.elytron.common.LdapKeyStoreDefinition;
import org.wildfly.extension.elytron.common.ModifiableKeyStoreDecorator;
import org.wildfly.extension.elytron.common.SSLDefinitions;
import org.wildfly.extension.elytron_tls.deployment.DependencyProcessor;

/**
 * Top level {@link ResourceDefinition} for the Elytron TLS subsystem.
 * <p>
 * TODO: notes about how the implementation should be done are explained with TODOs. Remove all of them
 * before release. Also, double check the included test cases - some of these will need to be updated, replaced, or expanded.
 *
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsSubsystemDefinition extends ElytronCommonDefinitions {

    /**
     * System property which if set to {@code true} will cause the JVM wide default {@link SSLContext} to be restored when the subsystem shuts down.
     * This property is only for use by test cases.
     */
    static final String RESTORE_DEFAULT_SSL_CONTEXT = ElytronTlsSubsystemDefinition.class.getPackage().getName() + ".restore-default-ssl-context";

    static final SimpleAttributeDefinition DEFAULT_SSL_CONTEXT = new SimpleAttributeDefinitionBuilder(ElytronCommonConstants.DEFAULT_SSL_CONTEXT, ModelType.STRING, true)
            .setCapabilityReference(SSL_CONTEXT_CAPABILITY, ELYTRON_TLS_RUNTIME_CAPABILITY)
            .setRestartAllServices()
            .build();

    public ElytronTlsSubsystemDefinition() {
        super(new Parameters(ElytronTlsExtension.SUBSYSTEM_PATH, ElytronTlsExtension.getResourceDescriptionResolver())
                .setAddHandler(new AddHandler())
                .setRemoveHandler(new RemoveHandler())
                .setCapabilities(ELYTRON_TLS_RUNTIME_CAPABILITY)
                .addAccessConstraints(new SensitiveTargetAccessConstraintDefinition(new SensitivityClassification(ElytronTlsExtension.SUBSYSTEM_NAME, Constants.ELYTRON_SECURITY, true, true, true)),
                        new ApplicationTypeAccessConstraintDefinition(new ApplicationTypeConfig(ElytronTlsExtension.SUBSYSTEM_NAME, Constants.ELYTRON_SECURITY, false))));
    }

    @Override
    public void registerChildren(ManagementResourceRegistration resourceRegistration) {
        Class<?> extensionClass = ElytronTlsExtension.class;

        // TLS building blocks

        resourceRegistration.registerSubModel(AdvancedModifiableKeyStoreDecorator.wrap(extensionClass, KeyStoreDefinition.configure(extensionClass)));
        resourceRegistration.registerSubModel(ModifiableKeyStoreDecorator.wrap(extensionClass, LdapKeyStoreDefinition.configure(extensionClass)));
        resourceRegistration.registerSubModel(ModifiableKeyStoreDecorator.wrap(extensionClass, FilteringKeyStoreDefinition.configure(extensionClass)));
        resourceRegistration.registerSubModel(SSLDefinitions.getKeyManagerDefinition(extensionClass));
        resourceRegistration.registerSubModel(SSLDefinitions.getTrustManagerDefinition(extensionClass));
        resourceRegistration.registerSubModel(SSLDefinitions.getServerSNISSLContextDefinition(extensionClass));
        resourceRegistration.registerSubModel(CertificateAuthorityDefinition.configure(extensionClass));
        resourceRegistration.registerSubModel(CertificateAuthorityAccountDefinition.configure(extensionClass));

        // TLS subsystem additions

        // TODO: uncomment these lines once the resources are implemented
        // resourceRegistration.registerSubModel(SSLContextDefinitions.getServerSSLContextDefinition(isServerOrHostController(resourceRegistration)));
        // resourceRegistration.registerSubModel(SSLContextDefinitions.getClientSSLContextDefinition(isServerOrHostController(resourceRegistration)));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerReadWriteAttribute(DEFAULT_SSL_CONTEXT, null, new ElytronTlsWriteAttributeHandler<Void>(DEFAULT_SSL_CONTEXT));
    }

    private static class AddHandler extends AbstractBoottimeAddStepHandler implements ElytronOperationStepHandler {

        private AddHandler() {
            super(DEFAULT_SSL_CONTEXT);
        }

        @Override
        protected void performBoottime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            CapabilityServiceTarget target = context.getCapabilityServiceTarget();

            final String defaultSSLContext = DEFAULT_SSL_CONTEXT.resolveModelAttribute(context, model).asStringOrNull();
            if (defaultSSLContext != null) {
                ServiceBuilder<?> serviceBuilder = target.addService(DefaultSSLContextService.SERVICE_NAME);
                Supplier<SSLContext> defaultSSLContextSupplier = serviceBuilder.requires(context.getCapabilityServiceName(SSL_CONTEXT_CAPABILITY, defaultSSLContext, SSLContext.class));
                Consumer<SSLContext> valueConsumer = serviceBuilder.provides(DefaultSSLContextService.SERVICE_NAME);

                DefaultSSLContextService defaultSSLContextService = new DefaultSSLContextService(defaultSSLContextSupplier, valueConsumer);
                serviceBuilder.setInstance(defaultSSLContextService)
                        .install();
            }

            if (context.isNormalServer()) {
                context.addStep(new AbstractDeploymentChainStep() {
                    @Override
                    protected void execute(DeploymentProcessorTarget processorTarget) {
                        final int DEPENDENCIES_ELYTRON_TLS = 0x0C60;
                        processorTarget.addDeploymentProcessor(ElytronTlsExtension.SUBSYSTEM_NAME, Phase.DEPENDENCIES, DEPENDENCIES_ELYTRON_TLS, new DependencyProcessor());

                        if (defaultSSLContext != null) {
                            processorTarget.addDeploymentProcessor(ElytronTlsExtension.SUBSYSTEM_NAME, Phase.CONFIGURE_MODULE, Phase.CONFIGURE_DEFAULT_SSL_CONTEXT, new SSLContextDependencyProcessor());
                        }
                    }
                }, Stage.RUNTIME);
            }
        }

        @Override
        protected boolean requiresRuntime(OperationContext context) {
            return isServerOrHostController(context);
        }
    }

    private static class RemoveHandler extends AbstractRemoveStepHandler implements ElytronOperationStepHandler {
        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) {
            context.reloadRequired();
        }

        @Override
        protected boolean requiresRuntime(OperationContext context) {
            return isServerOrHostController(context);
        }
    }

    /**
     * Derived from {@code ElytronWriteAttributeHandler} in {@code org.wildfly.core:wildfly-elytron-integration}.
     */
    static class ElytronTlsWriteAttributeHandler<V> extends AbstractWriteAttributeHandler<V> implements ElytronOperationStepHandler {

        public ElytronTlsWriteAttributeHandler(final AttributeDefinition... definitions) {
            super(definitions);
        }

        protected boolean applyUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                               ModelNode resolvedValue, ModelNode currentValue, HandbackHolder<V> handbackHolder) {
            if (!resolvedValue.isDefined() && currentValue.isDefined()) {
                // We can not capture the existing default as by doing so we would trigger its initialisation which
                // could fail in a variety of ways as well as the wasted initialisation, if the attribute is being
                // changed from defined to undefined the only option is to completely restart the process.
                context.restartRequired();
                return false;
            }

            return true;
        }

        @Override
        protected void revertUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName, ModelNode valueToRestore,
                                             ModelNode valueToRevert, V handback) {}

        @Override
        protected boolean requiresRuntime(OperationContext context) {
            return isServerOrHostController(context);
        }
    }
}
