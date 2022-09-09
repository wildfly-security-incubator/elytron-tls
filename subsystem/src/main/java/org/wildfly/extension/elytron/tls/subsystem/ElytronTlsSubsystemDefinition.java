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

import static org.jboss.as.controller.OperationContext.Stage.RUNTIME;
import static org.jboss.as.server.deployment.Phase.DEPENDENCIES;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.ELYTRON_TLS_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.ElytronTlsExtension.isServerOrHostController;

import java.security.Provider;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.jboss.as.controller.AbstractBoottimeAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.AttributeMarshaller;
import org.jboss.as.controller.AttributeParser;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PersistentResourceDefinition;
import org.jboss.as.controller.PropertiesAttributeDefinition;
import org.jboss.as.controller.ReloadRequiredWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.extension.ExpressionResolverExtension;
import org.jboss.as.controller.operations.validation.StringLengthValidator;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.server.AbstractDeploymentChainStep;
import org.jboss.as.server.DeploymentProcessorTarget;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger;
import org.wildfly.extension.elytron.tls.subsystem.deployment.DependencyProcessor;

/**
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsSubsystemDefinition extends PersistentResourceDefinition {

    static final PropertiesAttributeDefinition SECURITY_PROPERTIES = new PropertiesAttributeDefinition.Builder(Constants.SECURITY_PROPERTIES, true)
            .build();

    private static final OperationContext.AttachmentKey<SecurityPropertyService> SECURITY_PROPERTY_SERVICE_KEY = OperationContext.AttachmentKey.create(SecurityPropertyService.class);


    static final SimpleAttributeDefinition DEFAULT_SSL_CONTEXT = new SimpleAttributeDefinitionBuilder(Constants.DEFAULT_SSL_CONTEXT, ModelType.STRING, true)
            .setCapabilityReference(SSL_CONTEXT_CAPABILITY, ELYTRON_TLS_RUNTIME_CAPABILITY)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition INITIAL_PROVIDERS = new SimpleAttributeDefinitionBuilder(Constants.INITIAL_PROVIDERS, ModelType.STRING, true)
            .setCapabilityReference(PROVIDERS_CAPABILITY, ELYTRON_TLS_RUNTIME_CAPABILITY)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition FINAL_PROVIDERS = new SimpleAttributeDefinitionBuilder(Constants.FINAL_PROVIDERS, ModelType.STRING, true)
            .setCapabilityReference(PROVIDERS_CAPABILITY, ELYTRON_TLS_RUNTIME_CAPABILITY)
            .setRestartAllServices()
            .build();

    static final StringListAttributeDefinition DISALLOWED_PROVIDERS = new StringListAttributeDefinition.Builder(Constants.DISALLOWED_PROVIDERS)
            .setRequired(false)
            .setAttributeParser(AttributeParser.STRING_LIST)
            .setAttributeMarshaller(AttributeMarshaller.STRING_LIST)
            .setRestartJVM()
            .setElementValidator(new StringLengthValidator(1))
            .setAllowExpression(true)
            .build();

    private final AtomicReference<ExpressionResolverExtension> resolverRef;

    public ElytronTlsSubsystemDefinition(AtomicReference<ExpressionResolverExtension> resolverRef) {
        super(
                new SimpleResourceDefinition.Parameters(
                        ElytronTlsExtension.SUBSYSTEM_PATH,
                        ElytronTlsExtension.getResourceDescriptionResolver())
                .setAddHandler(new ElytronTlsAdd())
                .setRemoveHandler(new ElytronTlsRemove())
                .setCapabilities(ELYTRON_TLS_RUNTIME_CAPABILITY)
        );
        this.resolverRef = resolverRef;
    }

    @Override
    public void registerChildren(ManagementResourceRegistration resourceRegistration) {
        final boolean serverOrHostController = isServerOrHostController(resourceRegistration);

        // Expression Resolver
        resourceRegistration.registerSubModel(ExpressionResolverResourceDefinition.getExpressionResolverDefinition(resourceRegistration.getPathAddress(), resolverRef));

        // Provider Loader
        resourceRegistration.registerSubModel(ProviderDefinitions.getAggregateProvidersDefinition());
        resourceRegistration.registerSubModel(ProviderDefinitions.getProviderLoaderDefinition(serverOrHostController));

        // Credential Store Block
        resourceRegistration.registerSubModel(new CredentialStoreResourceDefinition());
        resourceRegistration.registerSubModel(new SecretKeyCredentialStoreDefinition());

        // TLS Builders
        resourceRegistration.registerSubModel(AdvancedModifiableKeyStoreDecorator.wrap(new KeyStoreDefinition()));
        resourceRegistration.registerSubModel(SSLContextDefinitions.getKeyManagerDefinition());
        resourceRegistration.registerSubModel(SSLContextDefinitions.getTrustManagerDefinition());
        resourceRegistration.registerSubModel(new CertificateAuthorityDefinition());
        resourceRegistration.registerSubModel(new CertificateAuthorityAccountDefinition());
        resourceRegistration.registerSubModel(SSLContextDefinitions.getClientSSLContextDefinition(serverOrHostController));
        resourceRegistration.registerSubModel(SSLContextDefinitions.getServerSSLContextDefinition(serverOrHostController));
    }
    @Override
    public Collection<AttributeDefinition> getAttributes() {
        return Collections.emptyList();
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        OperationStepHandler writeHandler = new ReloadRequiredWriteAttributeHandler(INITIAL_PROVIDERS, FINAL_PROVIDERS, DISALLOWED_PROVIDERS);
        resourceRegistration.registerReadWriteAttribute(SECURITY_PROPERTIES, null, new SecurityPropertiesWriteHandler(SECURITY_PROPERTIES));
        resourceRegistration.registerReadWriteAttribute(DEFAULT_SSL_CONTEXT, null, new ElytronWriteAttributeHandler<Void>(DEFAULT_SSL_CONTEXT) {
            @Override
            protected boolean applyUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                                   ModelNode resolvedValue, ModelNode currentValue,
                                                   HandbackHolder<Void> handbackHolder) throws OperationFailedException {
                if (!resolvedValue.isDefined() && currentValue.isDefined()) {
                    // We can not capture the existing default as by doing so we would trigger it's initialisation which
                    // could fail in a variety of ways as well as the wasted initialisation, if the attribute is being
                    // changed from defined to undefined the only option is to completely restart the process.
                    context.restartRequired();
                    return false;
                }
                return true;
            }

            @Override
            protected void revertUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                                                 ModelNode valueToRestore, ModelNode valueToRevert,
                                                 Void handback) throws OperationFailedException {}

        });
        resourceRegistration.registerReadWriteAttribute(INITIAL_PROVIDERS, null, writeHandler);
        resourceRegistration.registerReadWriteAttribute(FINAL_PROVIDERS, null, writeHandler);
        resourceRegistration.registerReadWriteAttribute(DISALLOWED_PROVIDERS, null, writeHandler);
    }

    @Override
    public void registerAdditionalRuntimePackages(ManagementResourceRegistration resourceRegistration) {
        super.registerAdditionalRuntimePackages(resourceRegistration);
    }


    static <T> ServiceBuilder<T> commonRequirements(ServiceBuilder<T> serviceBuilder, boolean dependOnProperties, boolean dependOnProviderRegistration) {
        if (dependOnProperties) serviceBuilder.requires(SecurityPropertyService.SERVICE_NAME);
        if (dependOnProviderRegistration) serviceBuilder.requires(ProviderRegistrationService.SERVICE_NAME);
        return serviceBuilder;
    }

    private static void installService(ServiceName serviceName, Service service, ServiceTarget serviceTarget) {
        serviceTarget.addService(serviceName)
                .setInstance(service)
                .setInitialMode(Mode.ACTIVE)
                .install();
    }

    private static SecurityPropertyService uninstallSecurityPropertyService(OperationContext context) {
        ServiceRegistry serviceRegistry = context.getServiceRegistry(true);

        ServiceController<?> service = serviceRegistry.getService(SecurityPropertyService.SERVICE_NAME);
        if (service != null) {
            Object serviceImplementation = service.getService();
            context.removeService(service);
            if (serviceImplementation instanceof SecurityPropertyService) {
                return (SecurityPropertyService) serviceImplementation;
            }
        }

        return null;
    }

    private static class ElytronTlsAdd extends AbstractBoottimeAddStepHandler implements ElytronOperationStepHandler  {

        private ElytronTlsAdd() {
            super(INITIAL_PROVIDERS, FINAL_PROVIDERS, DISALLOWED_PROVIDERS, SECURITY_PROPERTIES, DEFAULT_SSL_CONTEXT);
        }

        @Override
        protected void performBoottime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            Map<String, String> securityProperties = SECURITY_PROPERTIES.unwrap(context, model);
            final String defaultSSLContext = DEFAULT_SSL_CONTEXT.resolveModelAttribute(context, model).asStringOrNull();

            ServiceTarget target = context.getServiceTarget();
            installService(SecurityPropertyService.SERVICE_NAME, new SecurityPropertyService(securityProperties), target);

            List<String> disallowedProviders = DISALLOWED_PROVIDERS.unwrap(context, operation);
            ProviderRegistrationService prs = new ProviderRegistrationService(disallowedProviders);
            ServiceBuilder<?> builder = target.addService(ProviderRegistrationService.SERVICE_NAME)
                    .setInstance(prs)
                    .setInitialMode(Mode.ACTIVE);

            String initialProviders = INITIAL_PROVIDERS.resolveModelAttribute(context, model).asStringOrNull();
            if (initialProviders != null) {
                builder.requires(
                        context.getCapabilityServiceName(PROVIDERS_CAPABILITY, initialProviders, Provider[].class));
            }

            String finalProviders = FINAL_PROVIDERS.resolveModelAttribute(context, model).asStringOrNull();
            if (finalProviders != null) {
                builder.requires(
                        context.getCapabilityServiceName(PROVIDERS_CAPABILITY, finalProviders, Provider[].class));
            }
            builder.install();

            if (defaultSSLContext != null) {
                ServiceBuilder<?> serviceBuilder = target
                        .addService(DefaultSSLContextService.SERVICE_NAME)
                        .setInitialMode(Mode.ACTIVE);
                Supplier<SSLContext> defaultSSLContextSupplier = serviceBuilder.requires(
                        context.getCapabilityServiceName(SSL_CONTEXT_CAPABILITY, defaultSSLContext, SSLContext.class));
                Consumer<SSLContext> valueConsumer = serviceBuilder.provides(DefaultSSLContextService.SERVICE_NAME);

                DefaultSSLContextService defaultSSLContextService = new DefaultSSLContextService(defaultSSLContextSupplier, valueConsumer);
                serviceBuilder.setInstance(defaultSSLContextService).install();
            }

            context.addStep(new AbstractDeploymentChainStep() {
                public void execute(DeploymentProcessorTarget processorTarget) {
                    final int DEPENDENCIES_TEMPLATE = 6304;
                    processorTarget.addDeploymentProcessor(ElytronTlsExtension.SUBSYSTEM_NAME, DEPENDENCIES, DEPENDENCIES_TEMPLATE, new DependencyProcessor());
                }
            }, RUNTIME);

            ElytronTLSLogger.LOGGER.activatingSubsystem();
        }

        @Override
        protected void rollbackRuntime(OperationContext context, ModelNode operation, Resource resource) {
            uninstallSecurityPropertyService(context);
            context.removeService(ProviderRegistrationService.SERVICE_NAME);
        }

        @Override
        protected boolean requiresRuntime(final OperationContext context) {
            return isServerOrHostController(context);
        }
    }

    private static class ElytronTlsRemove extends AbstractRemoveStepHandler implements ElytronOperationStepHandler {
        private ElytronTlsRemove() {
            super();
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) {
            if (context.isResourceServiceRestartAllowed()) {
                SecurityPropertyService securityPropertyService = uninstallSecurityPropertyService(context);
                if (securityPropertyService != null) {
                    context.attach(SECURITY_PROPERTY_SERVICE_KEY, securityPropertyService);
                }
                context.removeService(ProviderRegistrationService.SERVICE_NAME);
            } else {
                context.reloadRequired();
            }
        }

        @Override
        protected void recoverServices(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget target = context.getServiceTarget();
            SecurityPropertyService securityPropertyService = context.getAttachment(SECURITY_PROPERTY_SERVICE_KEY);
            if (securityPropertyService != null) {
                installService(SecurityPropertyService.SERVICE_NAME, securityPropertyService, target);
            }
            List<String> providers = DISALLOWED_PROVIDERS.unwrap(context, model);
            installService(ProviderRegistrationService.SERVICE_NAME, new ProviderRegistrationService(providers), target);
        }

        protected boolean requiresRuntime(final OperationContext context) {
            return isServerOrHostController(context);
        }
    }
}
