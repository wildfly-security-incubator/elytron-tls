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

import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.*;
import static org.wildfly.extension.elytron.tls.subsystem.ElytronTlsExtension.getRequiredService;
import static org.wildfly.extension.elytron.tls.subsystem.FileAttributeDefinitions.PATH;
import static org.wildfly.extension.elytron.tls.subsystem.FileAttributeDefinitions.RELATIVE_TO;
import static org.wildfly.extension.elytron.tls.subsystem.FileAttributeDefinitions.pathResolver;
import static org.wildfly.extension.elytron.tls.subsystem.TrivialResourceDefinition.Builder;
import static org.wildfly.extension.elytron.tls.subsystem.TrivialService.ValueSupplier;
import static org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger.LOGGER;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.operations.validation.IntRangeValidator;
import org.jboss.as.controller.operations.validation.StringAllowedValuesValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManagerService;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartException;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.EmptyProvider;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.keystore.AliasFilter;
import org.wildfly.security.keystore.AtomicLoadKeyStore;
import org.wildfly.security.keystore.FilteringKeyStore;
import org.wildfly.security.keystore.KeyStoreUtil;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.provider.util.ProviderUtil;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.DomainlessSSLContextBuilder;
import org.wildfly.security.ssl.Protocol;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.X509RevocationTrustManager;


public class SSLContextDefinitions {
    private static final String[] ALLOWED_PROTOCOLS = { "SSLv2", "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" };

    static final ServiceUtil<SSLContext> SERVER_SERVICE_UTIL = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, Constants.SERVER_SSL_CONTEXT, SSLContext.class);
    static final ServiceUtil<SSLContext> CLIENT_SERVICE_UTIL = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, Constants.CLIENT_SSL_CONTEXT, SSLContext.class);

    static final ObjectTypeAttributeDefinition CREDENTIAL_REFERENCE = CredentialReference.getAttributeDefinition(true);

    static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(Constants.ALGORITHM, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition PROVIDER_NAME = new SimpleAttributeDefinitionBuilder(Constants.PROVIDER_NAME, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition PROVIDERS = new SimpleAttributeDefinitionBuilder(Constants.PROVIDERS, ModelType.STRING, true)
            .setAllowExpression(false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition CIPHER_SUITE_FILTER = new SimpleAttributeDefinitionBuilder(Constants.CIPHER_SUITE_FILTER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setRestartAllServices()
            .setValidator(new Validators.CipherSuiteFilterValidator())
            .setDefaultValue(new ModelNode("DEFAULT"))
            .build();

    static final SimpleAttributeDefinition CIPHER_SUITE_NAMES = new SimpleAttributeDefinitionBuilder(Constants.CIPHER_SUITE_NAMES, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setRestartAllServices()
            .setValidator(new Validators.CipherSuiteNamesValidator())
            // WFCORE-4789: Add the following line back when we are ready to enable TLS 1.3 by default
            //.setDefaultValue(new ModelNode(CipherSuiteSelector.OPENSSL_DEFAULT_CIPHER_SUITE_NAMES))
            .build();

    static final StringListAttributeDefinition PROTOCOLS = new StringListAttributeDefinition.Builder(Constants.PROTOCOLS)
            .setAllowExpression(true)
            .setMinSize(1)
            .setRequired(false)
            .setAllowedValues(ALLOWED_PROTOCOLS)
            .setValidator(new StringAllowedValuesValidator(ALLOWED_PROTOCOLS))
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition WANT_CLIENT_AUTH = new SimpleAttributeDefinitionBuilder(Constants.WANT_CLIENT_AUTH, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(ModelNode.FALSE)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition NEED_CLIENT_AUTH = new SimpleAttributeDefinitionBuilder(Constants.NEED_CLIENT_AUTH, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(ModelNode.FALSE)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition AUTHENTICATION_OPTIONAL = new SimpleAttributeDefinitionBuilder(Constants.AUTHENTICATION_OPTIONAL, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(ModelNode.FALSE)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition USE_CIPHER_SUITES_ORDER = new SimpleAttributeDefinitionBuilder(Constants.USE_CIPHER_SUITES_ORDER, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(ModelNode.TRUE)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition MAXIMUM_SESSION_CACHE_SIZE = new SimpleAttributeDefinitionBuilder(Constants.MAXIMUM_SESSION_CACHE_SIZE, ModelType.INT, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(-1))
            .setValidator(new IntRangeValidator(-1))
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition SESSION_TIMEOUT = new SimpleAttributeDefinitionBuilder(Constants.SESSION_TIMEOUT, ModelType.INT, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(-1))
            .setValidator(new IntRangeValidator(-1))
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition WRAP = new SimpleAttributeDefinitionBuilder(Constants.WRAP, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(ModelNode.FALSE)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition MAXIMUM_CERT_PATH = new SimpleAttributeDefinitionBuilder(Constants.MAXIMUM_CERT_PATH, ModelType.INT, true)
            .setAllowExpression(true)
            .setValidator(new IntRangeValidator(1))
            .setRestartAllServices()
            .build();




    /** KeyStore definitions **/

    static final SimpleAttributeDefinition TYPE = new SimpleAttributeDefinitionBuilder(Constants.TYPE, ModelType.STRING, true)
            .setMinSize(1)
            .setRestartAllServices()
            .setAllowExpression(false)
            .build();

    static final SimpleAttributeDefinition REQUIRED = new SimpleAttributeDefinitionBuilder(Constants.REQUIRED, ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setAllowExpression(true)
            .setRequires(Constants.PATH)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition ALIAS_FILTER = new SimpleAttributeDefinitionBuilder(Constants.ALIAS_FILTER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition KEY_STORE = new ObjectTypeAttributeDefinition.Builder(Constants.KEY_STORE, TYPE, PATH, RELATIVE_TO, REQUIRED, CREDENTIAL_REFERENCE, ALIAS_FILTER, PROVIDER_NAME)
            .setMinSize(1)
            .setRestartAllServices()
            .setAlternatives(Constants.KEY_STORE_REFERENCE)
            .setAllowExpression(false)
            .build();

    static final SimpleAttributeDefinition KEY_STORE_REFERENCE = new SimpleAttributeDefinitionBuilder(Constants.KEY_STORE_REFERENCE, ModelType.STRING, true)
            .setMinSize(1)
            .setCapabilityReference(KEY_STORE_CAPABILITY)
            .setRestartAllServices()
            .setAllowExpression(false)
            .setAlternatives(Constants.KEY_STORE)
            .build();


    /** Revocation definitions **/

    static final SimpleAttributeDefinition RESPONDER_KEYSTORE_REFERENCE = new SimpleAttributeDefinitionBuilder(Constants.RESPONDER_KEYSTORE_REFERENCE, ModelType.STRING, true)
            .setAllowExpression(true)
            .setCapabilityReference(KEY_STORE_CAPABILITY)
            .setRestartAllServices()
            .setAlternatives(Constants.RESPONDER_KEYSTORE)
            .setRequired(false)
            .setRequires(Constants.RESPONDER_CERTIFICATE)
            .build();

    static final ObjectTypeAttributeDefinition RESPONDER_KEYSTORE = new ObjectTypeAttributeDefinition.Builder(Constants.RESPONDER_KEYSTORE, TYPE, PATH, RELATIVE_TO, REQUIRED, CREDENTIAL_REFERENCE, ALIAS_FILTER, PROVIDER_NAME)
            .setRequired(false)
            .setMinSize(1)
            .setAlternatives(Constants.RESPONDER_KEYSTORE_REFERENCE)
            .setRequires(Constants.RESPONDER_CERTIFICATE)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition CERTIFICATE_REVOCATION_LIST = new ObjectTypeAttributeDefinition.Builder(Constants.CERTIFICATE_REVOCATION_LIST, PATH, RELATIVE_TO)
            .setRequired(false)
            .setRestartAllServices()
            .setAlternatives(Constants.CERTIFICATE_REVOCATION_LISTS)
            .build();

    static final ObjectListAttributeDefinition CERTIFICATE_REVOCATION_LISTS = new ObjectListAttributeDefinition.Builder(Constants.CERTIFICATE_REVOCATION_LISTS, CERTIFICATE_REVOCATION_LIST)
            .setRequired(false)
            .setRestartAllServices()
            .setAlternatives(Constants.CERTIFICATE_REVOCATION_LIST)
            .build();


    static final SimpleAttributeDefinition RESPONDER = new SimpleAttributeDefinitionBuilder(Constants.RESPONDER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition PREFER_CRLS = new SimpleAttributeDefinitionBuilder(Constants.PREFER_CRLS, ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setRequired(false)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition SOFT_FAIL = new SimpleAttributeDefinitionBuilder(Constants.SOFT_FAIL, ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setRequired(false)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition ONLY_LEAF_CERT = new SimpleAttributeDefinitionBuilder(Constants.ONLY_LEAF_CERT, ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setRequired(false)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition RESPONDER_CERTIFICATE = new SimpleAttributeDefinitionBuilder(Constants.RESPONDER_CERTIFICATE, ModelType.STRING, true)
            .setAllowExpression(true)
            .setRestartAllServices()
            .setRequired(false)
            .build();

    static final ObjectTypeAttributeDefinition OCSP = new ObjectTypeAttributeDefinition.Builder(Constants.OCSP, RESPONDER, PREFER_CRLS, RESPONDER_CERTIFICATE, RESPONDER_KEYSTORE_REFERENCE, RESPONDER_KEYSTORE)
            .setRequired(false)
            .setRestartAllServices()
            .build();

//    static final SimpleAttributeDefinition GENERATE_SELF_SIGNED_CERTIFICATE_HOST = new SimpleAttributeDefinitionBuilder(Constants.GENERATE_SELF_SIGNED_CERTIFICATE_HOST, ModelType.STRING, true)
//            .setAllowExpression(true)
//            .setMinSize(1)
//            .setRestartAllServices()
//            .build();

    /** KeyManager definitions **/

    static final SimpleAttributeDefinition KEY_MANAGER_REFERENCE = new SimpleAttributeDefinitionBuilder(Constants.KEY_MANAGER_REFERENCE, ModelType.STRING, true)
            .setMinSize(1)
            .setCapabilityReference(KEY_MANAGER_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setRestartAllServices()
            .setAllowExpression(false)
            .setAlternatives(Constants.KEY_MANAGER)
            .build();

    static ObjectTypeAttributeDefinition KEY_MANAGER = new ObjectTypeAttributeDefinition.Builder(Constants.KEY_MANAGER, KEY_STORE, KEY_STORE_REFERENCE, CREDENTIAL_REFERENCE, ALGORITHM, ALIAS_FILTER, PROVIDER_NAME)
            .setRequired(true)
            .setAlternatives(Constants.KEY_MANAGER_REFERENCE)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();


    /** TrustManager definitions **/

    static final SimpleAttributeDefinition TRUST_MANAGER_REFERENCE = new SimpleAttributeDefinitionBuilder(Constants.TRUST_MANAGER_REFERENCE, ModelType.STRING, true)
            .setMinSize(1)
            .setCapabilityReference(TRUST_MANAGER_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setRestartAllServices()
            .setAllowExpression(false)
            .setAlternatives(Constants.TRUST_MANAGER)
            .build();

    static final ObjectTypeAttributeDefinition TRUST_MANAGER = new ObjectTypeAttributeDefinition.Builder(Constants.TRUST_MANAGER, KEY_STORE, KEY_STORE_REFERENCE, ALIAS_FILTER, ALGORITHM, MAXIMUM_CERT_PATH, ONLY_LEAF_CERT, SOFT_FAIL, PROVIDER_NAME, OCSP, CERTIFICATE_REVOCATION_LIST, CERTIFICATE_REVOCATION_LISTS)
            .setRequired(true)
            .setAlternatives(Constants.TRUST_MANAGER_REFERENCE)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();


    static final AttributeDefinition[] CLIENT_ATTRIBUTES = new AttributeDefinition[]{CIPHER_SUITE_FILTER, CIPHER_SUITE_NAMES, PROTOCOLS,/* KEY_MANAGER,*/ KEY_MANAGER_REFERENCE,/* TRUST_MANAGER,*/ TRUST_MANAGER_REFERENCE, PROVIDER_NAME};

    static final AttributeDefinition[] SERVER_ATTRIBUTES = new AttributeDefinition[]{CIPHER_SUITE_FILTER, CIPHER_SUITE_NAMES, PROTOCOLS,/* KEY_MANAGER,*/ KEY_MANAGER_REFERENCE,/* TRUST_MANAGER,*/ TRUST_MANAGER_REFERENCE, PROVIDER_NAME, WANT_CLIENT_AUTH, NEED_CLIENT_AUTH, USE_CIPHER_SUITES_ORDER, MAXIMUM_SESSION_CACHE_SIZE, SESSION_TIMEOUT, WRAP};

    private static final SimpleAttributeDefinition ACTIVE_SESSION_COUNT = new SimpleAttributeDefinitionBuilder(Constants.ACTIVE_SESSION_COUNT, ModelType.INT)
            .setStorageRuntime()
            .build();

    static ResourceDefinition createClientSSLContextDefinition() {
        // TODO: implement
        return null;
    }

    static ResourceDefinition createServerSSLContextDefinition(boolean serverOrHostController) {

        final SimpleAttributeDefinition providersDefinition = new SimpleAttributeDefinitionBuilder(PROVIDERS)
                .setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY)
                .setAllowExpression(false)
                .setRestartAllServices()
                .build();

        final SimpleAttributeDefinition keyManagerDefinition = new SimpleAttributeDefinitionBuilder(KEY_MANAGER)
                .setRequired(true)
                .setRestartAllServices()
                .build();

        AbstractAddStepHandler add = new TrivialAddHandler<SSLContext>(SSLContext.class, ServiceController.Mode.ACTIVE, ServiceController.Mode.PASSIVE, SERVER_ATTRIBUTES, SSL_CONTEXT_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder,
                                                                                OperationContext context, ModelNode model) throws OperationFailedException {

                final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
                final List<String> protocols = PROTOCOLS.unwrap(context, model);
                final String cipherSuiteFilter = CIPHER_SUITE_FILTER.resolveModelAttribute(context, model).asString(); // has default value, can't be null
                final String cipherSuiteNames = CIPHER_SUITE_NAMES.resolveModelAttribute(context, model).asStringOrNull(); // doesn't have a default value yet since we are disabling TLS 1.3 by default
                final boolean wantClientAuth = WANT_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean needClientAuth = NEED_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean useCipherSuitesOrder = USE_CIPHER_SUITES_ORDER.resolveModelAttribute(context, model).asBoolean();
                final int maximumSessionCacheSize = MAXIMUM_SESSION_CACHE_SIZE.resolveModelAttribute(context, model).asInt();
                final int sessionTimeout = SESSION_TIMEOUT.resolveModelAttribute(context, model).asInt();
                final boolean wrap = WRAP.resolveModelAttribute(context, model).asBoolean();

                final ModelNode keyManagerNode = KEY_MANAGER.resolveModelAttribute(context, model);
                final ModelNode trustManagerNode = TRUST_MANAGER.resolveModelAttribute(context, model);

                ExceptionSupplier<KeyManager, Exception> keyManagerSupplier;
                ExceptionSupplier<TrustManager, Exception> trustManagerSupplier = null;

                ServiceBuilder<TrustManager> trustManagerServiceBuilder = null;

                // TODO: implement properly when creating key stores is enabled
//                Supplier<PathManager> pathManagerSupplier = serviceBuilder.requires(PathManagerService.SERVICE_NAME);

                if (keyManagerNode.isDefined()) {
                    keyManagerSupplier = createKeyManager(trustManagerServiceBuilder, context, keyManagerNode, pathManagerSupplier);
                } else {
                    String keyManagerReference = KEY_MANAGER_REFERENCE.resolveModelAttribute(context, model).asStringOrNull();
                    keyManagerSupplier = () -> (KeyManager) serviceBuilder.requires(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(KEY_MANAGER_CAPABILITY, keyManagerReference), KeyManager.class)).get();
                }

                if (trustManagerNode.isDefined()) {
                    trustManagerSupplier = createTrustManager(trustManagerServiceBuilder, context, keyManagerNode, pathManagerSupplier);
                } else {
                    String keyManagerReference = KEY_MANAGER_REFERENCE.resolveModelAttribute(context, model).asStringOrNull();
                    keyManagerSupplier = () -> (KeyManager) serviceBuilder.requires(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(KEY_MANAGER_CAPABILITY, keyManagerReference), KeyManager.class)).get();
                }

                final ExceptionSupplier<KeyManager, Exception> finalKeyManagerSupplier = keyManagerSupplier;
                final ExceptionSupplier<TrustManager, Exception> finalTrustManagerSupplier = trustManagerSupplier;

                return () -> {
                    X509ExtendedKeyManager keyManager = getX509KeyManager(finalKeyManagerSupplier.get());
                    X509ExtendedTrustManager trustManager = getX509TrustManager(finalTrustManagerSupplier.get());
                    Provider[] providers = Security.getProviders();

                    DomainlessSSLContextBuilder builder = new DomainlessSSLContextBuilder();
                    if (keyManager != null)
                        builder.setKeyManager(keyManager);
                    if (trustManager != null)
                        builder.setTrustManager(trustManager);
                    if (providers != null)
                        builder.setProviderSupplier(() -> providers);
                    builder.setCipherSuiteSelector(CipherSuiteSelector.aggregate(cipherSuiteNames != null ? CipherSuiteSelector.fromNamesString(cipherSuiteNames) : null, CipherSuiteSelector.fromString(cipherSuiteFilter)));
                    if (!protocols.isEmpty()) {
                        List<Protocol> list = new ArrayList<>();
                        for (String protocol : protocols) {
                            Protocol forName = Protocol.forName(protocol);
                            list.add(forName);
                        }
                        builder.setProtocolSelector(ProtocolSelector.empty().add(EnumSet.copyOf(list)));
                    }
                    builder.setWantClientAuth(wantClientAuth)
                            .setNeedClientAuth(needClientAuth)
                            .setUseCipherSuitesOrder(useCipherSuitesOrder)
                            .setSessionCacheSize(maximumSessionCacheSize)
                            .setSessionTimeout(sessionTimeout)
                            .setWrap(wrap);

                    if (LOGGER.isTraceEnabled()) {
                        LOGGER.tracef(
                                "ServerSSLContext supplying:  keyManager = %s  trustManager = %s  "
                                        + "providers = %s  cipherSuiteFilter = %s  cipherSuiteNames = %s protocols = %s  wantClientAuth = %s  needClientAuth = %s  "
                                        + "maximumSessionCacheSize = %s  sessionTimeout = %s wrap = %s",
                                keyManager, trustManager, Arrays.toString(providers), cipherSuiteFilter, cipherSuiteNames,
                                Arrays.toString(protocols.toArray()), wantClientAuth, needClientAuth,
                                maximumSessionCacheSize, sessionTimeout, wrap);
                    }

                    try {
                        return builder.build().create();
                    } catch (GeneralSecurityException e) {
                        throw new StartException(e);
                    }
                };
            }

            @Override
            protected Resource createResource(OperationContext context) {
                SSLContextResource resource = new SSLContextResource(Resource.Factory.create(), true);
                context.addResource(PathAddress.EMPTY_ADDRESS, resource);
                return resource;
            }

            @Override
            protected void installedForResource(ServiceController<SSLContext> serviceController, Resource resource) {
                ((SSLContextResource) resource).setSSLContextServiceController(serviceController);
            }

        };

        return createSSLContextDefinition(Constants.SERVER_SSL_CONTEXT, true, add, SERVER_ATTRIBUTES, serverOrHostController);
    }


    private static ExceptionSupplier<TrustManager, Exception> createTrustManager(ServiceBuilder<TrustManager> serviceBuilder, OperationContext context, ModelNode model, Supplier<PathManager> pathManager) throws OperationFailedException {
        final ModelNode keyStoreNode = KEY_STORE.resolveModelAttribute(context, model);
        final String keyStoreReference = KEY_STORE_REFERENCE.resolveModelAttribute(context, model).asStringOrNull();
        final ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier = CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);
        final String algorithmName = ALGORITHM.resolveModelAttribute(context, model).asStringOrNull();
        final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
        final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();

        ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;

        if (keyStoreReference != null) {
            if (keyStoreNode != null) {
                throw LOGGER.multipleKeystoreDefinitions();
            }
            keyStoreSupplier = () -> (KeyStore) serviceBuilder.requires(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(KEY_STORE_CAPABILITY, keyStoreReference), KeyStore.class)).get();
        } else {
            if (keyStoreNode == null) {
                throw LOGGER.missingKeyStoreDefinition();
            }
            keyStoreSupplier = createKeyStore(serviceBuilder, context, keyStoreNode, pathManager);
        }

        final String algorithm = algorithmName != null ? algorithmName : TrustManagerFactory.getDefaultAlgorithm();

        if (model.hasDefined(CERTIFICATE_REVOCATION_LIST.getName()) || model.hasDefined(OCSP.getName()) || model.hasDefined(CERTIFICATE_REVOCATION_LISTS.getName())) {
            return createX509RevocationTrustManager(serviceBuilder, context, model, algorithm, providerName, keyStoreSupplier, aliasFilter, pathManager);
        }

        DelegatingTrustManager delegatingTrustManager = new DelegatingTrustManager();
        return () -> {
            TrustManagerFactory trustManagerFactory = null;

            for (Provider current : Security.getProviders()) {
                if (providerName == null || providerName.equals(current.getName())) {
                    try {
                        trustManagerFactory =  TrustManagerFactory.getInstance(algorithm, current);
                    } catch (NoSuchAlgorithmException ignored) {
                    }
                }
            }
            if (trustManagerFactory == null) {
                throw LOGGER.unableToCreateManagerFactory(TrustManagerFactory.class.getSimpleName(), algorithm);
            }

            KeyStore keyStore = keyStoreSupplier.get();

            try {
                if (aliasFilter != null) {
                    keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
                }

                trustManagerFactory.init(keyStore);
            } catch (Exception e) {
                throw new StartException(e);
            }

            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            for (TrustManager trustManager : trustManagers) {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    delegatingTrustManager.setTrustManager((X509ExtendedTrustManager) trustManager);
                    return delegatingTrustManager;
                }
            }
            throw LOGGER.noTypeFound(X509ExtendedKeyManager.class.getSimpleName());
        };
    }

    private static ExceptionSupplier<TrustManager, Exception> createX509RevocationTrustManager(ServiceBuilder<TrustManager> serviceBuilder, OperationContext context,
                                                                         ModelNode model, String algorithm, String providerName, ExceptionSupplier<KeyStore, Exception> keyStoreSupplier, String aliasFilter, Supplier<PathManager> pathManager) throws OperationFailedException {

        ModelNode crlNode = CERTIFICATE_REVOCATION_LIST.resolveModelAttribute(context, model);
        ModelNode ocspNode = OCSP.resolveModelAttribute(context, model);
        ModelNode multipleCrlsNode = CERTIFICATE_REVOCATION_LISTS.resolveModelAttribute(context, model);
        boolean softFail = SOFT_FAIL.resolveModelAttribute(context, model).asBoolean();
        boolean onlyLeafCert = ONLY_LEAF_CERT.resolveModelAttribute(context, model).asBoolean();
        Integer maxCertPath = MAXIMUM_CERT_PATH.resolveModelAttribute(context, model).asIntOrNull();

        String crlPath = null;
        String crlRelativeTo = null;
        List<CrlFile> crlFiles = new ArrayList<>();

        if (crlNode.isDefined()) {
            crlPath = PATH.resolveModelAttribute(context, crlNode).asStringOrNull();
            crlRelativeTo = RELATIVE_TO.resolveModelAttribute(context, crlNode).asStringOrNull();

            if (crlPath != null) {
                crlFiles.add(new CrlFile(crlPath, crlRelativeTo, pathManager));
            }
        } else if (multipleCrlsNode.isDefined()) {
            for (ModelNode crl : multipleCrlsNode.asList()) {
                crlPath = PATH.resolveModelAttribute(context, crl).asStringOrNull();
                crlRelativeTo = RELATIVE_TO.resolveModelAttribute(context, crl).asStringOrNull();
                if (crlPath != null) {
                    crlFiles.add(new CrlFile(crlPath, crlRelativeTo, pathManager));
                }
            }
        }

        boolean preferCrls = PREFER_CRLS.resolveModelAttribute(context, ocspNode).asBoolean(false);
        String responder = RESPONDER.resolveModelAttribute(context, ocspNode).asStringOrNull();
        String responderCertAlias = RESPONDER_CERTIFICATE.resolveModelAttribute(context, ocspNode).asStringOrNull();
        String responderKeystore = RESPONDER_KEYSTORE.resolveModelAttribute(context, ocspNode).asStringOrNull();

        final ExceptionSupplier<KeyStore, Exception> responderStoreSupplier = responderKeystore != null ? () -> (KeyStore) serviceBuilder.requires(context.getCapabilityServiceName(
                buildDynamicCapabilityName(KEY_STORE_CAPABILITY, responderKeystore), KeyStore.class)) : keyStoreSupplier;

        URI responderUri;
        try {
            responderUri = responder == null ? null : new URI(responder);
        } catch (Exception e) {
            throw new OperationFailedException(e);
        }

        X509RevocationTrustManager.Builder builder = X509RevocationTrustManager.builder();
        builder.setResponderURI(responderUri);
        builder.setSoftFail(softFail);
        builder.setOnlyEndEntity(onlyLeafCert);
        if (maxCertPath != null) {
            builder.setMaxCertPath(maxCertPath.intValue());
        }
        if (model.hasDefined(CERTIFICATE_REVOCATION_LIST.getName()) || model.hasDefined(CERTIFICATE_REVOCATION_LISTS.getName())) {
            if (!model.hasDefined(OCSP.getName())) {
                builder.setPreferCrls(true);
                builder.setNoFallback(true);
            }
        }
        if (model.hasDefined(OCSP.getName())) {
            builder.setResponderURI(responderUri);
            if (!model.hasDefined(CERTIFICATE_REVOCATION_LIST.getName()) && !model.hasDefined(CERTIFICATE_REVOCATION_LISTS.getName())) {
                builder.setPreferCrls(false);
                builder.setNoFallback(true);
            } else {
                builder.setPreferCrls(preferCrls);
            }
        }
        final List<CrlFile> finalCrlFiles = crlFiles;
        return () -> {
            TrustManagerFactory trustManagerFactory = createTrustManagerFactory(Security.getProviders(), providerName, algorithm);
            KeyStore keyStore = keyStoreSupplier.get();

            if (aliasFilter != null) {
                try {
                    keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
                } catch (Exception e) {
                    throw new StartException(e);
                }
            }

            if (responderCertAlias != null) {
                KeyStore responderStore = responderStoreSupplier.get();
                try {
                    builder.setOcspResponderCert((X509Certificate) responderStore.getCertificate(responderCertAlias));
                } catch (KeyStoreException e) {
                    throw LOGGER.failedToLoadResponderCert(responderCertAlias, e);
                }
            }

            builder.setTrustStore(keyStore);
            builder.setTrustManagerFactory(trustManagerFactory);

            if (! finalCrlFiles.isEmpty()) {
                List<InputStream> finalCrlStreams = getCrlStreams(finalCrlFiles);
                builder.setCrlStreams(finalCrlStreams);
                return createReloadableX509CRLTrustManager(finalCrlFiles, builder);
            }
            return builder.build();
        };
    }

    private static List<InputStream> getCrlStreams(List<CrlFile> crlFiles) throws StartException {
        List<InputStream> crlStreams = new ArrayList<>();
        for (CrlFile crl : crlFiles) {
            try {
                crlStreams.add(new FileInputStream(resolveFileLocation(crl.getCrlPath(), crl.getRelativeTo(), crl.getPathManagerSupplier())));
            } catch (FileNotFoundException e) {
                throw LOGGER.unableToAccessCRL(e);
            }
        }
        return crlStreams;
    }

    private static File resolveFileLocation(String path, String relativeTo, Supplier<PathManager> pathManagerSupplier) {
        final File resolvedPath;
        if (relativeTo != null) {
            PathManager pathManager = pathManagerSupplier.get();
            resolvedPath = new File(pathManager.resolveRelativePathEntry(path, relativeTo));
        } else {
            resolvedPath = new File(path);
        }
        return resolvedPath;
    }

    private static TrustManagerFactory createTrustManagerFactory(Provider[] providers, String providerName, String algorithm) throws StartException {
        TrustManagerFactory trustManagerFactory = null;

        if (providers != null) {
            for (Provider current : providers) {
                if (providerName == null || providerName.equals(current.getName())) {
                    try {
                        return TrustManagerFactory.getInstance(algorithm, current);
                    } catch (NoSuchAlgorithmException ignored) {
                    }
                }
            }
            if (trustManagerFactory == null)
                throw LOGGER.unableToCreateManagerFactory(TrustManagerFactory.class.getSimpleName(), algorithm);
        }

        try {
            return TrustManagerFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new StartException(e);
        }
    }

    private static TrustManager createReloadableX509CRLTrustManager(final List<CrlFile> crlFiles, final X509RevocationTrustManager.Builder builder) {
        return new ReloadableX509ExtendedTrustManager() {

            private volatile X509ExtendedTrustManager delegate = builder.build();
            private AtomicBoolean reloading = new AtomicBoolean();

            @Override
            void reload() {
                if (reloading.compareAndSet(false, true)) {
                    try {
                        builder.setCrlStreams(getCrlStreams(crlFiles));
                        delegate = builder.build();
                    } catch (StartException cause) {
                        throw LOGGER.unableToReloadCRL(cause);
                    } finally {
                        reloading.lazySet(false);
                    }
                }
            }

            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
                delegate.checkClientTrusted(x509Certificates, s, socket);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
                delegate.checkServerTrusted(x509Certificates, s, socket);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
                delegate.checkClientTrusted(x509Certificates, s, sslEngine);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
                delegate.checkServerTrusted(x509Certificates, s, sslEngine);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                delegate.checkClientTrusted(x509Certificates, s);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                delegate.checkServerTrusted(x509Certificates, s);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return delegate.getAcceptedIssuers();
            }
        };
    }

    private static ExceptionSupplier<KeyManager, Exception> createKeyManager(ServiceBuilder<TrustManager> serviceBuilder, OperationContext context, ModelNode model, Supplier<PathManager> pathManager) throws OperationFailedException {
        final ModelNode keyStoreNode = KEY_STORE.resolveModelAttribute(context, model);
        final String keyStoreReference = KEY_STORE_REFERENCE.resolveModelAttribute(context, model).asStringOrNull();
        final ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier = CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);
        final String algorithm = ALGORITHM.resolveModelAttribute(context, model).asStringOrNull();
        final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
        final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();

        ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;

        if (keyStoreReference != null) {
            if (keyStoreNode != null) {
                throw LOGGER.multipleKeystoreDefinitions();
            }
            keyStoreSupplier = () -> (KeyStore) serviceBuilder.requires(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(KEY_STORE_CAPABILITY, keyStoreReference), KeyStore.class)).get();
        } else {
            if (keyStoreNode == null) {
                throw LOGGER.missingKeyStoreDefinition();
            }
            keyStoreSupplier = createKeyStore(serviceBuilder, context, keyStoreNode, pathManager);
        }

        return () -> {
            Provider[] providers = Security.getProviders();
            KeyManagerFactory keyManagerFactory = null;
            if (providers != null) {
                for (Provider current : providers) {
                    if (providerName == null || providerName.equals(current.getName())) {
                        try {
                            keyManagerFactory = KeyManagerFactory.getInstance(algorithm, current);
                            break;
                        } catch (NoSuchAlgorithmException ignored) {
                        }
                    }
                }
                if (keyManagerFactory == null)
                    throw LOGGER.unableToCreateManagerFactory(KeyManagerFactory.class.getSimpleName(), algorithm);
            } else {
                try {
                    keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
                } catch (NoSuchAlgorithmException e) {
                    throw new StartException(e);
                }
            }

            KeyStore keyStore = keyStoreSupplier.get();
            char[] password;
            try {
                CredentialSource cs = credentialSourceSupplier.get();
                if (cs != null) {
                    password = cs.getCredential(PasswordCredential.class).getPassword(ClearPassword.class).getPassword();
                } else {
                    throw new StartException(LOGGER.keyStorePasswordCannotBeResolved(KEY_STORE_REFERENCE.resolveModelAttribute(context, keyStoreNode).asStringOrNull()));
                }
            } catch (StartException e) {
                throw e;
            } catch (Exception e) {
                throw new StartException(e);
            }

            try {
                DelegatingKeyManager delegating = new DelegatingKeyManager();
                if (aliasFilter != null) {
                    keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
                }
                keyManagerFactory.init(keyStore, password);
                KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
                for (KeyManager keyManager : keyManagers) {
                    if (keyManager instanceof X509ExtendedKeyManager) {
                        delegating.setKeyManager((X509ExtendedKeyManager) keyManager);
                        return delegating;
                    }
                }
            } catch (Exception e) {
                throw new StartException(e);
            }
            throw LOGGER.noTypeFound(X509ExtendedKeyManager.class.getSimpleName());
        };
    }

    private static X509ExtendedKeyManager getX509KeyManager(KeyManager keyManager) throws StartException {
        if (keyManager == null) {
            return null;
        }
        if (keyManager instanceof X509ExtendedKeyManager) {
            X509ExtendedKeyManager x509KeyManager = (X509ExtendedKeyManager) keyManager;
            return x509KeyManager;
        }
        throw LOGGER.invalidTypeInjected(X509ExtendedKeyManager.class.getSimpleName());
    }

    private static X509ExtendedTrustManager getX509TrustManager(TrustManager trustManager) throws StartException {
        if (trustManager == null) {
            return null;
        }
        if (trustManager instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509TrustManager = (X509ExtendedTrustManager) trustManager;
            return x509TrustManager;
        }
        throw LOGGER.invalidTypeInjected(X509ExtendedTrustManager.class.getSimpleName());
    }


    private abstract static class ReloadableX509ExtendedTrustManager extends X509ExtendedTrustManager {
        abstract void reload();
    }

    private static class DelegatingTrustManager extends X509ExtendedTrustManager {

        private final AtomicReference<X509ExtendedTrustManager> delegating = new AtomicReference<>();

        public void setTrustManager(X509ExtendedTrustManager trustManager){
            delegating.set(trustManager);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
            delegating.get().checkClientTrusted(x509Certificates, s, socket);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
            delegating.get().checkServerTrusted(x509Certificates, s, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
            delegating.get().checkClientTrusted(x509Certificates, s, sslEngine);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
            delegating.get().checkServerTrusted(x509Certificates, s, sslEngine);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            delegating.get().checkClientTrusted(x509Certificates, s);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            delegating.get().checkServerTrusted(x509Certificates, s);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegating.get().getAcceptedIssuers();
        }
    }

    private static class DelegatingKeyManager extends X509ExtendedKeyManager {

        private final AtomicReference<X509ExtendedKeyManager> delegating = new AtomicReference<>();

        private void setKeyManager(X509ExtendedKeyManager keyManager) {
            delegating.set(keyManager);
        }

        @Override
        public String[] getClientAliases(String s, Principal[] principals) {
            return delegating.get().getClientAliases(s, principals);
        }

        @Override
        public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
            return delegating.get().chooseClientAlias(strings, principals, socket);
        }

        @Override
        public String[] getServerAliases(String s, Principal[] principals) {
            return delegating.get().getServerAliases(s, principals);
        }

        @Override
        public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
            return delegating.get().chooseServerAlias(s, principals, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(String s) {
            return delegating.get().getCertificateChain(s);
        }

        @Override
        public PrivateKey getPrivateKey(String s) {
            return delegating.get().getPrivateKey(s);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return delegating.get().chooseEngineClientAlias(keyType, issuers, engine);
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return delegating.get().chooseEngineServerAlias(keyType, issuers, engine);
        }
    }

    private static ExceptionSupplier<KeyStore, Exception> createKeyStore(ServiceBuilder<TrustManager> serviceBuilder, OperationContext context, ModelNode model, Supplier<PathManager> pathManager) throws OperationFailedException {
        final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
        final String type = TYPE.resolveModelAttribute(context, model).asStringOrNull();
        final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
        final String path = PATH.resolveModelAttribute(context, model).asStringOrNull();
        final String relativeTo = RELATIVE_TO.resolveModelAttribute(context, model).asStringOrNull();
        final boolean required = REQUIRED.resolveModelAttribute(context, model).asBoolean(false);
        final ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier = CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);

        ExceptionSupplier<KeyStore, Exception> res = () -> {
            AtomicLoadKeyStore keyStore = null;
            FileAttributeDefinitions.PathResolver pathResolver;
            File resolvedPath = null;
            Provider provider = null;

            if (type != null) {
                provider = resolveProviders(providerName, KeyStore.class, type);
                keyStore = AtomicLoadKeyStore.newInstance(type, provider);
            }

            if (path != null) {
                pathResolver = pathResolver();
                pathResolver.path(path);
                if (relativeTo != null) {
                    pathResolver.relativeTo(relativeTo, pathManager.get());
                }
                resolvedPath = pathResolver.resolve();
            }

            if (resolvedPath != null && ! resolvedPath.exists()) {
                if (required) {
                    if (type == null) {
                        throw LOGGER.nonexistingKeyStoreMissingType();
                    } else {
                        throw LOGGER.keyStoreFileNotExists(resolvedPath.getAbsolutePath());
                    }
                } else {
                    LOGGER.keyStoreFileNotExistsButIgnored(resolvedPath.getAbsolutePath());
                }
            }

            try (FileInputStream is = (resolvedPath != null && resolvedPath.exists()) ? new FileInputStream(resolvedPath) : null) {
                CredentialSource cs = credentialSourceSupplier != null ? credentialSourceSupplier.get() : null;
                if (cs == null) {
                    throw LOGGER.keyStorePasswordCannotBeResolved(path);
                }
                PasswordCredential credential = cs.getCredential(PasswordCredential.class);
                if (credential == null) {
                    throw LOGGER.keyStorePasswordCannotBeResolved(path);
                }
                ClearPassword clearPassword = credential.getPassword(ClearPassword.class);
                if (clearPassword == null) {
                    throw LOGGER.keyStorePasswordCannotBeResolved(path);
                }

                char[] password = clearPassword.getPassword();

                if (is != null) {
                    if (type != null) {
                        keyStore.load(is, password);
                    } else {
                        KeyStore detected = KeyStoreUtil.loadKeyStore(() -> Security.getProviders(), providerName, is, resolvedPath.getPath(), password);

                        if (detected == null) {
                            throw LOGGER.unableToDetectKeyStore(resolvedPath.getPath());
                        }

                        keyStore = AtomicLoadKeyStore.atomize(detected);
                    }
                } else {
                    if (keyStore == null) {
                        String defaultType = KeyStore.getDefaultType();
                        LOGGER.debugf("KeyStore: provider = %s  path = %s  resolvedPath = %s  password = %b  aliasFilter = %s does not exist. New keystore of %s type will be created.",
                                provider, path, resolvedPath, password != null, aliasFilter, defaultType
                        );
                        keyStore = AtomicLoadKeyStore.newInstance(defaultType);
                    }

                    synchronized (EmptyProvider.getInstance()) {
                        keyStore.load(null, password);
                    }
                }
            }
            return keyStore;
        };

        return res;
    }

    private static Provider resolveProviders(String name, Class type, String alg) throws StartException {
        Provider provider = ProviderUtil.findProvider(Security.getProviders(), name, type, alg);
        if (provider == null) {
            throw LOGGER.noSuitableProvider(alg);
        }
        return provider;
    }

    abstract static class SSLContextRuntimeHandler extends ElytronRuntimeOnlyHandler {
        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            ServiceName serviceName = getSSLContextServiceUtil().serviceName(operation);

            ServiceController<SSLContext> serviceController = getRequiredService(context.getServiceRegistry(false), serviceName, SSLContext.class);
            ServiceController.State serviceState;
            if ((serviceState = serviceController.getState()) != ServiceController.State.UP) {
                throw LOGGER.requiredServiceNotUp(serviceName, serviceState);
            }

            performRuntime(context.getResult(), operation, serviceController.getService().getValue());
        }

        protected abstract void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException;

        protected abstract ServiceUtil<SSLContext> getSSLContextServiceUtil();
    }

    private static ResourceDefinition createSSLContextDefinition(String pathKey, boolean server, AbstractAddStepHandler addHandler, AttributeDefinition[] attributes, boolean serverOrHostController) {
        /* The original method used SimpleResourceDefinition and would return an object from SSLContextResourceDefinition(parameters, attributes)
         * This was likely planned to replace a variety of other classes (like TrivialResourceDefinition) */
        // TODO: Simplify and reimplement _Trivial_ classes with native subsystem versions

//        SimpleResourceDefinition.Parameters parameters = new SimpleResourceDefinition.Parameters(PathElement.pathElement(pathKey), ElytronTlsExtension.getResourceDescriptionResolver(pathKey))
//                .setAddHandler(addHandler)
//                .setCapabilities(SSL_CONTEXT_RUNTIME_CAPABILITY)
//                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
//                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES);

        Builder builder = TrivialResourceDefinition.builder()
                .setPathKey(pathKey)
                .setAddHandler(addHandler)
                .setAttributes(attributes)
                .setRuntimeCapabilities(SSL_CONTEXT_RUNTIME_CAPABILITY);

        if (serverOrHostController) {
            builder.addReadOnlyAttribute(ACTIVE_SESSION_COUNT, new SSLContextRuntimeHandler() {
                @Override
                protected void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException {
                    SSLSessionContext sessionContext = server ? sslContext.getServerSessionContext() : sslContext.getClientSessionContext();
                    int sum = 0;
                    for (byte[] b : Collections.list(sessionContext.getIds())) {
                        int i = 1;
                        sum += i;
                    }
                    result.set(sum);
                }

                @Override
                protected ServiceUtil<SSLContext> getSSLContextServiceUtil() {
                    return server ? SERVER_SERVICE_UTIL : CLIENT_SERVICE_UTIL;
                }
            }).addChild(new SSLSessionDefinition(server));
        }

        return builder.build();
    }

    static class CrlFile {
        private String crlPath = null;
        private String relativeTo = null;
        private Supplier<PathManager> pathManagerSupplier = null;

        public CrlFile(final String crlPath, final String relativeTo, Supplier<PathManager> pathManagerSupplier) {
            this.crlPath = crlPath;
            this.relativeTo = relativeTo;
            this.pathManagerSupplier = pathManagerSupplier;
        }

        public String getCrlPath() {
            return crlPath;
        }

        public String getRelativeTo() {
            return relativeTo;
        }

        public Supplier<PathManager> getPathManagerSupplier() {
            return pathManagerSupplier;
        }
    }

}
