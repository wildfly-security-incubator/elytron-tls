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

import static org.jboss.as.controller.AbstractControllerService.PATH_MANAGER_CAPABILITY;
import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.jboss.as.controller.security.CredentialReference.handleCredentialReferenceUpdate;
import static org.jboss.as.controller.security.CredentialReference.rollbackCredentialStoreUpdate;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.KEY_MANAGER_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.KEY_MANAGER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.KEY_STORE_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.KEY_STORE_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.TRUST_MANAGER_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.Capabilities.TRUST_MANAGER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.tls.subsystem.ElytronTlsExtension.getRequiredService;
import static org.wildfly.extension.elytron.tls.subsystem.FileAttributeDefinitions.PATH;
import static org.wildfly.extension.elytron.tls.subsystem.FileAttributeDefinitions.RELATIVE_TO;
import static org.wildfly.extension.elytron.tls.subsystem.FileAttributeDefinitions.pathName;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
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
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleOperationDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.descriptions.ResourceDescriptionResolver;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.operations.validation.IntRangeValidator;
import org.jboss.as.controller.operations.validation.StringAllowedValuesValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
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


/**
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class SSLContextDefinitions {

    static final ServiceUtil<SSLContext> SERVER_SERVICE_UTIL = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, Constants.SERVER_SSL_CONTEXT, SSLContext.class);
    static final ServiceUtil<SSLContext> CLIENT_SERVICE_UTIL = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, Constants.CLIENT_SSL_CONTEXT, SSLContext.class);

    static final ObjectTypeAttributeDefinition CREDENTIAL_REFERENCE = CredentialReference.getAttributeDefinition(true);

    /** Base attribute definitions */

    static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(Constants.ALGORITHM, ModelType.STRING, true)
            .setMinSize(1)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition CIPHER_SUITE_FILTER = new SimpleAttributeDefinitionBuilder(Constants.CIPHER_SUITE_FILTER, ModelType.STRING, true)
            .setMinSize(1)
            .setDefaultValue(new ModelNode("DEFAULT"))
            .setValidator(new Validators.CipherSuiteFilterValidator())
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition CIPHER_SUITE_NAMES = new SimpleAttributeDefinitionBuilder(Constants.CIPHER_SUITE_NAMES, ModelType.STRING, true)
            .setMinSize(1)
            .setValidator(new Validators.CipherSuiteNamesValidator())
            // WFCORE-4789: Add the following line back when we are ready to enable TLS 1.3 by default
            //.setDefaultValue(new ModelNode(CipherSuiteSelector.OPENSSL_DEFAULT_CIPHER_SUITE_NAMES))
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    private static final String[] ALLOWED_PROTOCOLS = { "SSLv2", "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" };

    static final StringListAttributeDefinition PROTOCOLS = new StringListAttributeDefinition.Builder(Constants.PROTOCOLS)
            .setMinSize(1)
            .setRequired(false)
            .setValidator(new StringAllowedValuesValidator(ALLOWED_PROTOCOLS))
            .setAllowedValues(ALLOWED_PROTOCOLS)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition WANT_CLIENT_AUTH = new SimpleAttributeDefinitionBuilder(Constants.WANT_CLIENT_AUTH, ModelType.BOOLEAN, true)
            .setMinSize(1)
            .setDefaultValue(ModelNode.FALSE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition NEED_CLIENT_AUTH = new SimpleAttributeDefinitionBuilder(Constants.NEED_CLIENT_AUTH, ModelType.BOOLEAN, true)
            .setMinSize(1)
            .setDefaultValue(ModelNode.FALSE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition AUTHENTICATION_OPTIONAL = new SimpleAttributeDefinitionBuilder(Constants.AUTHENTICATION_OPTIONAL, ModelType.BOOLEAN, true)
            .setMinSize(1)
            .setDefaultValue(ModelNode.FALSE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition USE_CIPHER_SUITES_ORDER = new SimpleAttributeDefinitionBuilder(Constants.USE_CIPHER_SUITES_ORDER, ModelType.BOOLEAN, true)
            .setMinSize(1)
            .setDefaultValue(ModelNode.TRUE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition MAXIMUM_SESSION_CACHE_SIZE = new SimpleAttributeDefinitionBuilder(Constants.MAXIMUM_SESSION_CACHE_SIZE, ModelType.INT, true)
            .setValidator(new IntRangeValidator(-1))
            .setDefaultValue(new ModelNode(-1))
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition SESSION_TIMEOUT = new SimpleAttributeDefinitionBuilder(Constants.SESSION_TIMEOUT, ModelType.INT, true)
            .setValidator(new IntRangeValidator(-1))
            .setDefaultValue(new ModelNode(-1))
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition WRAP = new SimpleAttributeDefinitionBuilder(Constants.WRAP, ModelType.BOOLEAN, true)
            .setDefaultValue(ModelNode.FALSE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition MAXIMUM_CERT_PATH = new SimpleAttributeDefinitionBuilder(Constants.MAXIMUM_CERT_PATH, ModelType.INT, true)
            .setValidator(new IntRangeValidator(1))
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition GENERATE_SELF_SIGNED_CERTIFICATE_HOST = new SimpleAttributeDefinitionBuilder(Constants.GENERATE_SELF_SIGNED_CERTIFICATE_HOST, ModelType.STRING, true)
            .setMinSize(1)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    /** Provider definitions */

    static final SimpleAttributeDefinition PROVIDER_NAME = new SimpleAttributeDefinitionBuilder(Constants.PROVIDER_NAME, ModelType.STRING, true)
            .setMinSize(1)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition PROVIDERS = new SimpleAttributeDefinitionBuilder(Constants.PROVIDERS, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setAllowExpression(false)
            .build();


    static final SimpleAttributeDefinition providersKMDefinition = new SimpleAttributeDefinitionBuilder(PROVIDERS)
            .setCapabilityReference(PROVIDERS_CAPABILITY, KEY_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();


    static final SimpleAttributeDefinition providersTMDefinition = new SimpleAttributeDefinitionBuilder(PROVIDERS)
            .setCapabilityReference(PROVIDERS_CAPABILITY, TRUST_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();


    /** KeyStore definitions **/

    static final SimpleAttributeDefinition TYPE = new SimpleAttributeDefinitionBuilder(Constants.TYPE, ModelType.STRING, true)
            .setMinSize(1)
            .setAttributeGroup(Constants.IMPLEMENTATION)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition REQUIRED = new SimpleAttributeDefinitionBuilder(Constants.REQUIRED, ModelType.BOOLEAN, true)
            .setRequires(Constants.PATH)
            .setAttributeGroup(Constants.FILE)
            .setDefaultValue(ModelNode.FALSE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition ALIAS_FILTER = new SimpleAttributeDefinitionBuilder(Constants.ALIAS_FILTER, ModelType.STRING, true)
            .setMinSize(1)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    /* Since XSD doesn't support providing a choice between 2 attributes, validation is done in the definition.
     * This applies to all types of key stores, key managers, and trust managers
     * TODO: potentially move validation into XML schema */

    static final SimpleAttributeDefinition KEY_STORE = new SimpleAttributeDefinitionBuilder(Constants.KEY_STORE, ModelType.STRING, true)
            .setMinSize(1)
            .setRequired(true)
            // .setAlternatives(Constants.KEY_STORE_OBJECT)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setAllowExpression(false)
            .build();
            
    static final SimpleAttributeDefinition keystoreKMDefinition = new SimpleAttributeDefinitionBuilder(KEY_STORE)
            .setCapabilityReference(KEY_STORE_CAPABILITY, KEY_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition keystoreTMDefinition = new SimpleAttributeDefinitionBuilder(KEY_STORE)
            .setCapabilityReference(KEY_STORE_CAPABILITY, TRUST_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();


    static final ObjectTypeAttributeDefinition KEY_STORE_OBJECT = new ObjectTypeAttributeDefinition.Builder(Constants.KEY_STORE_OBJECT, TYPE,
                PATH, RELATIVE_TO, REQUIRED, CREDENTIAL_REFERENCE, ALIAS_FILTER, KeyStoreDefinition.PROVIDER_NAME, KeyStoreDefinition.PROVIDERS)
            .setMinSize(1)
            .setRequired(true)
            .setAlternatives(Constants.KEY_STORE)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition keystoreKMObjectDefinition = new ObjectTypeAttributeDefinition.Builder(Constants.KEY_STORE_OBJECT, KEY_STORE_OBJECT)
            .setCapabilityReference(KEY_STORE_CAPABILITY, TRUST_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();
            
    static final ObjectTypeAttributeDefinition keystoreTMObjectDefinition = new ObjectTypeAttributeDefinition.Builder(Constants.KEY_STORE_OBJECT, KEY_STORE_OBJECT)
            .setCapabilityReference(KEY_STORE_CAPABILITY, TRUST_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    /** Revocation definitions */

    static final SimpleAttributeDefinition RESPONDER_KEYSTORE = new SimpleAttributeDefinitionBuilder(Constants.RESPONDER_KEYSTORE, ModelType.STRING, true)
            .setRequired(false)
            // .setAlternatives(Constants.RESPONDER_KEYSTORE_OBJECT)
            .setRequires(Constants.RESPONDER_CERTIFICATE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition RESPONDER_KEYSTORE_OBJECT = new ObjectTypeAttributeDefinition.Builder(Constants.RESPONDER_KEYSTORE_OBJECT,
            TYPE, PATH, RELATIVE_TO, REQUIRED, CREDENTIAL_REFERENCE, ALIAS_FILTER, KeyStoreDefinition.PROVIDER_NAME, KeyStoreDefinition.PROVIDERS)
            .setRequired(false)
            .setAlternatives(Constants.RESPONDER_KEYSTORE)
            .setRequires(Constants.RESPONDER_CERTIFICATE)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition CERTIFICATE_REVOCATION_LIST = new ObjectTypeAttributeDefinition.Builder(Constants.CERTIFICATE_REVOCATION_LIST,
            PATH, RELATIVE_TO, MAXIMUM_CERT_PATH)
            .setRequired(false)
            .setAlternatives(Constants.CERTIFICATE_REVOCATION_LISTS)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition CERTIFICATE_REVOCATION_LIST_NO_MAX_CERT_PATH = new ObjectTypeAttributeDefinition.Builder(Constants.CERTIFICATE_REVOCATION_LIST, PATH, RELATIVE_TO)
            .setRequired(false)
            .setRestartAllServices()
            .build();

    static final ObjectListAttributeDefinition CERTIFICATE_REVOCATION_LISTS = new ObjectListAttributeDefinition.Builder(Constants.CERTIFICATE_REVOCATION_LISTS, CERTIFICATE_REVOCATION_LIST_NO_MAX_CERT_PATH)
            .setRequired(false)
            .setAlternatives(Constants.CERTIFICATE_REVOCATION_LIST)
            .setRestartAllServices()
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
            .setRequired(false)
            .setDefaultValue(ModelNode.FALSE)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition ONLY_LEAF_CERT = new SimpleAttributeDefinitionBuilder(Constants.ONLY_LEAF_CERT, ModelType.BOOLEAN, true)
            .setRequired(false)
            .setDefaultValue(ModelNode.FALSE)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition RESPONDER_CERTIFICATE = new SimpleAttributeDefinitionBuilder(Constants.RESPONDER_CERTIFICATE, ModelType.STRING, true)
            .setRequired(false)
            .setAllowExpression(true)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition OCSP = new ObjectTypeAttributeDefinition.Builder(Constants.OCSP, RESPONDER, PREFER_CRLS,
            RESPONDER_CERTIFICATE, RESPONDER_KEYSTORE/* , RESPONDER_KEYSTORE_OBJECT */)
            .setRequired(false)
            .setRestartAllServices()
            .build();

    /** KeyManager definitions */

    static final SimpleAttributeDefinition KEY_MANAGER = new SimpleAttributeDefinitionBuilder(Constants.KEY_MANAGER, ModelType.STRING, true)
            .setMinSize(1)
            // .setAlternatives(Constants.KEY_MANAGER_OBJECT)
            .setCapabilityReference(KEY_MANAGER_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition KEY_MANAGER_OBJECT = new ObjectTypeAttributeDefinition.Builder(Constants.KEY_MANAGER_OBJECT,
    ALGORITHM, providersKMDefinition, PROVIDER_NAME, keystoreKMDefinition, keystoreKMObjectDefinition, ALIAS_FILTER, CREDENTIAL_REFERENCE,
    GENERATE_SELF_SIGNED_CERTIFICATE_HOST)
            .setRequired(true)
            .setAlternatives(Constants.KEY_MANAGER)
            .setCapabilityReference(KEY_MANAGER_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();


    /** TrustManager definitions */

    static final SimpleAttributeDefinition TRUST_MANAGER = new SimpleAttributeDefinitionBuilder(Constants.TRUST_MANAGER, ModelType.STRING, true)
            .setMinSize(1)
            // .setAlternatives(Constants.TRUST_MANAGER_OBJECT)
            .setCapabilityReference(TRUST_MANAGER_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition TRUST_MANAGER_OBJECT = new ObjectTypeAttributeDefinition.Builder(Constants.TRUST_MANAGER_OBJECT, ALGORITHM,
                PROVIDER_NAME, providersTMDefinition, keystoreTMDefinition, keystoreTMObjectDefinition, ALIAS_FILTER, CERTIFICATE_REVOCATION_LIST,
                CERTIFICATE_REVOCATION_LISTS, OCSP, SOFT_FAIL, ONLY_LEAF_CERT, MAXIMUM_CERT_PATH)
            .setAlternatives(Constants.TRUST_MANAGER)
            .setCapabilityReference(TRUST_MANAGER_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    /* SSL Context definitions */

   static final SimpleAttributeDefinition DEFAULT_SSL_CONTEXT = new SimpleAttributeDefinitionBuilder(Constants.DEFAULT_SSL_CONTEXT, ModelType.STRING)
           .setRequired(true)
           .setCapabilityReference(SSL_CONTEXT_CAPABILITY)
           .setRestartAllServices()
           .build();

//    static final MapAttributeDefinition HOST_CONTEXT_MAP = new SimpleMapAttributeDefinition.Builder(Constants.HOST_CONTEXT_MAP, ModelType.STRING, true)
//            .setMinSize(0)
//            .setMapValidator(new HostContextMapValidator())
//            .setCapabilityReference(SSL_CONTEXT_CAPABILITY)
//            .setAllowExpression(false)
//            .setRestartAllServices()
//            .build();

    /** Runtime Attributes */
    private static final SimpleAttributeDefinition ACTIVE_SESSION_COUNT = new SimpleAttributeDefinitionBuilder(Constants.ACTIVE_SESSION_COUNT, ModelType.INT)
            .setStorageRuntime()
            .build();

    static ResourceDefinition getKeyManagerDefinition() {

        final StandardResourceDescriptionResolver RESOURCE_RESOLVER = ElytronTlsExtension.getResourceDescriptionResolver(Constants.KEY_MANAGER);
        final ObjectTypeAttributeDefinition credentialReferenceDefinition = CredentialReference.getAttributeDefinition(true);

        AttributeDefinition[] attributes = new AttributeDefinition[]{ALGORITHM, providersKMDefinition, PROVIDER_NAME,
                keystoreKMDefinition, /* keystoreKMObjectDefinition */ ALIAS_FILTER, credentialReferenceDefinition, GENERATE_SELF_SIGNED_CERTIFICATE_HOST};

        AbstractAddStepHandler add = new TrivialAddHandler<KeyManager>(KeyManager.class, attributes, KEY_MANAGER_RUNTIME_CAPABILITY) {

            @Override
            protected void populateModel(final OperationContext context, final ModelNode operation, final Resource resource) throws  OperationFailedException {
                super.populateModel(context, operation, resource);
                handleCredentialReferenceUpdate(context, resource.getModel());
            }

            @Override
            protected ValueSupplier<KeyManager> getValueSupplier(ServiceBuilder<KeyManager> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {

                ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier = CredentialReference.getCredentialSourceSupplier(context, credentialReferenceDefinition, model, serviceBuilder);
                final String algorithmName = ALGORITHM.resolveModelAttribute(context, model).asStringOrNull();
                final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
                final String generateSelfSignedCertificateHost = GENERATE_SELF_SIGNED_CERTIFICATE_HOST.resolveModelAttribute(context, model).asStringOrNull();
                final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
                final String providersName = providersKMDefinition.resolveModelAttribute(context, model).asStringOrNull();
                
                Supplier<Provider[]> providersSupplier = addRequirement(PROVIDERS_CAPABILITY, Provider[].class, serviceBuilder,
                                                                        context, providersName);
                Supplier<PathManager> pathManagerSupplier = serviceBuilder.requires(PATH_MANAGER_CAPABILITY.getCapabilityServiceName());
                
                // final ModelNode keyStoreObject = keystoreKMObjectDefinition.resolveModelAttribute(context, model);
                final String keyStoreName = keystoreKMDefinition.resolveModelAttribute(context, model).asStringOrNull();
                final ModifiableKeyStoreService keyStoreService = getModifiableKeyStoreService(context, keyStoreName);
                ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;
                
                /* if (keyStoreName != null) {
                    if (keyStoreObject != null) {
                        throw LOGGER.multipleKeystoreDefinitions();
                    }
                    keyStoreSupplier = new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, keyStoreName);
                } else {
                    if (keyStoreObject == null) {
                        LOGGER.missingKeyStoreDefinition();
                    }
                    keyStoreSupplier = createKeyStore(serviceBuilder, context, keyStoreObject, pathManagerSupplier, providersSupplier);
                } */
                keyStoreSupplier = new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, keyStoreName);

                final String algorithm = algorithmName != null ? algorithmName : KeyManagerFactory.getDefaultAlgorithm();
                DelegatingKeyManager delegatingKeyManager = new DelegatingKeyManager();
                return () -> {
                    Provider[] providers = providersSupplier.get();
                    KeyManagerFactory keyManagerFactory = null;
                    if (providers != null) {
                        for (Provider current : providers) {
                            if (providerName == null || providerName.equals(current.getName())) {
                                try {
                                    // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                                    // However the same loop would need to remain as it is still possible a specific provider can't create it.
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
                            // throw new StartException(LOGGER.keyStorePasswordCannotBeResolved(keyStoreName == null ? keyStoreObject.asStringOrNull() : keyStoreName));
                            throw new StartException(LOGGER.keyStorePasswordCannotBeResolved(keyStoreName));
                        }
                        if (LOGGER.isTraceEnabled()) {
                            LOGGER.tracef(
                                    "KeyManager supplying:  providers = %s  provider = %s  algorithm = %s  keyManagerFactory = %s  " +
                                            "keyStoreName = %s  aliasFilter = %s  keyStore = %s  keyStoreSize = %d  password (of item) = %b",
                                    Arrays.toString(providers), providerName, algorithm, keyManagerFactory, keyStoreName, aliasFilter, keyStore, keyStore.size(), password != null
                            );
                        }
                    } catch (StartException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new StartException(e);
                    }

                    if ((keyStoreService instanceof KeyStoreService) && ((KeyStoreService) keyStoreService).shouldAutoGenerateSelfSignedCertificate(generateSelfSignedCertificateHost)) {
                        LOGGER.selfSignedCertificateWillBeCreated(((KeyStoreService) keyStoreService).getResolvedAbsolutePath(), generateSelfSignedCertificateHost);
                        return new LazyDelegatingKeyManager(keyStoreService, password, keyManagerFactory,
                                generateSelfSignedCertificateHost, aliasFilter);
                    } else {
                        try {
                            if (initKeyManagerFactory(keyStore, delegatingKeyManager, aliasFilter, password, keyManagerFactory)) {
                                return delegatingKeyManager;
                            }
                        } catch (Exception e) {
                            throw new StartException(e);
                        }
                        throw LOGGER.noTypeFound(X509ExtendedKeyManager.class.getSimpleName());
                    }
                };
            }

            @Override
            protected void rollbackRuntime(OperationContext context, final ModelNode operation, final Resource resource) {
                rollbackCredentialStoreUpdate(credentialReferenceDefinition, context, resource);
            }

            class SSLContextExceptionSupplier<T, E extends Exception> implements ExceptionSupplier<T, E> {
                private final Supplier<T> supplier;
                private final ExceptionSupplier<T, E> exceptionSupplier;
        
                SSLContextExceptionSupplier (String baseName, Class<T> type, ServiceBuilder<?> serviceBuilder,
                                             OperationContext context, String dynamicModelElement) {
                    this.supplier = addRequirement(baseName, type, serviceBuilder, context, dynamicModelElement);
                    this.exceptionSupplier = this.supplier::get;
                }
        
                @Override
                public T get() throws E {
                    return exceptionSupplier.get();
                }
            }
        };

        final ServiceUtil<KeyManager> KEY_MANAGER_UTIL = ServiceUtil.newInstance(KEY_MANAGER_RUNTIME_CAPABILITY, Constants.KEY_MANAGER, KeyManager.class);
        return TrivialResourceDefinition.builder()
                .setPathKey(Constants.KEY_MANAGER)
                .setAddHandler(add)
                .setAttributes(attributes)
                .setRuntimeCapabilities(KEY_MANAGER_RUNTIME_CAPABILITY)
                .addOperation(new SimpleOperationDefinitionBuilder(Constants.INIT, RESOURCE_RESOLVER)
                        .setRuntimeOnly()
                        .build(), init(KEY_MANAGER_UTIL))
                .build();
    }

    static ResourceDefinition getTrustManagerDefinition() {

        final StandardResourceDescriptionResolver RESOURCE_RESOLVER = ElytronTlsExtension.getResourceDescriptionResolver(Constants.TRUST_MANAGER);

        AttributeDefinition[] attributes = new AttributeDefinition[]{ALGORITHM, providersTMDefinition, PROVIDER_NAME,
                keystoreTMDefinition, /* keystoreTMObjectDefinition, */ ALIAS_FILTER, CERTIFICATE_REVOCATION_LIST, CERTIFICATE_REVOCATION_LISTS, OCSP, SOFT_FAIL, ONLY_LEAF_CERT, MAXIMUM_CERT_PATH};

        AbstractAddStepHandler add = new TrivialAddHandler<TrustManager>(TrustManager.class, attributes, TRUST_MANAGER_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<TrustManager> getValueSupplier(ServiceBuilder<TrustManager> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String algorithmName = ALGORITHM.resolveModelAttribute(context, model).asStringOrNull();
                final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
                final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
                final String providersName = providersTMDefinition.resolveModelAttribute(context, model).asStringOrNull();

                final Supplier<Provider[]> providersSupplier = addRequirement(PROVIDERS_CAPABILITY, Provider[].class, serviceBuilder,
                                                                              context, providersName);
                Supplier<PathManager> pathManagerSupplier = serviceBuilder.requires(PATH_MANAGER_CAPABILITY.getCapabilityServiceName());

                // final ModelNode keyStoreObject = keystoreTMObjectDefinition.resolveModelAttribute(context, model);
                final String keyStoreName = keystoreTMDefinition.resolveModelAttribute(context, model).asStringOrNull();
                final ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;
                
                /* if (keyStoreName != null) {
                    if (keyStoreObject != null) {
                        throw LOGGER.multipleKeystoreDefinitions();
                    }
                    keyStoreSupplier = new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, keyStoreName);
                } else {
                    if (keyStoreObject == null) {
                        LOGGER.missingKeyStoreDefinition();
                    }
                    keyStoreSupplier = createKeyStore(serviceBuilder, context, keyStoreObject, pathManagerSupplier, providersSupplier);
                } */
                keyStoreSupplier = new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, keyStoreName);

                final String algorithm = algorithmName != null ? algorithmName : TrustManagerFactory.getDefaultAlgorithm();

                if (model.hasDefined(CERTIFICATE_REVOCATION_LIST.getName()) || model.hasDefined(OCSP.getName()) || model.hasDefined(CERTIFICATE_REVOCATION_LISTS.getName())) {
                    return createX509RevocationTrustManager(serviceBuilder, context, model, algorithm, providerName, providersSupplier, keyStoreSupplier, aliasFilter);
                }

                DelegatingTrustManager delegatingTrustManager = new DelegatingTrustManager();
                return () -> {
                    Provider[] providers = providersSupplier.get();

                    TrustManagerFactory trustManagerFactory = createTrustManagerFactory(providers, providerName, algorithm);
                    KeyStore keyStore = keyStoreSupplier.get();

                    try {
                        if (aliasFilter != null) {
                            keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
                        }

                        if (LOGGER.isTraceEnabled()) {
                            LOGGER.tracef(
                                    "TrustManager supplying:  providers = %s  provider = %s  algorithm = %s  trustManagerFactory = %s  keyStoreName = %s  keyStore = %s  aliasFilter = %s  keyStoreSize = %d",
                                    Arrays.toString(providers), providerName, algorithm, trustManagerFactory, keyStoreName, keyStore, aliasFilter, keyStore.size()
                            );
                        }

                        trustManagerFactory.init(keyStoreSupplier.get());
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

            private ValueSupplier<TrustManager> createX509RevocationTrustManager(ServiceBuilder<TrustManager> serviceBuilder, OperationContext context,
                                                                                 ModelNode model, String algorithm, String providerName, Supplier<Provider[]> providersSupplier,
                                                                                 ExceptionSupplier<KeyStore, Exception> keyStoreSupplier, String aliasFilter) throws OperationFailedException {

                ModelNode crlNode = CERTIFICATE_REVOCATION_LIST.resolveModelAttribute(context, model);
                ModelNode ocspNode = OCSP.resolveModelAttribute(context, model);
                ModelNode multipleCrlsNode = CERTIFICATE_REVOCATION_LISTS.resolveModelAttribute(context, model);
                boolean softFail = SOFT_FAIL.resolveModelAttribute(context, model).asBoolean();
                boolean onlyLeafCert = ONLY_LEAF_CERT.resolveModelAttribute(context, model).asBoolean();
                Integer maxCertPath = MAXIMUM_CERT_PATH.resolveModelAttribute(context, model).asIntOrNull();

                String crlPath = null;
                String crlRelativeTo = null;
                Supplier<PathManager> pathManagerSupplier = serviceBuilder.requires(PATH_MANAGER_CAPABILITY.getCapabilityServiceName());
                List<CrlFile> crlFiles = new ArrayList<>();

                if (crlNode.isDefined()) {
                    crlPath = PATH.resolveModelAttribute(context, crlNode).asStringOrNull();
                    crlRelativeTo = RELATIVE_TO.resolveModelAttribute(context, crlNode).asStringOrNull();

                    if (crlPath != null) {
                        if (crlRelativeTo != null) {
                            serviceBuilder.requires(pathName(crlRelativeTo));
                        }
                        crlFiles.add(new CrlFile(crlPath, crlRelativeTo, pathManagerSupplier));
                    }
                } else if (multipleCrlsNode.isDefined()) {
                    // certificate-revocation-lists and certificate-revocation-list are mutually exclusive
                    for (ModelNode crl : multipleCrlsNode.asList()) {
                        crlPath = PATH.resolveModelAttribute(context, crl).asStringOrNull();
                        crlRelativeTo = RELATIVE_TO.resolveModelAttribute(context, crl).asStringOrNull();
                        if (crlPath != null) {
                            if (crlRelativeTo != null) {
                                serviceBuilder.requires(pathName(crlRelativeTo));
                            }
                            crlFiles.add(new CrlFile(crlPath, crlRelativeTo, pathManagerSupplier));
                        }
                    }
                }

                boolean preferCrls = PREFER_CRLS.resolveModelAttribute(context, ocspNode).asBoolean(false);
                String responder = RESPONDER.resolveModelAttribute(context, ocspNode).asStringOrNull();
                String responderCertAlias = RESPONDER_CERTIFICATE.resolveModelAttribute(context, ocspNode).asStringOrNull();
                String responderKeystore = RESPONDER_KEYSTORE.resolveModelAttribute(context, ocspNode).asStringOrNull();

                final ExceptionSupplier<KeyStore, Exception> responderStoreSupplier = responderKeystore != null
                                ? new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, responderKeystore)
                                : keyStoreSupplier;

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
                    TrustManagerFactory trustManagerFactory = createTrustManagerFactory(providersSupplier.get(), providerName, algorithm);
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

            private List<InputStream> getCrlStreams(List<CrlFile> crlFiles) throws StartException {
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

            private TrustManager createReloadableX509CRLTrustManager(final List<CrlFile> crlFiles, final X509RevocationTrustManager.Builder builder) {
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

            private File resolveFileLocation(String path, String relativeTo, Supplier<PathManager> pathManagerSupplier) {
                final File resolvedPath;
                if (relativeTo != null) {
                    PathManager pathManager = pathManagerSupplier.get();
                    resolvedPath = new File(pathManager.resolveRelativePathEntry(path, relativeTo));
                } else {
                    resolvedPath = new File(path);
                }
                return resolvedPath;
            }

            private TrustManagerFactory createTrustManagerFactory(Provider[] providers, String providerName, String algorithm) throws StartException {
                TrustManagerFactory trustManagerFactory = null;

                if (providers != null) {
                    for (Provider current : providers) {
                        if (providerName == null || providerName.equals(current.getName())) {
                            try {
                                // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                                // However the same loop would need to remain as it is still possible a specific provider can't create it.
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

            class SSLContextExceptionSupplier<T, E extends Exception> implements ExceptionSupplier<T, E> {
                private final Supplier<T> supplier;
                private final ExceptionSupplier<T, E> exceptionSupplier;
        
                SSLContextExceptionSupplier (String baseName, Class<T> type, ServiceBuilder<?> serviceBuilder,
                                             OperationContext context, String dynamicModelElement) {
                    this.supplier = addRequirement(baseName, type, serviceBuilder, context, dynamicModelElement);
                    this.exceptionSupplier = this.supplier::get;
                }
        
                @Override
                public T get() throws E {
                    return exceptionSupplier.get();
                }
            }
        };

        ResourceDescriptionResolver resolver = ElytronTlsExtension.getResourceDescriptionResolver(Constants.TRUST_MANAGER);
        final ServiceUtil<TrustManager> TRUST_MANAGER_UTIL = ServiceUtil.newInstance(TRUST_MANAGER_RUNTIME_CAPABILITY, Constants.TRUST_MANAGER, TrustManager.class);
        return TrivialResourceDefinition.builder()
                .setPathKey(Constants.TRUST_MANAGER)
                .setResourceDescriptionResolver(resolver)
                .setAddHandler(add)
                .setAttributes(attributes)
                .setRuntimeCapabilities(TRUST_MANAGER_RUNTIME_CAPABILITY)
                .addOperation(new SimpleOperationDefinitionBuilder(Constants.RELOAD_CERTIFICATE_REVOCATION_LIST, resolver)
                        .setRuntimeOnly()
                        .build(), new ElytronRuntimeOnlyHandler() {

                    @Override
                    protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
                        ServiceName serviceName = TRUST_MANAGER_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue()).getCapabilityServiceName();
                        ServiceController<TrustManager> serviceContainer = getRequiredService(context.getServiceRegistry(true), serviceName, TrustManager.class);
                        State serviceState;
                        if ((serviceState = serviceContainer.getState()) != State.UP) {
                            throw LOGGER.requiredServiceNotUp(serviceName, serviceState);
                        }
                        TrustManager trustManager = serviceContainer.getValue();
                        if (! (trustManager instanceof ReloadableX509ExtendedTrustManager)) {
                            throw LOGGER.unableToReloadCRLNotReloadable();
                        }
                        ((ReloadableX509ExtendedTrustManager) trustManager).reload();
                    }
                })
                .addOperation(new SimpleOperationDefinitionBuilder(Constants.INIT, RESOURCE_RESOLVER)
                        .setRuntimeOnly()
                        .build(), init(TRUST_MANAGER_UTIL))
                .build();
    }

    private static ResourceDefinition createSSLContextDefinition(String pathKey, boolean server, AbstractAddStepHandler addHandler, AttributeDefinition[] attributes, boolean serverOrHostController) {
        /* The original method used SimpleResourceDefinition and would return an object from SSLContextResourceDefinition(parameters, attributes)
         * This was likely planned to replace a variety of other classes (like TrivialResourceDefinition)
         * TODO: Simplify and reimplement _Trivial_ classes with native subsystem versions */

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
                protected void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) {
                    SSLSessionContext sessionContext = server ? sslContext.getServerSessionContext() : sslContext.getClientSessionContext();
                    int sum = 0;
                    for (byte[] ignored : Collections.list(sessionContext.getIds())) {
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

    static ResourceDefinition getClientSSLContextDefinition(boolean serverOrHostController) {

        final SimpleAttributeDefinition providersDefinition = new SimpleAttributeDefinitionBuilder(PROVIDERS)
                .setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY)
                .setAllowExpression(false)
                .setRestartAllServices()
                .build();

        final AttributeDefinition[] attributes = new AttributeDefinition[]{CIPHER_SUITE_FILTER, CIPHER_SUITE_NAMES,
                PROTOCOLS, /* KEY_MANAGER_OBJECT, */ KEY_MANAGER, /* TRUST_MANAGER_OBJECT, */ TRUST_MANAGER,
                PROVIDER_NAME, providersDefinition};

        AbstractAddStepHandler add = new TrivialAddHandler<SSLContext>(SSLContext.class, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY) {
            @Override
            protected ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
                final String providersName = providersDefinition.resolveModelAttribute(context, model).asStringOrNull();
                final List<String> protocols = PROTOCOLS.unwrap(context, model);
                final String cipherSuiteFilter = CIPHER_SUITE_FILTER.resolveModelAttribute(context, model).asString();
                final String cipherSuiteNames = CIPHER_SUITE_NAMES.resolveModelAttribute(context, model).asStringOrNull();
                
                Supplier<Provider[]> providersSupplier = addRequirement(PROVIDERS_CAPABILITY, Provider[].class, serviceBuilder,
                                                                            context, providersName);
                Supplier<PathManager> pathManagerSupplier = serviceBuilder.requires(PATH_MANAGER_CAPABILITY.getCapabilityServiceName());
                SSLContextExceptionSupplier<KeyManager, Exception> keyManagerSupplier;
                SSLContextExceptionSupplier<TrustManager, Exception> trustManagerSupplier;
                
                final String keyManagerName = KEY_MANAGER.resolveModelAttribute(context, model).asStringOrNull();
                /* final ModelNode keyManagerObject = KEY_MANAGER_OBJECT.resolveModelAttribute(context, model);
                if (keyManagerObject.isDefined()) {
                    keyManagerSupplier = (SSLContextExceptionSupplier<KeyManager, Exception>) createKeyManager(serviceBuilder, context, keyManagerObject, pathManagerSupplier, providersSupplier);
                } else { // Use reference
                    keyManagerSupplier = new SSLContextExceptionSupplier<>(KEY_MANAGER_CAPABILITY, KeyManager.class, serviceBuilder,
                    context, keyManagerName);
                } */
                keyManagerSupplier = new SSLContextExceptionSupplier<>(KEY_MANAGER_CAPABILITY, KeyManager.class, serviceBuilder, context, keyManagerName);

                final String trustManagerName = TRUST_MANAGER.resolveModelAttribute(context, model).asStringOrNull();
                /* final ModelNode trustManagerObject = TRUST_MANAGER_OBJECT.resolveModelAttribute(context, model);
                if (trustManagerObject.isDefined()) {
                    trustManagerSupplier = (SSLContextExceptionSupplier<TrustManager, Exception>) createTrustManager(serviceBuilder, context, trustManagerObject, pathManagerSupplier, providersSupplier);
                } else {
                    trustManagerSupplier = new SSLContextExceptionSupplier<>(TRUST_MANAGER_CAPABILITY, TrustManager.class, serviceBuilder,
                            context, trustManagerName);
                } */
                trustManagerSupplier = new SSLContextExceptionSupplier<>(TRUST_MANAGER_CAPABILITY, TrustManager.class, serviceBuilder, context, trustManagerName);

                final SSLContextExceptionSupplier<KeyManager, Exception> finalKeyManagerSupplier = keyManagerSupplier;
                final SSLContextExceptionSupplier<TrustManager, Exception> finalTrustManagerSupplier = trustManagerSupplier;

                return () -> {
                    X509ExtendedKeyManager keyManager = getX509KeyManager(finalKeyManagerSupplier.get());
                    X509ExtendedTrustManager trustManager = getX509TrustManager(finalTrustManagerSupplier.get());
                    Provider[] providers = filterProviders(providersSupplier.get(), providerName);

                    DomainlessSSLContextBuilder builder = new DomainlessSSLContextBuilder();
                    if (keyManager != null) builder.setKeyManager(keyManager);
                    if (trustManager != null) builder.setTrustManager(trustManager);
                    if (providers != null) builder.setProviderSupplier(() -> providers);
                    builder.setCipherSuiteSelector(CipherSuiteSelector.aggregate(
                                cipherSuiteNames != null? CipherSuiteSelector.fromNamesString(cipherSuiteNames) : null,
                                CipherSuiteSelector.fromString(cipherSuiteFilter)
                    ));
                    if (!protocols.isEmpty()) {
                        List<Protocol> list = new ArrayList<>();
                        for (String protocol : protocols) {
                            Protocol forName = Protocol.forName(protocol);
                            list.add(forName);
                        }
                        builder.setProtocolSelector(ProtocolSelector.empty().add(
                                EnumSet.copyOf(list)
                        ));
                    }
                    builder.setClientMode(true)
                            .setWrap(false);

                    if (LOGGER.isTraceEnabled()) {
                        LOGGER.tracef(
                                "ClientSSLContext supplying:  keyManager = %s  trustManager = %s  providers = %s  " +
                                        "cipherSuiteFilter = %s cipherSuiteNames = %s protocols = %s",
                                keyManager, trustManager, Arrays.toString(providers), cipherSuiteFilter, cipherSuiteNames,
                                Arrays.toString(protocols.toArray())
                        );
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
                SSLContextResource resource = new SSLContextResource(Resource.Factory.create(), false);
                context.addResource(PathAddress.EMPTY_ADDRESS, resource);
                return resource;
            }

            @Override
            protected void installedForResource(ServiceController<SSLContext> serviceController, Resource resource) {
                ((SSLContextResource) resource).setSSLContextServiceController(serviceController);
            }
        };

        return createSSLContextDefinition(Constants.CLIENT_SSL_CONTEXT, false, add, attributes, serverOrHostController);
    }

    static ResourceDefinition getServerSSLContextDefinition(boolean serverOrHostController) {

        final ObjectTypeAttributeDefinition credentialReferenceDefinition = CredentialReference.getAttributeDefinition(true);

        final SimpleAttributeDefinition providersDefinition = new SimpleAttributeDefinitionBuilder(PROVIDERS)
                .setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY)
                .setRestartAllServices()
                .build();

        final SimpleAttributeDefinition keyManagerDefinition = new SimpleAttributeDefinitionBuilder(KEY_MANAGER)
                .setRequired(true)
                .setRestartAllServices()
                .build();

        final AttributeDefinition[] attributes = new AttributeDefinition[]{CIPHER_SUITE_FILTER, CIPHER_SUITE_NAMES,
                PROTOCOLS, /* KEY_MANAGER_OBJECT, */ keyManagerDefinition, /* TRUST_MANAGER_OBJECT, */ TRUST_MANAGER, PROVIDER_NAME,
                providersDefinition, WANT_CLIENT_AUTH, NEED_CLIENT_AUTH, AUTHENTICATION_OPTIONAL, USE_CIPHER_SUITES_ORDER, MAXIMUM_SESSION_CACHE_SIZE,
                SESSION_TIMEOUT, WRAP};


        AbstractAddStepHandler add = new TrivialAddHandler<SSLContext>(SSLContext.class, ServiceController.Mode.ACTIVE,
                                        ServiceController.Mode.PASSIVE, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder,
                                                                                OperationContext context, ModelNode model) throws OperationFailedException {
                                                    
                final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
                final String providersName = PROVIDERS.resolveModelAttribute(context, model).asStringOrNull();
                final List<String> protocols = PROTOCOLS.unwrap(context, model);
                final String cipherSuiteFilter = CIPHER_SUITE_FILTER.resolveModelAttribute(context, model).asString(); // has default value, can't be null
                final String cipherSuiteNames = CIPHER_SUITE_NAMES.resolveModelAttribute(context, model).asStringOrNull(); // doesn't have a default value yet since we are disabling TLS 1.3 by default
                final boolean wantClientAuth = WANT_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean needClientAuth = NEED_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean authenticationOptional = AUTHENTICATION_OPTIONAL.resolveModelAttribute(context, model).asBoolean();
                final boolean useCipherSuitesOrder = USE_CIPHER_SUITES_ORDER.resolveModelAttribute(context, model).asBoolean();
                final int maximumSessionCacheSize = MAXIMUM_SESSION_CACHE_SIZE.resolveModelAttribute(context, model).asInt();
                final int sessionTimeout = SESSION_TIMEOUT.resolveModelAttribute(context, model).asInt();
                final boolean wrap = WRAP.resolveModelAttribute(context, model).asBoolean();
                
                Supplier<Provider[]> providersSupplier = addRequirement(PROVIDERS_CAPABILITY, Provider[].class, serviceBuilder,
                                                                                        context, providersName);
                Supplier<PathManager> pathManagerSupplier = serviceBuilder.requires(PATH_MANAGER_CAPABILITY.getCapabilityServiceName());
                SSLContextExceptionSupplier<KeyManager, Exception> keyManagerSupplier;
                SSLContextExceptionSupplier<TrustManager, Exception> trustManagerSupplier;

                final String keyManagerName = keyManagerDefinition.resolveModelAttribute(context, model).asStringOrNull();
                /* final ModelNode keyManagerObject = KEY_MANAGER_OBJECT.resolveModelAttribute(context, model);
                if (keyManagerObject.isDefined()) {
                    keyManagerSupplier = (SSLContextExceptionSupplier<KeyManager, Exception>) createKeyManager(serviceBuilder, context, keyManagerObject, pathManagerSupplier, providersSupplier);
                } else { // Use reference
                    keyManagerSupplier = new SSLContextExceptionSupplier<>(KEY_MANAGER_CAPABILITY, KeyManager.class, serviceBuilder,
                    context, keyManagerName);
                } */
                keyManagerSupplier = new SSLContextExceptionSupplier<>(KEY_MANAGER_CAPABILITY, KeyManager.class, serviceBuilder, context, keyManagerName);
                
                final String trustManagerName = TRUST_MANAGER.resolveModelAttribute(context, model).asStringOrNull();
                /* final ModelNode trustManagerObject = TRUST_MANAGER_OBJECT.resolveModelAttribute(context, model);
                if (trustManagerObject.isDefined()) {
                    trustManagerSupplier = (SSLContextExceptionSupplier<TrustManager, Exception>) createTrustManager(serviceBuilder, context, keyManagerObject, pathManagerSupplier, providersSupplier);
                } else {
                    trustManagerSupplier = new SSLContextExceptionSupplier<>(TRUST_MANAGER_CAPABILITY, TrustManager.class, serviceBuilder,
                            context, trustManagerName);
                } */
                trustManagerSupplier = new SSLContextExceptionSupplier<>(TRUST_MANAGER_CAPABILITY, TrustManager.class, serviceBuilder, context, trustManagerName);

                final SSLContextExceptionSupplier<KeyManager, Exception> finalKeyManagerSupplier = keyManagerSupplier;
                final SSLContextExceptionSupplier<TrustManager, Exception> finalTrustManagerSupplier = trustManagerSupplier;

                return () -> {
                    X509ExtendedKeyManager keyManager = getX509KeyManager(finalKeyManagerSupplier.get());
                    X509ExtendedTrustManager trustManager = getX509TrustManager(finalTrustManagerSupplier.get());
                    Provider[] providers = filterProviders(providersSupplier.get(), providerName);

                    DomainlessSSLContextBuilder builder = new DomainlessSSLContextBuilder();
                    if (keyManager != null) builder.setKeyManager(keyManager);
                    if (trustManager != null) builder.setTrustManager(trustManager);
                    if (providers != null) builder.setProviderSupplier(() -> providers);
                    builder.setCipherSuiteSelector(CipherSuiteSelector.aggregate(
                            cipherSuiteNames != null ? CipherSuiteSelector.fromNamesString(cipherSuiteNames) : null,
                            CipherSuiteSelector.fromString(cipherSuiteFilter)
                    ));
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
                            .setAuthenticationOptional(authenticationOptional)
                            .setUseCipherSuitesOrder(useCipherSuitesOrder)
                            .setSessionCacheSize(maximumSessionCacheSize)
                            .setSessionTimeout(sessionTimeout)
                            .setWrap(wrap);

                    if (LOGGER.isTraceEnabled()) {
                        LOGGER.tracef(
                                "ServerSSLContext supplying:  keyManager = %s  trustManager = %s  "
                                        + "providers = %s  cipherSuiteFilter = %s  cipherSuiteNames = %s protocols = %s  wantClientAuth = %s  needClientAuth = %s  "
                                        + "authenticationOptional = %s maximumSessionCacheSize = %s  sessionTimeout = %s wrap = %s",
                                keyManager, trustManager, Arrays.toString(providers), cipherSuiteFilter, cipherSuiteNames,
                                Arrays.toString(protocols.toArray()), wantClientAuth, needClientAuth, authenticationOptional,
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

        return createSSLContextDefinition(Constants.SERVER_SSL_CONTEXT, true, add, attributes, serverOrHostController);
    }


    private static ExceptionSupplier<TrustManager, Exception> createTrustManager(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model,
                                                                                 Supplier<PathManager> pathManager,
                                                                                 Supplier<Provider[]> providersSupplier) throws OperationFailedException {
        final String algorithmName = ALGORITHM.resolveModelAttribute(context, model).asStringOrNull();
        final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
        final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
        
        final ModelNode keyStoreObject = keystoreTMObjectDefinition.resolveModelAttribute(context, model);
        final String keyStoreName = keystoreTMDefinition.resolveModelAttribute(context, model).asStringOrNull();
        ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;

        if (keyStoreName != null) {
            if (keyStoreObject != null) {
                throw LOGGER.multipleKeystoreDefinitions();
            }
            keyStoreSupplier = new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, keyStoreName);
        } else {
            if (keyStoreObject == null) {
                throw LOGGER.missingKeyStoreDefinition();
            }
            keyStoreSupplier = createKeyStore(serviceBuilder, context, keyStoreObject, pathManager, providersSupplier);
        }

        final String algorithm = algorithmName != null ? algorithmName : TrustManagerFactory.getDefaultAlgorithm();

        if (model.hasDefined(CERTIFICATE_REVOCATION_LIST.getName()) || model.hasDefined(OCSP.getName()) || model.hasDefined(CERTIFICATE_REVOCATION_LISTS.getName())) {
            return createX509RevocationTrustManager(serviceBuilder, context, model, algorithm, providerName, keyStoreSupplier, aliasFilter, pathManager);
        }

        DelegatingTrustManager delegatingTrustManager = new DelegatingTrustManager();
        return () -> {
            Provider[] providers = providersSupplier.get();
            
            TrustManagerFactory trustManagerFactory = createTrustManagerFactory(providers, providerName, algorithm);
            KeyStore keyStore = keyStoreSupplier.get();

            try {
                if (aliasFilter != null) {
                    keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
                }

                if (LOGGER.isTraceEnabled()) {
                    LOGGER.tracef(
                            "TrustManager supplying:  providers = %s  provider = %s  algorithm = %s  trustManagerFactory = %s  keyStoreName = %s  keyStore = %s  aliasFilter = %s  keyStoreSize = %d",
                            Arrays.toString(providers), providerName, algorithm, trustManagerFactory, keyStoreName, keyStore, aliasFilter, keyStore.size()
                    );
                }

                trustManagerFactory.init(keyStoreSupplier.get());
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

    private static ExceptionSupplier<TrustManager, Exception> createX509RevocationTrustManager(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context,
                                                                         ModelNode model, String algorithm, String providerName, ExceptionSupplier<KeyStore, Exception> keyStoreSupplier,
                                                                         String aliasFilter, Supplier<PathManager> pathManager) throws OperationFailedException {

        ModelNode crlNode = CERTIFICATE_REVOCATION_LIST.resolveModelAttribute(context, model);
        ModelNode ocspNode = OCSP.resolveModelAttribute(context, model);
        ModelNode multipleCrlsNode = CERTIFICATE_REVOCATION_LISTS.resolveModelAttribute(context, model);
        boolean softFail = SOFT_FAIL.resolveModelAttribute(context, model).asBoolean();
        boolean onlyLeafCert = ONLY_LEAF_CERT.resolveModelAttribute(context, model).asBoolean();
        Integer maxCertPath = MAXIMUM_CERT_PATH.resolveModelAttribute(context, model).asIntOrNull();

        String crlPath;
        String crlRelativeTo;
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
        String responderKeystoreName = RESPONDER_KEYSTORE.resolveModelAttribute(context, ocspNode).asStringOrNull();

        final ExceptionSupplier<KeyStore, Exception> responderStoreSupplier = (responderKeystoreName != null)
                ? new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, responderKeystoreName)
                : keyStoreSupplier;

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
            builder.setMaxCertPath(maxCertPath);
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
        if (providers != null) {
            for (Provider current : providers) {
                if (providerName == null || providerName.equals(current.getName())) {
                    try {
                        return TrustManagerFactory.getInstance(algorithm, current);
                    } catch (NoSuchAlgorithmException ignored) {
                    }
                }
            }
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

    private static ExceptionSupplier<KeyManager, Exception> createKeyManager(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context,
                                                                             ModelNode model, Supplier<PathManager> pathManagerSupplier,
                                                                             Supplier<Provider[]> providersSupplier) throws OperationFailedException {
        final ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier = CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);
        final String algorithmName = ALGORITHM.resolveModelAttribute(context, model).asStringOrNull();
        final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
        final String generateSelfSignedCertificateHost = GENERATE_SELF_SIGNED_CERTIFICATE_HOST.resolveModelAttribute(context, model).asStringOrNull();
        final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
        
        final ModelNode keyStoreObject = keystoreKMObjectDefinition.resolveModelAttribute(context, model);
        final String keyStoreName = keystoreKMDefinition.resolveModelAttribute(context, model).asStringOrNull();
        final ModifiableKeyStoreService keyStoreService = getModifiableKeyStoreService(context, keyStoreName);
        ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;

        if (keyStoreName != null) {
            if (keyStoreObject != null) {
                throw LOGGER.multipleKeystoreDefinitions();
            }
            keyStoreSupplier = new SSLContextExceptionSupplier<>(KEY_STORE_CAPABILITY, KeyStore.class, serviceBuilder, context, keyStoreName);
        } else {
            if (keyStoreObject == null) {
                throw LOGGER.missingKeyStoreDefinition();
            }
            keyStoreSupplier = createKeyStore(serviceBuilder, context, keyStoreObject, pathManagerSupplier, providersSupplier);
        }

        final String algorithm = algorithmName == null ? algorithmName : KeyManagerFactory.getDefaultAlgorithm();
        DelegatingKeyManager delegatingKeyManager = new DelegatingKeyManager();
        return () -> {
            Provider[] providers = providersSupplier.get();
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
                    throw new StartException(LOGGER.keyStorePasswordCannotBeResolved(keyStoreName == null ? keyStoreObject.asStringOrNull() : keyStoreName));
                }
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.tracef(
                            "KeyManager supplying:  providers = %s  provider = %s  algorithm = %s  keyManagerFactory = %s  " +
                                    "keyStoreName = %s  aliasFilter = %s  keyStore = %s  keyStoreSize = %d  password (of item) = %b",
                            Arrays.toString(providers), providerName, algorithm, keyManagerFactory, keyStoreName, aliasFilter, keyStore, keyStore.size(), password != null
                    );
                }
            } catch (StartException e) {
                throw e;
            } catch (Exception e) {
                throw new StartException(e);
            }
            
            if ((keyStoreService instanceof KeyStoreService) && ((KeyStoreService) keyStoreService).shouldAutoGenerateSelfSignedCertificate(generateSelfSignedCertificateHost)) {
                LOGGER.selfSignedCertificateWillBeCreated(((KeyStoreService) keyStoreService).getResolvedAbsolutePath(), generateSelfSignedCertificateHost);
                return new LazyDelegatingKeyManager(keyStoreService, password, keyManagerFactory,
                        generateSelfSignedCertificateHost, aliasFilter);
            } else {
                try {
                    if (initKeyManagerFactory(keyStore, delegatingKeyManager, aliasFilter, password, keyManagerFactory)) {
                        return delegatingKeyManager;
                    }
                } catch (Exception e) {
                    throw new StartException(e);
                }
                throw LOGGER.noTypeFound(X509ExtendedKeyManager.class.getSimpleName());
            } 
        };
    }

    private static OperationStepHandler init(ServiceUtil<?> managerUtil) {
        return new ElytronRuntimeOnlyHandler() {
            @Override
            protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
                try {
                    ServiceName serviceName = managerUtil.serviceName(operation);
                    ServiceController<?> serviceContainer = null;
                    if(serviceName.getParent().getCanonicalName().equals(KEY_MANAGER_CAPABILITY)){
                        serviceContainer = getRequiredService(context.getServiceRegistry(false), serviceName, KeyManager.class);
                    } else if (serviceName.getParent().getCanonicalName().equals(TRUST_MANAGER_CAPABILITY)) {
                        serviceContainer = getRequiredService(context.getServiceRegistry(false), serviceName, TrustManager.class);
                    } else {
                        throw LOGGER.invalidServiceNameParent(serviceName.getParent().getCanonicalName());
                    }
                    serviceContainer.getService().stop(null);
                    serviceContainer.getService().start(null);
                } catch (Exception e) {
                    throw new OperationFailedException(e);
                }
            }
        };
    }

    private static X509ExtendedKeyManager getX509KeyManager(KeyManager keyManager) throws StartException {
        if (keyManager == null) {
            return null;
        }
        if (keyManager instanceof X509ExtendedKeyManager) {
            return (X509ExtendedKeyManager) keyManager;
        }
        throw LOGGER.invalidTypeInjected(X509ExtendedKeyManager.class.getSimpleName());
    }

    private static class LazyDelegatingKeyManager extends DelegatingKeyManager {
        private ModifiableKeyStoreService keyStoreService;
        private char[] password;
        private KeyManagerFactory keyManagerFactory;
        private String generateSelfSignedCertificateHostName;
        private String aliasFilter;
        private volatile boolean init = false;

        private LazyDelegatingKeyManager(ModifiableKeyStoreService keyStoreService, char[] password, KeyManagerFactory keyManagerFactory,
                                         String generateSelfSignedCertificateHostName, String aliasFilter) {
            this.keyStoreService = keyStoreService;
            this.password = password;
            this.keyManagerFactory = keyManagerFactory;
            this.generateSelfSignedCertificateHostName = generateSelfSignedCertificateHostName;
            this.aliasFilter = aliasFilter;
        }

        private void doInit() {
            if(! init) {
                synchronized (this) {
                    if(! init) {
                        try {
                            ((KeyStoreService) keyStoreService).generateAndSaveSelfSignedCertificate(generateSelfSignedCertificateHostName, password);
                            if (! initKeyManagerFactory(((KeyStoreService) keyStoreService).getValue(), this, aliasFilter, password, keyManagerFactory)) {
                                throw LOGGER.noTypeFoundForLazyInitKeyManager(X509ExtendedKeyManager.class.getSimpleName());
                            }
                        } catch (Exception e) {
                            throw LOGGER.failedToLazilyInitKeyManager(e);
                        } finally {
                            init = true;
                        }
                    }
                }
            }
        }

        @Override
        public String[] getClientAliases(String s, Principal[] principals) {
            doInit();
            return super.getClientAliases(s, principals);
        }

        @Override
        public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
            doInit();
            return super.chooseClientAlias(strings, principals, socket);
        }

        @Override
        public String[] getServerAliases(String s, Principal[] principals) {
            doInit();
            return super.getServerAliases(s, principals);
        }

        @Override
        public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
            doInit();
            return super.chooseServerAlias(s, principals, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(String s) {
            doInit();
            return super.getCertificateChain(s);
        }

        @Override
        public PrivateKey getPrivateKey(String s) {
            doInit();
            return super.getPrivateKey(s);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            doInit();
            return super.chooseEngineClientAlias(keyType, issuers, engine);
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            doInit();
            return super.chooseEngineServerAlias(keyType, issuers, engine);
        }

    }

    static boolean initKeyManagerFactory(KeyStore keyStore, DelegatingKeyManager delegating, String aliasFilter,
                                         char[] password, KeyManagerFactory keyManagerFactory) throws Exception {
        if (aliasFilter != null) {
            keyStore = FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter));
        }
        keyManagerFactory.init(keyStore, password);
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
        boolean keyManagerTypeFound = false;
        for (KeyManager keyManager : keyManagers) {
            if (keyManager instanceof X509ExtendedKeyManager) {
                delegating.setKeyManager((X509ExtendedKeyManager) keyManager);
                keyManagerTypeFound = true;
                break;
            }
        }
        return keyManagerTypeFound;
    }
    
    private static X509ExtendedTrustManager getX509TrustManager(TrustManager trustManager) throws StartException {
        if (trustManager == null) {
            return null;
        }
        if (trustManager instanceof X509ExtendedTrustManager) {
            return (X509ExtendedTrustManager) trustManager;
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

    private static ExceptionSupplier<KeyStore, Exception> createKeyStore(ServiceBuilder<?> serviceBuilder, OperationContext context,
                                                                         ModelNode model, Supplier<PathManager> pathManager,
                                                                         Supplier<Provider[]> providersSupplier) throws OperationFailedException {
        final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
        final String type = TYPE.resolveModelAttribute(context, model).asStringOrNull();
        final String aliasFilter = ALIAS_FILTER.resolveModelAttribute(context, model).asStringOrNull();
        final String path = PATH.resolveModelAttribute(context, model).asStringOrNull();
        final String relativeTo = RELATIVE_TO.resolveModelAttribute(context, model).asStringOrNull();
        final boolean required = REQUIRED.resolveModelAttribute(context, model).asBoolean(false);
        final ExceptionSupplier<CredentialSource, Exception> credentialSourceSupplier = CredentialReference.getCredentialSourceSupplier(context, CREDENTIAL_REFERENCE, model, serviceBuilder);

        return () -> {
            AtomicLoadKeyStore keyStore = null;
            FileAttributeDefinitions.PathResolver pathResolver;
            File resolvedPath = null;
            Provider provider = null;

            if (type != null) {
                provider = resolveProviders(providerName, KeyStore.class, type, providersSupplier.get());
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

                LOGGER.tracef(
                        "starting:  type = %s  provider = %s  path = %s  resolvedPath = %s  password = %b  aliasFilter = %s",
                        type, provider, path, resolvedPath, password != null, aliasFilter
                );

                if (is != null) {
                    if (type != null) {
                        keyStore.load(is, password);
                    } else {
                        Provider[] resolvedProviders = providersSupplier.get();
                        Provider[] finalProviders = resolvedProviders == null ? Security.getProviders() : resolvedProviders;
                        KeyStore detected = KeyStoreUtil.loadKeyStore(() -> finalProviders, providerName, is, resolvedPath.getPath(), password);

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
    }

    private static Provider resolveProviders(String name, Class<?> type, String alg, Provider[] candidates) throws StartException {
        Supplier<Provider[]> resolveProvidersSupplier = () -> candidates == null ? Security.getProviders() : candidates;
        Provider provider = ProviderUtil.findProvider(resolveProvidersSupplier, name, type, alg);
        if (provider == null) {
            throw LOGGER.noSuitableProvider(alg);
        }
        return provider;
    }

    // Derives dynamic name from provided attribute
    private static <V> Supplier<V> addRequirement(String baseName, Class<V> type, ServiceBuilder<?> serviceBuilder,
                                                  OperationContext context, String dynamicNameElement) {
        Supplier<V> supplier = () -> null;

        if (dynamicNameElement != null) {
            supplier = serviceBuilder.requires(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(baseName, dynamicNameElement), type));
        }
        return supplier;
    }

    private static Provider[] filterProviders(Provider[] all, String provider) {
        if (provider == null || all == null) return all;
        List<Provider> list = new ArrayList<>();
        for (Provider current : all) {
            if (provider.equals(current.getName())) {
                list.add(current);
            }
        }
        return list.toArray(new Provider[0]);
    }

    /**
     * A supplier that throws exceptions, and can be constructed from {@link ServiceBuilder} or {@link ExceptionSupplier}.
     */
    private static class SSLContextExceptionSupplier<T, E extends Exception> implements ExceptionSupplier<T, E> {
        private final Supplier<T> supplier;
        private final ExceptionSupplier<T, E> exceptionSupplier;

        SSLContextExceptionSupplier (String baseName, Class<T> type, ServiceBuilder<?> serviceBuilder,
                                     OperationContext context, String dynamicModelElement) {
            this.supplier = addRequirement(baseName, type, serviceBuilder, context, dynamicModelElement);
            this.exceptionSupplier = this.supplier::get;
        }

        @Override
        public T get() throws E {
            return exceptionSupplier.get();
        }
    }

    abstract static class SSLContextRuntimeHandler extends ElytronRuntimeOnlyHandler {
        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            ServiceName serviceName = getSSLContextServiceUtil().serviceName(operation);

            ServiceController<SSLContext> serviceController = getRequiredService(context.getServiceRegistry(false), serviceName, SSLContext.class);
            State serviceState;
            if ((serviceState = serviceController.getState()) != State.UP) {
                throw LOGGER.requiredServiceNotUp(serviceName, serviceState);
            }

            performRuntime(context.getResult(), operation, serviceController.getService().getValue());
        }

        protected abstract void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException;

        protected abstract ServiceUtil<SSLContext> getSSLContextServiceUtil();
    }

    static ModifiableKeyStoreService getModifiableKeyStoreService(OperationContext context, String keyStoreName) {
        ServiceRegistry serviceRegistry = context.getServiceRegistry(true);
        RuntimeCapability<Void> runtimeCapability = KEY_STORE_RUNTIME_CAPABILITY.fromBaseCapability(keyStoreName);
        ServiceName serviceName = runtimeCapability.getCapabilityServiceName();
        ServiceController<KeyStore> serviceContainer = getRequiredService(serviceRegistry, serviceName, KeyStore.class);
        return (ModifiableKeyStoreService) serviceContainer.getService();
    }

    static class CrlFile {
        private final String crlPath;
        private final String relativeTo;
        private final Supplier<PathManager> pathManagerSupplier;

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
