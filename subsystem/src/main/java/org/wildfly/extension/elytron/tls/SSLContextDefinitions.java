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

package org.wildfly.extension.elytron.tls;


import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.KEY_MANAGER_CAPABILITY;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.KEY_STORE_CAPABILITY;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.PRINCIPAL_TRANSFORMER_CAPABILITY;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.SSL_CONTEXT_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.common.ElytronCommonCapabilities.TRUST_MANAGER_CAPABILITY;
import static org.wildfly.extension.elytron.common.FileAttributeDefinitions.PATH;
import static org.wildfly.extension.elytron.common.FileAttributeDefinitions.RELATIVE_TO;
import static org.wildfly.extension.elytron.common.KeyStoreDefinition.CREDENTIAL_REFERENCE;
import static org.wildfly.extension.elytron.common.KeyStoreDefinition.REQUIRED;
import static org.wildfly.extension.elytron.common.KeyStoreDefinition.TYPE;
import static org.wildfly.extension.elytron.tls._private.ElytronTLSMessages.LOGGER;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.common.ElytronCommonConstants;
import org.wildfly.extension.elytron.common.ElytronCommonTrivialAddHandler;
import org.wildfly.extension.elytron.common.KeyStoreDefinition;
import org.wildfly.extension.elytron.common.SSLDefinitions;
import org.wildfly.extension.elytron.common.SSLSessionDefinition;
import org.wildfly.extension.elytron.common.ServiceUtil;
import org.wildfly.extension.elytron.common.TrivialService;
import org.wildfly.extension.elytron.common.capabilities.PrincipalTransformer;
import org.wildfly.extension.elytron.common.util.ElytronCommonMessages;
import org.wildfly.extension.elytron.tls.TrivialResourceDefinition.Builder;
import org.wildfly.security.ssl.SSLContextBuilder;

/**
 * Collection of {@link ResourceDefinition} used to configure {@link SSLContext}. Elytron TLS combines attributes of key stores,
 * key/trust managers, and SSLContexts to configure with a single command.
 *
 * <p>TODO: The *-ssl-context resources include new attributes, called {@code key-store-configuration} and {@code trust-store-configuration},
 * which combine the attributes of a keystore and a key/trust manager (some of the manager attributes are renamed to avoid conflicts). So,
 * providing a path and credential-reference are sufficient to configure a full setup. Behind the scenes, the attributes
 * are used to configure new keystore and manager resources. The {@code *-store-configuration} attributes must <b>not</b>
 * propagated to the XML.</p>
 *
 * <p>This might require a different implementation of {@link AttributeDefinition} to be used, but this hasn't been investigated yet.
 * It doesn't restrict the attributes from appearing in the model reference (ex. using the CLI to check the attribute
 * {@code org.wildfly.extension.elytron-tls.key-store-configuration.path} could actually display the path of the associated
 * key-store resource).</p>
 *
 * <p>For more information, see <a href="https://github.com/wildfly/wildfly-proposals/pull/500">the proposal</a>.</p>
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
class SSLContextDefinitions extends SSLDefinitions {

    private static final BooleanSupplier IS_FIPS = getFipsSupplier();

    static final SimpleAttributeDefinition providersSSLContextDefinition = new SimpleAttributeDefinitionBuilder(PROVIDERS)
            .setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    /* TODO the alternatives listed are key-store attributes. Within key-/trust-store-configuration, a user can either provide the attributes to create a new
        keystore, or they can reference an existing one. */
    static final SimpleAttributeDefinition keyStoreKMDefinition = new SimpleAttributeDefinitionBuilder(KEYSTORE)
            .setCapabilityReference(KEY_STORE_CAPABILITY, KEY_MANAGER_CAPABILITY)
            .setAlternatives(ElytronCommonConstants.PROVIDER_NAME, ElytronCommonConstants.PROVIDERS, ElytronCommonConstants.PATH,
                    ElytronCommonConstants.RELATIVE_TO, ElytronCommonConstants.REQUIRED, ElytronCommonConstants.ALIAS_FILTER)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition trustStoreTMDefinition = new SimpleAttributeDefinitionBuilder(Constants.TRUST_STORE, KEYSTORE)
            .setCapabilityReference(KEY_STORE_CAPABILITY, TRUST_MANAGER_CAPABILITY)
            .setAlternatives(ElytronCommonConstants.PROVIDER_NAME, ElytronCommonConstants.PROVIDERS, ElytronCommonConstants.PATH,
                    ElytronCommonConstants.RELATIVE_TO, ElytronCommonConstants.REQUIRED, ElytronCommonConstants.ALIAS_FILTER)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    static final ObjectTypeAttributeDefinition credentialReferenceDefinition = CredentialReference.getAttributeDefinition(true);

    /* Renamed key/trust manager attributes */

    static final SimpleAttributeDefinition aliasFilterKMDefinition = new SimpleAttributeDefinitionBuilder(Constants.KEY_MANAGER_ALIAS_FILTER, ALIAS_FILTER)
            .build();
    static final SimpleAttributeDefinition aliasFilterTMDefinition = new SimpleAttributeDefinitionBuilder(Constants.TRUST_MANAGER_ALIAS_FILTER, ALIAS_FILTER)
            .build();

    static final SimpleAttributeDefinition providerNameKMDefinition = new SimpleAttributeDefinitionBuilder(Constants.KEY_MANAGER_PROVIDER_NAME, PROVIDER_NAME)
            .build();
    static final SimpleAttributeDefinition providerNameTMDefinition = new SimpleAttributeDefinitionBuilder(Constants.TRUST_MANAGER_PROVIDER_NAME, PROVIDER_NAME)
            .build();

    static final SimpleAttributeDefinition providersKMDefinition = new SimpleAttributeDefinitionBuilder(Constants.KEY_MANAGER_PROVIDERS, PROVIDERS)
            .setCapabilityReference(PROVIDERS_CAPABILITY, KEY_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();
    static final SimpleAttributeDefinition providersTMDefinition = new SimpleAttributeDefinitionBuilder(Constants.TRUST_MANAGER_PROVIDERS, PROVIDERS)
            .setCapabilityReference(PROVIDERS_CAPABILITY, TRUST_MANAGER_CAPABILITY)
            .setAllowExpression(false)
            .setRestartAllServices()
            .build();

    /* TODO: Elytron TLS is built to be compatible with the main subsystem, so the user can also ignore the new types
        completely, and just reference an existing key/trust manager  */

    static final SimpleAttributeDefinition keyManagerDefWithAlternatives = new SimpleAttributeDefinitionBuilder(KEY_MANAGER)
            .setAlternatives(Constants.KEY_STORE_CONFIGURATION)
            .build();

    static final SimpleAttributeDefinition trustManagerDefWithAlternatives = new SimpleAttributeDefinitionBuilder(TRUST_MANAGER)
            .setAlternatives(Constants.TRUST_STORE_CONFIGURATION)
            .build();

    /* KeyStore & TrustStore configuration */

    private static final AttributeDefinition[] KEYSTORE_KM_ATTRIBUTES = {keyStoreKMDefinition, TYPE, KeyStoreDefinition.PROVIDER_NAME,
            KeyStoreDefinition.PROVIDERS, CREDENTIAL_REFERENCE, PATH, RELATIVE_TO, REQUIRED, KeyStoreDefinition.ALIAS_FILTER};
    private static final AttributeDefinition[] TRUSTSTORE_TM_ATTRIBUTES = {trustStoreTMDefinition, TYPE, KeyStoreDefinition.PROVIDER_NAME,
            KeyStoreDefinition.PROVIDERS, CREDENTIAL_REFERENCE, PATH, RELATIVE_TO, REQUIRED, KeyStoreDefinition.ALIAS_FILTER};

    /* TODO An example CLI call:
        /subsystem=elytron-tls/server-ssl-context=appSSC:add(\
            key-store-configration={path=keystore.p12,relative-to=jboss.server.config.dir,credential-reference={clear-text=key-p@ssw0rd123}, cipher-suite-names=TLS_AES_128_GCM_SHA256},\
            trust-store-configuration={trust-store=applicationTrustStore,credential-reference={clear-text=trust-p@ssw0rd123}})
     */

    static final ObjectTypeAttributeDefinition keyStoreConfiguration = ObjectTypeAttributeDefinition.Builder.of(Constants.KEY_STORE_CONFIGURATION,
                    KEYSTORE_KM_ATTRIBUTES, new AttributeDefinition[]{ALGORITHM, providersKMDefinition, providerNameKMDefinition,
                            aliasFilterKMDefinition, credentialReferenceDefinition, GENERATE_SELF_SIGNED_CERTIFICATE_HOST})
            .build();

    static final ObjectTypeAttributeDefinition trustStoreConfiguration = ObjectTypeAttributeDefinition.Builder.of(Constants.TRUST_STORE_CONFIGURATION,
                    TRUSTSTORE_TM_ATTRIBUTES, new AttributeDefinition[]{ALGORITHM, providersTMDefinition, providerNameTMDefinition,
                            aliasFilterTMDefinition, CERTIFICATE_REVOCATION_LIST, CERTIFICATE_REVOCATION_LISTS, OCSP, SOFT_FAIL, ONLY_LEAF_CERT, MAXIMUM_CERT_PATH})
            .build();

    /*
     * Runtime Attributes
     */

    private static final SimpleAttributeDefinition ACTIVE_SESSION_COUNT = new SimpleAttributeDefinitionBuilder(ElytronCommonConstants.ACTIVE_SESSION_COUNT, ModelType.INT)
            .setStorageRuntime()
            .build();


    /* TODO: note that REALM_MAPPER attribute has also been removed (in addition to SECURITY_DOMAIN) since it depends on
        wildfly-elytron-auth-server. There are a long chain of dependencies that come with that artifact, so we're trying
        to eventually remove it. More details are included in the "Undertow + Elytron Web" section of the proposal. */

    static ResourceDefinition getServerSSLContextDefinition(boolean serverOrHostController) {
        final SimpleAttributeDefinition keyManagerServerDefinition = new SimpleAttributeDefinitionBuilder(keyManagerDefWithAlternatives)
                .setRequired(true)
                .setRestartAllServices()
                .build();

        final AttributeDefinition[] attributes = new AttributeDefinition[]{CIPHER_SUITE_FILTER, CIPHER_SUITE_NAMES, PROTOCOLS,
                WANT_CLIENT_AUTH, NEED_CLIENT_AUTH, AUTHENTICATION_OPTIONAL, USE_CIPHER_SUITES_ORDER,
                MAXIMUM_SESSION_CACHE_SIZE, SESSION_TIMEOUT, WRAP, PRE_REALM_PRINCIPAL_TRANSFORMER, POST_REALM_PRINCIPAL_TRANSFORMER,
                FINAL_PRINCIPAL_TRANSFORMER, PROVIDER_NAME, providersSSLContextDefinition,
                keyStoreConfiguration, keyManagerServerDefinition, trustStoreConfiguration, trustManagerDefWithAlternatives};

        AbstractAddStepHandler add = new ElytronCommonTrivialAddHandler<SSLContext>(ElytronTlsExtension.class, SSLContext.class, ServiceController.Mode.ACTIVE, ServiceController.Mode.PASSIVE, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY) {
            @Override
            protected TrivialService.ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder,
                                                                                OperationContext context, ModelNode model) throws OperationFailedException {

                final Supplier<KeyStore> keyStoreKMSupplier = addDependency(KEY_STORE_CAPABILITY, keyStoreKMDefinition, KeyStore.class, serviceBuilder, context, model);
                final Supplier<KeyManager> keyManagerSupplier = addDependency(KEY_MANAGER_CAPABILITY, keyManagerServerDefinition, KeyManager.class, serviceBuilder, context, model);
                final Supplier<KeyStore> trustStoreTMSupplier = addDependency(KEY_STORE_CAPABILITY, trustStoreTMDefinition, KeyStore.class, serviceBuilder, context, model);
                final Supplier<TrustManager> trustManagerSupplier = addDependency(TRUST_MANAGER_CAPABILITY, trustManagerDefWithAlternatives, TrustManager.class, serviceBuilder, context, model);
                final Supplier<PrincipalTransformer> preRealmPrincipalTransformerSupplier = addDependency(PRINCIPAL_TRANSFORMER_CAPABILITY, PRE_REALM_PRINCIPAL_TRANSFORMER, PrincipalTransformer.class, serviceBuilder, context, model);
                final Supplier<PrincipalTransformer> postRealmPrincipalTransformerSupplier = addDependency(PRINCIPAL_TRANSFORMER_CAPABILITY, POST_REALM_PRINCIPAL_TRANSFORMER, PrincipalTransformer.class, serviceBuilder, context, model);
                final Supplier<PrincipalTransformer> finalPrincipalTransformerSupplier = addDependency(PRINCIPAL_TRANSFORMER_CAPABILITY, FINAL_PRINCIPAL_TRANSFORMER, PrincipalTransformer.class, serviceBuilder, context, model);
                final Supplier<Provider[]> providersSupplier = addDependency(PROVIDERS_CAPABILITY, providersSSLContextDefinition, Provider[].class, serviceBuilder, context, model);

                final ModelNode keyStoreConfigAttributes = keyStoreConfiguration.resolveModelAttribute(context, model).asObject();
                final ModelNode trustStoreConfigAttributes = trustStoreConfiguration.resolveModelAttribute(context, model).asObject();
                final String providerName = PROVIDER_NAME.resolveModelAttribute(context, model).asStringOrNull();
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

                /* TODO extract the key-store-configure attributes, listed in KEYSTORE_KM_ATTRIBUTES. Reference SSLDefinitions.getKeyManagerDefinition.
                    Repeat for trust-store-configure and TRUSTSTORE_TM_ATTRIBUTES (SSLDefinitions.getTrustManagerDefinition)
                    Some extraction commands: */
                final String keyStoreName = keyStoreConfigAttributes.get(keyStoreKMDefinition.getName()).asStringOrNull();
                final Supplier<KeyStore> keyStoreSupplier = addDependency(KEY_STORE_CAPABILITY, keyStoreName, KeyStore.class, serviceBuilder, context, model);

                return () -> {
                    SSLContextBuilder builder = new SSLContextBuilder();

                    X509ExtendedKeyManager keyManager = getX509KeyManager(keyManagerSupplier.get());
                    if (keyManager != null) {
                        builder.setKeyManager(keyManager);
                    } else {
                        /* TODO (if statement): check if keyStoreSupplier.get() provides a key-store instance - otherwise create a keystore resource. This
                            This part requires some research to find the correct calls to make.*/

                        // TODO: create a key manager resource. Requires some research.
                    }

                    // TODO repeat for trustManager

                    /* TODO: once you have the managers, implement the remainder of the code to create an SSL context.
                        This is very similar to the code in SSLDefinitions.getServerSSLContextDefinition */

                };
            }

            @Override
            protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
                super.performRuntime(context, operation, model);
            }
        };

        return createSSLContextDefinition(ElytronCommonConstants.SERVER_SSL_CONTEXT, true,
                add, attributes, serverOrHostController);
    }

    static ResourceDefinition getClientSSLContextDefinition(boolean serverOrHostController) {

        final AttributeDefinition[] attributes = new AttributeDefinition[]{CIPHER_SUITE_FILTER, CIPHER_SUITE_NAMES, PROTOCOLS,
                PROVIDER_NAME, providersSSLContextDefinition,
                keyStoreConfiguration,keyManagerDefWithAlternatives, trustStoreConfiguration, trustManagerDefWithAlternatives};

        AbstractAddStepHandler add = new ElytronCommonTrivialAddHandler<SSLContext>(ElytronTlsExtension.class, SSLContext.class, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY) {
            /* TODO: implement client-ssl-context in a similar method to server-ssl-context. Reference
                SSLDefinitions.getClientSSLContextDefinition for specific attributes used - some server-ssl-context attributes
                are not used here. */
        };

        return createSSLContextDefinition(ElytronCommonConstants.CLIENT_SSL_CONTEXT, false,
                add, attributes, serverOrHostController);
    }

    private static ResourceDefinition createSSLContextDefinition(String pathKey, boolean server,
                                                                 AbstractAddStepHandler addHandler, AttributeDefinition[] attributes, boolean serverOrHostController) {

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
            }).addChild(SSLSessionDefinition.configure(ElytronTlsExtension.class, server));
        }

        return builder.build();
    }

    private static X509ExtendedKeyManager getX509KeyManager(KeyManager keyManager) throws StartException {
        if (keyManager == null) {
            return null;
        }
        if (keyManager instanceof X509ExtendedKeyManager) {
            X509ExtendedKeyManager x509KeyManager = (X509ExtendedKeyManager) keyManager;
            if (x509KeyManager instanceof DelegatingKeyManager && IS_FIPS.getAsBoolean()) {
                LOGGER.trace("FIPS enabled on JVM, unwrapping KeyManager");
                // If FIPS is enabled unwrap the KeyManager
                x509KeyManager = ((DelegatingKeyManager) x509KeyManager).delegating.get();
            }

            return x509KeyManager;
        }
        throw ElytronCommonMessages.ROOT_LOGGER.invalidTypeInjected(X509ExtendedKeyManager.class.getSimpleName());
    }

    private static X509ExtendedTrustManager getX509TrustManager(TrustManager trustManager) throws StartException {
        if (trustManager == null) {
            return null;
        }
        if (trustManager instanceof X509ExtendedTrustManager) {
            X509ExtendedTrustManager x509TrustManager = (X509ExtendedTrustManager) trustManager;
            if (x509TrustManager instanceof DelegatingTrustManager && IS_FIPS.getAsBoolean()) {
                LOGGER.trace("FIPS enabled on JVM, unwrapping TrustManager");
                x509TrustManager = ((DelegatingTrustManager)x509TrustManager).delegating.get();
            }
            return x509TrustManager;
        }
        throw ElytronCommonMessages.ROOT_LOGGER.invalidTypeInjected(X509ExtendedTrustManager.class.getSimpleName());
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

    private static BooleanSupplier getFipsSupplier() {
        try {
            final Class<?> providerClazz = SSLContextDefinitions.class.getClassLoader().loadClass("com.sun.net.ssl.internal.ssl.Provider");
            final Method isFipsMethod = providerClazz.getMethod("isFIPS");

            Object isFips;
            try {
                isFips = isFipsMethod.invoke(null);
                if ((isFips instanceof Boolean)) {
                    return () -> (boolean) isFips;
                } else {
                    return () -> false;
                }
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                LOGGER.trace("Unable to invoke com.sun.net.ssl.internal.ssl.Provider.isFIPS() method.", e);
                return () -> false;
            }
        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException e) {
            LOGGER.trace("Unable to find com.sun.net.ssl.internal.ssl.Provider.isFIPS() method.", e);
        }

        return () -> new SecureRandom().getProvider().getName().toLowerCase().contains("fips");
    }

    /** @return A {@link Supplier} for an optional value, for the transition to the new JBoss MSC API */
    private static <T> Supplier<T> addDependency(String baseName, SimpleAttributeDefinition attribute, Class<T> type,
                                                 ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {

        String dynamicNameElement = attribute.resolveModelAttribute(context, model).asStringOrNull();
        return addDependency(baseName, dynamicNameElement, type, serviceBuilder, context, model);
    }

    /** @return A {@link Supplier} for an optional value, for the transition to the new JBoss MSC API */
    private static <T> Supplier<T> addDependency(String baseName, String dynamicNameElement, Class<T> type,
                                                 ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {

        InjectedValue<T> injectedValue = new InjectedValue<>();
        if (dynamicNameElement != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(baseName, dynamicNameElement), type),
                    type, injectedValue);
        }
        return injectedValue::getOptionalValue;
    }
}