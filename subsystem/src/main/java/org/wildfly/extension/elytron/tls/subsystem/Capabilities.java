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

import java.security.KeyStore;
import java.security.Permissions;
import java.security.Policy;
import java.security.Provider;
import java.util.function.Consumer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.security.sasl.SaslServerFactory;

import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.msc.service.ServiceBuilder;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.x500.cert.acme.AcmeAccount;
import org.wildfly.security.x500.cert.acme.CertificateAuthority;

/**
 * The capabilities provided by and required by this subsystem.
 *
 * The capabilities are same as the ones provided by the Elytron subsystem
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
class Capabilities {

    private static final String WILDFLY_SECURITY_CAPABILITY_BASE = "org.wildfly.security.";

    static final String ELYTRON_TLS_SUBSYSTEM_CAPABILITY_NAME = "org.wildfly.extras.elytron-tls";
    
    static final RuntimeCapability<Void> ELYTRON_TLS_RUNTIME_CAPABILITY = RuntimeCapability.Builder
            .of(ELYTRON_TLS_SUBSYSTEM_CAPABILITY_NAME)
            .addRequirements(ElytronTlsExtension.WELD_CAPABILITY_NAME)
            .build();

    static final String AUTHENTICATION_CONFIGURATION_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "authentication-configuration";

    static final RuntimeCapability<Void> AUTHENTICATION_CONFIGURATION_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(AUTHENTICATION_CONFIGURATION_CAPABILITY, true, AuthenticationConfiguration.class)
            .build();

    static final String AUTHENTICATION_CONTEXT_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "authentication-context";

    static final RuntimeCapability<Void> AUTHENTICATION_CONTEXT_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(AUTHENTICATION_CONTEXT_CAPABILITY, true, AuthenticationContext.class)
            .build();

    static final String CERTIFICATE_AUTHORITY_ACCOUNT_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "certificate-authority-account";

    static final RuntimeCapability<Void> CERTIFICATE_AUTHORITY_ACCOUNT_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CERTIFICATE_AUTHORITY_ACCOUNT_CAPABILITY, true, AcmeAccount.class)
            .build();

    static final String CERTIFICATE_AUTHORITY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "certificate-authority";

    static final RuntimeCapability<Void> CERTIFICATE_AUTHORITY_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CERTIFICATE_AUTHORITY_CAPABILITY, true, CertificateAuthority.class)
            .build();

    static final String CREDENTIAL_STORE_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "credential-store";

    /*
     * A variant of the credential-store capability which also provides access to the underlying
     * {@code CredentialStore} as a runtime API from a {@code ExceptionFunction<OperationContext, CredentialStore, OperationFailedException>}.
     */
    static final String CREDENTIAL_STORE_API_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "credential-store-api";

    static final RuntimeCapability<Void> CREDENTIAL_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(CREDENTIAL_STORE_CAPABILITY, true, CredentialStore.class)
            .build();

    static final String DIR_CONTEXT_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "dir-context";

    // This has to be at this position, and must not be a lambda, to avoid an init circularity problem on IBM
    @SuppressWarnings("Convert2Lambda")
    static final Consumer<ServiceBuilder> COMMON_DEPENDENCIES = new Consumer<ServiceBuilder>() {
        // unchecked because ServiceBuilder is a raw type
        @SuppressWarnings("unchecked")
        public void accept(final ServiceBuilder serviceBuilder) {
            //ElytronDefinition.commonDependencies(serviceBuilder);
            //TODO:
        }
    };

    static final String ELYTRON_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "elytron";


    static final RuntimeCapability<Consumer<ServiceBuilder>> ELYTRON_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(ELYTRON_CAPABILITY, COMMON_DEPENDENCIES)
            .build();

    static final String EVIDENCE_DECODER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "evidence-decoder";

    static final RuntimeCapability<Void> EVIDENCE_DECODER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(EVIDENCE_DECODER_CAPABILITY, true, EvidenceDecoder.class)
            .build();

    static final String HTTP_AUTHENTICATION_FACTORY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "http-authentication-factory";

    static final RuntimeCapability<Void> HTTP_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(HTTP_AUTHENTICATION_FACTORY_CAPABILITY, true, HttpAuthenticationFactory.class)
            .build();

    static final String HTTP_SERVER_MECHANISM_FACTORY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "http-server-mechanism-factory";

    static final RuntimeCapability<Void> HTTP_SERVER_MECHANISM_FACTORY_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(HTTP_SERVER_MECHANISM_FACTORY_CAPABILITY, true, HttpServerAuthenticationMechanismFactory.class)
            .build();

    static final String JACC_POLICY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "jacc-policy";
    static final RuntimeCapability<Void> JACC_POLICY_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(JACC_POLICY_CAPABILITY, false, Policy.class)
            .build();

    static final String KEY_MANAGER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "key-manager";

    static final RuntimeCapability<Void> KEY_MANAGER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(KEY_MANAGER_CAPABILITY, true, KeyManager.class)
            .build();

    static final String KEY_STORE_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "key-store";

    static final RuntimeCapability<Void> KEY_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(KEY_STORE_CAPABILITY, true, KeyStore.class)
            .build();

    static final String MODIFIABLE_SECURITY_REALM_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "modifiable-security-realm";

    static final RuntimeCapability<Void> MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(MODIFIABLE_SECURITY_REALM_CAPABILITY, true, ModifiableSecurityRealm.class)
            .build();

    static final String PERMISSION_MAPPER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "permission-mapper";

    static final RuntimeCapability<Void> PERMISSION_MAPPER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PERMISSION_MAPPER_CAPABILITY, true, PermissionMapper.class)
            .build();

    static final String PERMISSION_SET_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "permission-set";

    static final RuntimeCapability<Void> PERMISSION_SET_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PERMISSION_SET_CAPABILITY, true, Permissions.class)
            .build();

    static final String POLICY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "policy";
    static final RuntimeCapability<Void> POLICY_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(POLICY_CAPABILITY, false, Policy.class)
            .build();

    static final String PRINCIPAL_TRANSFORMER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "principal-transformer";


    static final String PRINCIPAL_DECODER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "principal-decoder";

    static final RuntimeCapability<Void> PRINCIPAL_DECODER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PRINCIPAL_DECODER_CAPABILITY, true, PrincipalDecoder.class)
            .build();

    static final String PROVIDERS_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "providers";

    /*
     * A variant of the credential-store capability which also provides access to the underlying
     * {@code CredentialStore} as a runtime API from a {@code ExceptionFunction<OperationContext, Provider[], OperationFailedException>}.
     */
    static final String PROVIDERS_API_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "providers-api";

    static final RuntimeCapability<Void> PROVIDERS_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PROVIDERS_CAPABILITY, true, Provider[].class)
            .build();

    static final String REALM_MAPPER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "realm-mapper";

    static final RuntimeCapability<Void> REALM_MAPPER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(REALM_MAPPER_CAPABILITY, true, RealmMapper.class)
            .build();

    static final String ROLE_DECODER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "role-decoder";

    static final RuntimeCapability<Void> ROLE_DECODER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(ROLE_DECODER_CAPABILITY, true, RoleDecoder.class)
            .build();

    static final String ROLE_MAPPER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "role-mapper";

    static final RuntimeCapability<Void> ROLE_MAPPER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(ROLE_MAPPER_CAPABILITY, true, RoleMapper.class)
            .build();

    static final String SASL_AUTHENTICATION_FACTORY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "sasl-authentication-factory";

    static final RuntimeCapability<Void> SASL_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(SASL_AUTHENTICATION_FACTORY_CAPABILITY, true, SaslAuthenticationFactory.class)
            .build();

    static final String SASL_SERVER_FACTORY_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "sasl-server-factory";

    static final RuntimeCapability<Void> SASL_SERVER_FACTORY_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(SASL_SERVER_FACTORY_CAPABILITY, true, SaslServerFactory.class)
            .build();

    static final String SECURITY_DOMAIN_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "security-domain";

    static final RuntimeCapability<Void> SECURITY_DOMAIN_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(SECURITY_DOMAIN_CAPABILITY, true, SecurityDomain.class)
            .build();

    static final String SECURITY_EVENT_LISTENER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "security-event-listener";

    static final String SECURITY_FACTORY_CAPABILITY_BASE = WILDFLY_SECURITY_CAPABILITY_BASE + "security-factory.";

    static final String SECURITY_FACTORY_CREDENTIAL_CAPABILITY = SECURITY_FACTORY_CAPABILITY_BASE + "credential";

    static final String SECURITY_REALM_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "security-realm";

    static final RuntimeCapability<Void> SECURITY_REALM_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(SECURITY_REALM_CAPABILITY, true, SecurityRealm.class)
            .build();

    static final String SSL_CONTEXT_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "ssl-context";

    static final RuntimeCapability<Void> SSL_CONTEXT_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(SSL_CONTEXT_CAPABILITY, true, SSLContext.class)
            .build();

    static final String TRUST_MANAGER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "trust-manager";

    static final RuntimeCapability<Void> TRUST_MANAGER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(TRUST_MANAGER_CAPABILITY, true, TrustManager.class)
            .build();


    static final String EXPRESSION_RESOLVER_CAPABILITY = WILDFLY_SECURITY_CAPABILITY_BASE + "expression-resolver";

}
