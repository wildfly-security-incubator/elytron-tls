/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.extension.elytron.tls;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.wildfly.extension.elytron.tls.CertificateChainAttributeDefinitions.getNamedCertificateList;
import static org.wildfly.extension.elytron.tls.CertificateChainAttributeDefinitions.writeCertificates;
import static org.wildfly.extension.elytron.tls.ElytronTlsExtension.ISO_8601_FORMAT;
import static org.wildfly.extension.elytron.tls._private.ElytronTLSMessages.LOGGER;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.function.BiConsumer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleOperationDefinition;
import org.jboss.as.controller.SimpleOperationDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.descriptions.ResourceDescriptionResolver;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.wildfly.common.iteration.ByteIterator;

// TODO: merge into SSLContextDefintions?

/**
 * A resource definition to represent a currently established SSL session.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SSLSessionDefinition extends SimpleResourceDefinition {

    private static final SimpleAttributeDefinition APPLICATION_BUFFER_SIZE = new SimpleAttributeDefinitionBuilder(Constants.APPLICATION_BUFFER_SIZE, ModelType.INT)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition CIPHER_SUITE = new SimpleAttributeDefinitionBuilder(Constants.CIPHER_SUITE, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition CREATION_TIME = new SimpleAttributeDefinitionBuilder(Constants.CREATION_TIME, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition LAST_ACCESSED_TIME = new SimpleAttributeDefinitionBuilder(Constants.LAST_ACCESSED_TIME, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition LOCAL_PRINCIPAL = new SimpleAttributeDefinitionBuilder(Constants.LOCAL_PRINCIPAL, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition PACKET_BUFFER_SIZE = new SimpleAttributeDefinitionBuilder(Constants.PACKET_BUFFER_SIZE, ModelType.INT)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition PEER_HOST = new SimpleAttributeDefinitionBuilder(Constants.PEER_HOST, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition PEER_PORT = new SimpleAttributeDefinitionBuilder(Constants.PEER_PORT, ModelType.INT)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition PEER_PRINCIPAL = new SimpleAttributeDefinitionBuilder(Constants.PEER_PRINCIPAL, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition PROTOCOL = new SimpleAttributeDefinitionBuilder(Constants.PROTOCOL, ModelType.STRING)
            .setStorageRuntime()
            .build();

    private static final SimpleAttributeDefinition VALID = new SimpleAttributeDefinitionBuilder(Constants.VALID, ModelType.BOOLEAN)
            .setStorageRuntime()
            .build();

    private static final ResourceDescriptionResolver RESOURCE_DESCRIPTION_RESOLVER = ElytronTlsExtension.getResourceDescriptionResolver(Constants.SERVER_SSL_CONTEXT, Constants.SSL_SESSION);


    private static final SimpleOperationDefinition INVALIDATE = new SimpleOperationDefinitionBuilder(Constants.INVALIDATE, RESOURCE_DESCRIPTION_RESOLVER)
            .build();

    private boolean server;

    SSLSessionDefinition(boolean server) {
        super(new Parameters(PathElement.pathElement(Constants.SSL_SESSION), RESOURCE_DESCRIPTION_RESOLVER)
            .setAddRestartLevel(OperationEntry.Flag.RESTART_NONE)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRuntime());
        this.server = server;
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerReadOnlyAttribute(APPLICATION_BUFFER_SIZE, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.getApplicationBufferSize())));
        resourceRegistration.registerReadOnlyAttribute(CIPHER_SUITE, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.getCipherSuite())));
        resourceRegistration.registerReadOnlyAttribute(CREATION_TIME, new SSLSessionRuntimeHandler(
                (ModelNode r, SSLSession s) -> r.set(new SimpleDateFormat(ISO_8601_FORMAT).format(new Date(s.getCreationTime())))));
        resourceRegistration.registerReadOnlyAttribute(LAST_ACCESSED_TIME, new SSLSessionRuntimeHandler(
                (ModelNode r, SSLSession s) -> r.set(new SimpleDateFormat(ISO_8601_FORMAT).format(new Date(s.getLastAccessedTime())))));
        resourceRegistration.registerReadOnlyAttribute(getNamedCertificateList(Constants.LOCAL_CERTIFICATES),
                new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> {
                    try {
                        writeCertificates(r, s.getLocalCertificates());
                    } catch (CertificateEncodingException | NoSuchAlgorithmException ignored) {
                    }
                }));
        resourceRegistration.registerReadOnlyAttribute(LOCAL_PRINCIPAL, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> {
                    Principal p = s.getLocalPrincipal();
                    if (p != null) {
                        r.set(p.toString());
                    }
        }));
        resourceRegistration.registerReadOnlyAttribute(PACKET_BUFFER_SIZE, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.getPacketBufferSize())));
        resourceRegistration.registerReadOnlyAttribute(getNamedCertificateList(Constants.PEER_CERTIFICATES),
                new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> {
                    try {
                        writeCertificates(r, s.getPeerCertificates());
                    } catch (CertificateEncodingException | NoSuchAlgorithmException | SSLPeerUnverifiedException ignored) {
                    }
                }));
        resourceRegistration.registerReadOnlyAttribute(PEER_HOST, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.getPeerHost())));
        resourceRegistration.registerReadOnlyAttribute(PEER_PORT, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.getPeerPort())));
        resourceRegistration.registerReadOnlyAttribute(PEER_PRINCIPAL, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> {
                    try {
                        Principal p = s.getPeerPrincipal();
                        if (p != null) {
                            r.set(p.toString());
                        }
                    } catch (SSLPeerUnverifiedException ignored) {}
        }));
        resourceRegistration.registerReadOnlyAttribute(PROTOCOL, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.getProtocol())));
        resourceRegistration.registerReadOnlyAttribute(VALID, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> r.set(s.isValid())));
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);
        resourceRegistration.registerOperationHandler(INVALIDATE, new SSLSessionRuntimeHandler((ModelNode r, SSLSession s) -> s.invalidate()));
    }

    class SSLSessionRuntimeHandler extends SSLContextDefinitions.SSLContextRuntimeHandler {

        private final BiConsumer<ModelNode, SSLSession> biConsumer;

        SSLSessionRuntimeHandler(BiConsumer<ModelNode, SSLSession> biConsumer) {
            this.biConsumer = biConsumer;
        }
        @Override
        protected void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException {
            SSLSessionContext sslSessionContext = server ? sslContext.getServerSessionContext() : sslContext.getClientSessionContext();
            SSLSession sslSession = sslSessionContext.getSession(sessionId(operation));
            if (sslSession != null) {
                performRuntime(result, operation, sslSession);
            }
        }

        protected void performRuntime(ModelNode result, ModelNode operation, SSLSession sslSession) throws OperationFailedException {
            biConsumer.accept(result, sslSession);
        }

        @Override
        protected ServiceUtil<SSLContext> getSSLContextServiceUtil() {
            return server ? SSLContextDefinitions.SERVER_SERVICE_UTIL : SSLContextDefinitions.CLIENT_SERVICE_UTIL;
        }
    }

    private static byte[] sessionId(ModelNode operation) {
        PathAddress pa = PathAddress.pathAddress(operation.require(OP_ADDR));
        for (int i = pa.size() - 1; i > 0; i--) {
            PathElement pe = pa.getElement(i);
            if (Constants.SSL_SESSION.equals(pe.getKey())) {
                return ByteIterator.ofBytes(pe.getValue().getBytes(StandardCharsets.UTF_8)).asUtf8String().hexDecode().drain();
            }
        }

        throw LOGGER.operationAddressMissingKey(Constants.SSL_SESSION);
    }
}
