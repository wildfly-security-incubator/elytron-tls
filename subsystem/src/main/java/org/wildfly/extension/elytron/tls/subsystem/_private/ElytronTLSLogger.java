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

package org.wildfly.extension.elytron.tls.subsystem._private;

import static org.jboss.logging.Logger.Level.INFO;
import static org.jboss.logging.Logger.Level.WARN;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.server.deployment.DeploymentUnitProcessingException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartException;

import java.io.IOException;

/**
 * Log messages for Elytron TLS subsystem
 *
 * @author <a href="mmazanek@redhat.com">Martin Mazanek</a>
 */
@MessageLogger(projectCode = "ELYTLS", length = 4)
public interface ElytronTLSLogger extends BasicLogger {

    ElytronTLSLogger LOGGER = Logger.getMessageLogger(ElytronTLSLogger.class, "org.wildfly.extension.elytron.tls.subsystem");

    @LogMessage(level = INFO)
    @Message(id = 1, value = "Activating Elytron TLS Subsystem")
    void activatingSubsystem();

    @Message(id = 2, value = "Deployment %s requires use of the '%s' capability but it is not currently registered")
    DeploymentUnitProcessingException deploymentRequiresCapability(String deploymentName, String capabilityName);

    @Message(id = 3, value = "The operation did not contain an address with a value for '%s'.")
    IllegalArgumentException operationAddressMissingKey(final String key);

    /**
     * A {@link StartException} if it is not possible to initialise the {@link Service}.
     *
     * @param cause the cause of the failure.
     * @return The {@link StartException} for the error.
     */
    @Message(id = 4, value = "Unable to start the service.")
    StartException unableToStartService(@Cause Exception cause);

    @Message(id = 7, value = "The required service '%s' is not UP, it is currently '%s'.")
    OperationFailedException requiredServiceNotUp(ServiceName serviceName, ServiceController.State state);

    @Message(id = 12, value = "No suitable provider found for type '%s'")
    StartException noSuitableProvider(String type);

    @Message(id = 18, value = "Unable to create %s for algorithm '%s'.")
    StartException unableToCreateManagerFactory(final String type, final String algorithm);

    @Message(id = 19, value = "No '%s' found in injected value.")
    StartException noTypeFound(final String type);

    @Message(id = 22, value = "KeyStore file '%s' does not exist and required.")
    StartException keyStoreFileNotExists(final String file);

    @LogMessage(level = WARN)
    @Message(id = 23, value = "KeyStore file '%s' does not exist. Used blank.")
    void keyStoreFileNotExistsButIgnored(final String file);

    @Message(id = 31, value = "Unable to access CRL file.")
    StartException unableToAccessCRL(@Cause Exception cause);

    @Message(id = 32, value = "Unable to reload CRL file.")
    RuntimeException unableToReloadCRL(@Cause Exception cause);

    @Message(id = 37, value = "Injected value is not of '%s' type.")
    StartException invalidTypeInjected(final String type);

    @Message(id = 39, value = "Unable to reload CRL file - TrustManager is not reloadable")
    OperationFailedException unableToReloadCRLNotReloadable();

    @Message(id = 43, value = "A cycle has been detected initialising the resources - %s")
    OperationFailedException cycleDetected(String cycle);

    @Message(id = 910, value = "Password cannot be resolved for key-store '%s'")
    IOException keyStorePasswordCannotBeResolved(String path);

    @Message(id = 1017, value = "Invalid value for cipher-suite-filter. %s")
    OperationFailedException invalidCipherSuiteFilter(@Cause Throwable cause, String causeMessage);

    @Message(id = 1059, value = "Unable to detect KeyStore '%s'")
    StartException unableToDetectKeyStore(String path);

    @Message(id = 1061, value = "Invalid value of host context map: '%s' is not valid hostname pattern.")
    OperationFailedException invalidHostContextMapValue(String hostname);

    @Message(id = 1064, value = "Failed to load OCSP responder certificate '%s'.")
    StartException failedToLoadResponderCert(String alias, @Cause Exception exception);

    @Message(id = 1066, value = "Invalid value for cipher-suite-names. %s")
    OperationFailedException invalidCipherSuiteNames(@Cause Throwable cause, String causeMessage);

    @Message(id = 1080, value = "Non existing key store needs to have defined type.")
    OperationFailedException nonexistingKeyStoreMissingType();

    @Message(id = 1085, value = "Multiple keystore definitions.")
    OperationFailedException multipleKeystoreDefinitions();
    @Message(id = 1086, value = "Missing keystore definition.")
    OperationFailedException missingKeyStoreDefinition();

    @Message(id = 1210, value = "Initialisation of an %s without an active management OperationContext is not allowed.")
    ExpressionResolver.ExpressionResolutionServerException illegalNonManagementInitialization(Class<?> initialzingClass);
}
