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

import java.io.IOException;
import java.security.NoSuchProviderException;

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

    /**
     * An {@link OperationFailedException} where the name of the operation does not match the expected names.
     *
     * @param actualName the operation name contained within the request.
     * @param expectedNames the expected operation names.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 8, value = "Invalid operation name '%s', expected one of '%s'")
    OperationFailedException invalidOperationName(String actualName, String... expectedNames);

    /**
     * An {@link RuntimeException} where an operation can not be completed.
     *
     * @param cause the underlying cause of the failure.
     * @return The {@link RuntimeException} for the error.
     */
    @Message(id = 9, value = "Unable to complete operation. '%s'")
    RuntimeException unableToCompleteOperation(@Cause Throwable cause, String causeMessage);

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

    /*
     * Credential Store Section.
     */

    @Message(id = 909, value = "Credential store '%s' does not support given credential store entry type '%s'")
    OperationFailedException credentialStoreEntryTypeNotSupported(String credentialStoreName, String entryType);

    @Message(id = 910, value = "Password cannot be resolved for key-store '%s'")
    IOException keyStorePasswordCannotBeResolved(String path);

    @Message(id = 911, value = "Credential store '%s' protection parameter cannot be resolved")
    IOException credentialStoreProtectionParameterCannotBeResolved(String name);

    @Message(id = 913, value = "Credential alias '%s' of credential type '%s' already exists in the store")
    OperationFailedException credentialAlreadyExists(String alias, String credentialType);

    @Message(id = 914, value = "Provider loader '%s' cannot supply Credential Store provider of type '%s'")
    NoSuchProviderException providerLoaderCannotSupplyProvider(String providerLoader, String type);

    @Message(id = 920, value = "Credential alias '%s' of credential type '%s' does not exist in the store")
    OperationFailedException credentialDoesNotExist(String alias, String credentialType);

    @Message(id = 921, value = "Location parameter is not specified for filebased keystore type '%s'")
    OperationFailedException filebasedKeystoreLocationMissing(String type);

    @Message(id = Message.NONE, value = "Reload dependent services which might already have cached the secret value")
    String reloadDependantServices();

    @Message(id = Message.NONE, value = "Update dependent resources as alias '%s' does not exist anymore")
    String updateDependantServices(String alias);

    @Message(id = 922, value = "Unable to load credential from credential store.")
    ExpressionResolver.ExpressionResolutionUserException unableToLoadCredential(@Cause Throwable cause);

    @Message(id = 923, value = "Unable to encrypt the supplied clear text.")
    OperationFailedException unableToEncryptClearText(@Cause Throwable cause);

    @Message(id = 924, value = "Unable to create immediately available credential store.")
    OperationFailedException unableToCreateCredentialStoreImmediately(@Cause Throwable cause);

    @Message(id = 925, value = "Unable to reload the credential store.")
    OperationFailedException unableToReloadCredentialStore(@Cause Throwable cause);

    @Message(id = 926, value = "Unable to initialize the credential store.")
    OperationFailedException unableToInitialiseCredentialStore(@Cause Throwable cause);

    @Message(id = 927, value = "The secret key operation '%s' failed to complete due to '%s'.")
    OperationFailedException secretKeyOperationFailed(String operationName, String error, @Cause Throwable cause);

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

    @Message(id = 1200, value = "The name of the resolver to use was not specified and no default-resolver has been defined.")
    OperationFailedException noResolverSpecifiedAndNoDefault();

    @Message(id = 1201, value = "No expression resolver has been defined with the name '%s'.")
    OperationFailedException noResolverWithSpecifiedName(String name);

    @Message(id = 1202, value = "A cycle has been detected initialising the expression resolver for '%s' and '%s'.")
    ExpressionResolver.ExpressionResolutionUserException cycleDetectedInitialisingExpressionResolver(String firstExpression, String secondExpression);

    @Message(id = 1203, value = "Expression resolver initialisation has already failed.")
    ExpressionResolver.ExpressionResolutionUserException expressionResolverInitialisationAlreadyFailed(@Cause Throwable cause);

    @Message(id = 1204, value = "The expression '%s' does not specify a resolver and no default is defined.")
    ExpressionResolver.ExpressionResolutionUserException expressionResolutionWithoutResolver(String expression);

    @Message(id = 1205, value = "The expression '%s' specifies a resolver configuration which does not exist.")
    ExpressionResolver.ExpressionResolutionUserException invalidResolver(String expression);

    @Message(id = 1206, value = "Unable to decrypt expression '%s'.")
    ExpressionResolver.ExpressionResolutionUserException unableToDecryptExpression(String expression, @Cause Throwable cause);

    @Message(id = 1207, value = "Resolution of credential store expressions is not supported in the MODEL stage of operation execution.")
    ExpressionResolver.ExpressionResolutionServerException modelStageResolutionNotSupported(@Cause IllegalStateException cause);

    @Message(id = 1208, value = "Unable to resolve CredentialStore %s -- %s")
    ExpressionResolver.ExpressionResolutionServerException unableToResolveCredentialStore(String storeName, String details, @Cause Exception cause);

    @Message(id = 1209, value = "Unable to initialize CredentialStore %s -- %s")
    ExpressionResolver.ExpressionResolutionUserException unableToInitializeCredentialStore(String storeName, String details, @Cause Exception cause);

    @Message(id = 1210, value = "Initialisation of an %s without an active management OperationContext is not allowed.")
    ExpressionResolver.ExpressionResolutionServerException illegalNonManagementInitialization(Class<?> initialzingClass);
}
