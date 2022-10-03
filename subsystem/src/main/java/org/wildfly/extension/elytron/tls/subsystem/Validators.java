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

import static org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger.LOGGER;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.operations.validation.ModelTypeValidator;
import org.jboss.as.controller.operations.validation.ParameterValidator;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.wildfly.security.ssl.CipherSuiteSelector;

public class Validators {


    static class CipherSuiteFilterValidator extends ModelTypeValidator {

        CipherSuiteFilterValidator() {
            super(ModelType.STRING, true, true, false);
        }

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            super.validateParameter(parameterName, value);
            if (value.isDefined()) {
                try {
                    CipherSuiteSelector.fromString(value.asString());
                } catch (IllegalArgumentException e) {
                    throw LOGGER.invalidCipherSuiteFilter(e, e.getLocalizedMessage());
                }
            }
        }
    }
    static class CipherSuiteNamesValidator extends ModelTypeValidator {

        CipherSuiteNamesValidator() {
            super(ModelType.STRING, true, true, false);
        }

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            super.validateParameter(parameterName, value);
            if (value.isDefined()) {
                try {
                    CipherSuiteSelector.fromNamesString(value.asString());
                } catch (IllegalArgumentException e) {
                    throw LOGGER.invalidCipherSuiteNames(e, e.getLocalizedMessage());
                }
            }
        }
    }

    static class HostContextMapValidator implements ParameterValidator {
        // Hostnames can contain ASCII letters a-z (case-insensitive), digits 0-9, hyphens and dots.
        // This pattern allows also [,],*,? characters to make regular expressions possible. Non-escaped dot represents any character, escaped dot is delimeter.
        static Pattern hostnameRegexPattern = Pattern.compile("[0-9a-zA-Z\\[.*]" + // first character can be digit, letter, left square bracket, non-escaped dot or asterisk
                "([0-9a-zA-Z*.\\[\\]?^-]" + // any combination of digits, letters, asterisks, non-escaped dots, square brackets, question marks, hyphens and carets
                "|" +                       // OR
                "(?<!\\\\\\.)\\\\\\.)*" +   // if there is an escaped dot, there cannot be another escaped dot right behind it
                // backslash must be escaped, so '\\\\' translates to literally slash, and '\\.' translates to literally dot
                "[0-9a-zA-Z*.\\[\\]?]");   // escaped dot or hyphen cannot be at the end

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            if (value.isDefined()) {
                for (String hostname : value.keys()) {
                    if (!hostnameRegexPattern.matcher(hostname).matches()) {
                        throw LOGGER.invalidHostContextMapValue(hostname);
                    }
                    try {
                        Pattern.compile(hostname);  // make sure the input is valid regex as well (eg. will check that the square brackets are paired)
                    } catch (PatternSyntaxException exception) {
                        throw LOGGER.invalidHostContextMapValue(hostname);
                    }
                }
            }
        }
    }
}
