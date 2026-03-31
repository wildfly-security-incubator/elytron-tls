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

package org.wildfly.extension.elytron_tls._private;

import org.jboss.logging.Logger;
import org.jboss.logging.annotations.MessageLogger;
import org.wildfly.extension.elytron.common.util.ElytronCommonMessages;

/**
 * Log messages for Elytron TLS subsystem
 *
 * @author <a href="mmazanek@redhat.com">Martin Mazanek</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
@MessageLogger(projectCode = "ELYTLS", length = 5)
public interface ElytronTLSMessages extends ElytronCommonMessages {

    ElytronTLSMessages LOGGER = Logger.getMessageLogger(ElytronTLSMessages.class, "org.wildfly.extension.elytron_tls");
}
