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

import org.jboss.as.controller.OperationStepHandler;
import org.jboss.msc.Service;

/**
 * An {@link OperationStepHandler} which executes functions in the new {@link Service} API, and can 
 * check if an operation is running on a server or host {@link java.lang.ModuleLayer.Controller}
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a> 
 */
interface ElytronTlsOperationStepHandler extends ElytronOperationStepHandler {
}
