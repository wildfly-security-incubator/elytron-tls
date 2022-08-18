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

import static org.wildfly.extension.elytron.tls.subsystem.Constants.ENCRYPTION;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.EXPRESSION;
import static org.wildfly.extension.elytron.tls.subsystem.Constants.EXPRESSION_RESOLVER;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceXMLDescription;

class ExpressionResolverParser {
    final PersistentResourceXMLDescription expressionResolverParser_1_0 = PersistentResourceXMLDescription.builder(
            PathElement.pathElement(EXPRESSION, ENCRYPTION))
            .setXmlElementName(EXPRESSION_RESOLVER)
            .addAttribute(ExpressionResolverResourceDefinition.RESOLVERS)
            .addAttribute(ExpressionResolverResourceDefinition.DEFAULT_RESOLVER)
            .addAttribute(ExpressionResolverResourceDefinition.PREFIX)
            .build();
}
