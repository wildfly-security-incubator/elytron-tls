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
