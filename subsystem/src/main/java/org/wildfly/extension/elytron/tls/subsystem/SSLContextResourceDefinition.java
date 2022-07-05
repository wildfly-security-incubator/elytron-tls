package org.wildfly.extension.elytron.tls.subsystem;

import org.jboss.as.controller.AbstractWriteAttributeHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ReloadRequiredWriteAttributeHandler;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.ManagementResourceRegistration;

public class SSLContextResourceDefinition extends SimpleResourceDefinition {

    private AttributeDefinition[] attributes;
    private boolean server;

    public SSLContextResourceDefinition(Parameters parameters, AttributeDefinition[] attributes, boolean server) {
        super(parameters);
        this.attributes = attributes;
        this.server = server;
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        if (attributes != null && attributes.length > 0) {
            AbstractWriteAttributeHandler writeHandler = new ReloadRequiredWriteAttributeHandler(attributes);
            for (AttributeDefinition current : attributes) {
                resourceRegistration.registerReadWriteAttribute(current, null, writeHandler);
            }
        }
    }
}
