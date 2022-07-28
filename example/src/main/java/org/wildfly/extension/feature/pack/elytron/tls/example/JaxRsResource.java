package org.wildfly.extension.feature.pack.elytron.tls.example;

import javax.enterprise.context.RequestScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

/**
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 */
@RequestScoped
@Path("/")
public class JaxRsResource {

    @GET
    @Path("/greeting")
    public String getGreeting() {
        return "!";
    }
}
