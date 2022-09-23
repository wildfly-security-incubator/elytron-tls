package org.wildfly.extension.elytron.tls.subsystem;

import static org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger.LOGGER;

import org.wildfly.common.function.ExceptionFunction;

/**
 * Captures a {@link Service} method as an {@link ExceptionFunction} to make available to runtime
 * operations. Derived from {@link org.jboss.as.clustering.controller.OperationFunction<T, V>}.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */

public class RuntimeServiceFunction<T, R, E extends Exception> extends RuntimeServiceObject<T> implements ExceptionFunction<T, R, E> {

    /* Remaining point is that not using the object field makes operating on this ExceptionFunction itself
     * [ function.execute() ] impossible. This is likely not desired, calling another function to operate on
     * itself may cause issues. Will add brief explainer to overriding method. */

    RuntimeServiceFunction() {
        objectAccepted = true;
        objectClass = ExceptionFunction.class;
    }

    @Override
    public synchronized void accept(T acceptedValue) {
        throw LOGGER.RuntimeServiceFunctionAlreadyInitialized();
    }

    /**
     * Use the service function to execute an operation on the value.
     * 
     * @param value the value to execute on
     * @return the function result
     * @throws E if an exception occurs
     */
    @Override
    public R apply(T value) throws E {
        return null;
    }
}
