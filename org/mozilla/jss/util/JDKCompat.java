package org.mozilla.jss.util;

import java.lang.reflect.Method;

import javax.net.ssl.SSLParameters;

public class JDKCompat {
    public static class SSLParametersHelper {
        public static String[] getApplicationProtocols(SSLParameters inst) {
            try {
                Method getter = inst.getClass().getMethod("getApplicationProtocols");
                Object result = getter.invoke(inst);
                if (result instanceof String[]) {
                    return (String[]) result;
                }
            } catch (Throwable t) {}

            return null;
        }
    }
}
