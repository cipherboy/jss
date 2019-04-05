package org.mozilla.jss.ssl.javax;

import java.security.SecureRandom;
import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSContext extends SSLContextSpi {
    public static Logger logger = LoggerFactory.getLogger(JSSContext.class);

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) {
        logger.debug("JSSContext: engineInit(" + km + ", " + tm + ", " + sr + ")");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        logger.debug("JSSContext: engineCreateSSLEngine()");
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        logger.debug("JSSContext: engineCreateSSLEngine(" + host + ", " + port + ")");
        return null;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        logger.debug("JSSContext: engineGetClientSessionContext()");
        return null;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        logger.debug("JSSContext: engineGetServerSessionContext()");
        return null;
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        logger.debug("JSSContext: engineGetServerSocketFactory()");
        return null;
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        logger.debug("JSSContext: engineGetSocketFactory()");
        return null;
    }
}
