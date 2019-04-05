package org.mozilla.jss.ssl.javax;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.*;

public class JSSServerSocketFactory extends SSLServerSocketFactory {
    public static Logger logger = LoggerFactory.getLogger(JSSServerSocketFactory.class);

    public ServerSocket createServerSocket(int port) {
        logger.debug("JSSServerSocketFactory: createServerSocket(" + port + ")");
        return null;
    }

    public ServerSocket createServerSocket(int port, int backlog) {
        logger.debug("JSSServerSocketFactory: createServerSocket(" + port + ", " + backlog + ")");
        return null;
    }

    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) {
        logger.debug("JSSServerSocketFactory: createServerSocket(" + port + ", " + backlog + ", " + ifAddress + ")");
        return null;
    }

    public String[] getDefaultCipherSuites() {
        logger.debug("JSSServerSocketFactory: getDefaultCipherSuites()");
        return null;
    }

    public String[] getSupportedCipherSuites() {
        logger.debug("JSSServerSocketFactory: getSupportedCipherSuites()");
        return null;
    }
}
