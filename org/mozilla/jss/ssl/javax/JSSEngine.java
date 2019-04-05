import java.lang.Runnable;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.nss.*;

public class JSSEngine extends javax.net.ssl.SSLEngine {
    public static Logger logger = LoggerFactory.getLogger(JSSEngine.class);

    private static int BUFFER_SIZE = 4096;

    private boolean is_client = false;
    private String peer_info = null;
    private BufferProxy read_buf = null;
    private BufferProxy write_buf = null;
    private PRFDProxy ssl_fd = null;

    public JSSEngine() {
        super();

        peer_info = "";
        logger.debug("JSSEngine: constructor()");
    }

    public JSSEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);

        peer_info = peerHost + ":" + peerPort;
        logger.debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ")");
    }

    private void init() {
        logger.debug("JSSEngine: init()");
        read_buf = Buffer.Create(BUFFER_SIZE);
        write_buf = Buffer.Create(BUFFER_SIZE);
        ssl_fd = PR.NewBufferPRFD(read_buf, write_buf, peer_info.getBytes());
    }

    public void beginHandshake() {
        logger.debug("JSSEngine: beginHandshake()");
        if (ssl_fd == null) {
            init();
        }

        SSL.ResetHandshake(ssl_fd, is_client);
    }

    public void closeInbound() {
        logger.debug("JSSEngine: closeInbound()");
    }

    public void closeOutbound() {
        logger.debug("JSSEngine: closeOutbound()");
    }

    public Runnable getDelegatedTask() {
        logger.debug("JSSEngine: getDelegatedTask()");
        return null;
    }

    public String[] getEnabledCipherSuites() {
        logger.debug("JSSEngine: getEnabledCipherSuites()");
        return null;
    }
    public String[] getEnabledProtocols() {
        logger.debug("JSSEngine: getEnabledProtocols()");
        return null;
    }
    public boolean getEnableSessionCreation() {
        logger.debug("JSSEngine: getEnableSessionCreation()");
        return false;
    }
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        logger.debug("JSSEngine: getHandshakeStatus()");
        return null;
    }
    public boolean getNeedClientAuth() {
        logger.debug("JSSEngine: getNeedClientAuth()");
        return false;
    }
    public SSLSession getSession() {
        logger.debug("JSSEngine: getSession()");
        return null;
    }
    public String[] getSupportedCipherSuites() {
        logger.debug("JSSEngine: getSupportedCipherSuites()");
        return null;
    }
    public String[] getSupportedProtocols() {
        logger.debug("JSSEngine: getSupportedProtocols()");
        return null;
    }
    public boolean getUseClientMode() {
        logger.debug("JSSEngine: getUseClientMode()");
        return false;
    }
    public boolean getWantClientAuth() {
        logger.debug("JSSEngine: getWantClientAuth()");
        return false;
    }
    public boolean isInboundDone() {
        logger.debug("JSSEngine: isInboundDone()");
        return false;
    }
    public boolean isOutboundDone() {
        logger.debug("JSSEngine: isOutboundDone()");
        return false;
    }

    public void setEnabledCipherSuites(String[] suites) {
        logger.debug("JSSEngine: setEnabledCipherSuites(");
        for (String suite : suites) {
            logger.debug("\t" + suite + ",");
        }
        logger.debug(")");
    }
    public void setEnabledProtocols(String[] protocols) {
        logger.debug("JSSEngine: setEnabledProtocols(");
        for (String protocol : protocols) {
            logger.debug("\t" + protocol + ",");
        }
        logger.debug(")");
    }
    public void setEnableSessionCreation(boolean flag) {
        logger.debug("JSSEngine: setEnableSessionCreation(" + flag + ")");
    }

    public void setNeedClientAuth(boolean need) {
        logger.debug("JSSEngine: setNeedClientAuth(" + need + ")");
    }

    public void setUseClientMode(boolean mode) {
        logger.debug("JSSEngine: setUseClientMode(" + mode + ")");
    }

    public void setWantClientAuth(boolean want) {
        logger.debug("JSSEngine: setWantClientAuth(" + want + ")");
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
        logger.debug("JSSEngine: unwrap()");
        return null;
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
        logger.debug("JSSEngine: wrap()");
        return null;
    }
}
