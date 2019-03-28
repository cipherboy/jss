import java.lang.Runnable;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import org.mozilla.jss.nss.*;

public class JSSEngine extends javax.net.ssl.SSLEngine {
    private boolean is_client = false;
    private String peer_info = null;
    private BufferProxy read_buf = null;
    private BufferProxy write_buf = null;
    private PRFDProxy ssl_fd = null;

    public JSSEngine() {
        super();

        peer_info = "";
    }

    public JSSEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);
        peer_info = peerHost + ":" + peerPort;
    }

    public void beginHandshake() {
        SSL.ResetHandshake(ssl_fd, is_client);
    }

    public void closeInbound() {}
    public void closeOutbound() {}
    public Runnable getDelegatedTask() {
        return null;
    }

    public String[] getEnabledCipherSuites() {
        return null;
    }
    public String[] getEnabledProtocols() {
        return null;
    }
    public boolean getEnableSessionCreation() {
        return false;
    }
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return null;
    }
    public boolean getNeedClientAuth() {
        return false;
    }
    public SSLSession getSession() {
        return null;
    }
    public String[] getSupportedCipherSuites() {
        return null;
    }
    public String[] getSupportedProtocols() {
        return null;
    }
    public boolean getUseClientMode() {
        return false;
    }
    public boolean getWantClientAuth() {
        return false;
    }
    public boolean isInboundDone() {
        return false;
    }
    public boolean isOutboundDone() {
        return false;
    }

    public void setEnabledCipherSuites(String[] suites) {}
    public void setEnabledProtocols(String[] protocols) {}
    public void setEnableSessionCreation(boolean flag) {}

    public void setNeedClientAuth(boolean need) {}

    public void setUseClientMode(boolean mode) {}
    public void setWantClientAuth(boolean want) {}

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
        return null;
    }
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
        return null;
    }
}
