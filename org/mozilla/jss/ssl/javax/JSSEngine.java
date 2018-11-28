import java.lang.Runnable;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

class JSSEngine extends javax.net.ssl.SSLEngine {
    public JSSEngine() {
        super();
    }

    public JSSEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);
    }

    public void beginHandshake() {}
    public void closeInbound() {}
    public void closeOutbound() {}
    public Runnable getDelegatedTask() {}
    public String[] getEnabledCipherSuites() {}
    public String[] getEnabledProtocols() {}
    public boolean getEnableSessionCreation() {}
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {}
    public boolean getNeedClientAuth() {}
    public SSLSession getSession() {}
    public String[] getSupportedCipherSuites() {}
    public String[] getSupportedProtocols() {}
    public boolean getUseClientMode() {}
    public boolean getWantClientAuth() {}
    public boolean isInboundDone() {}
    public boolean isOutboundDone() {}

    public void setEnabledCipherSuites(String[] suites) {}
    public void setEnabledProtocols(String[] protocols) {}
    public void setEnableSessionCreation(boolean flag) {}

    public void setNeedClientAuth(boolean need) {}

    public void setUseClientMode(boolean mode) {}
    public void setWantClientAuth(boolean want) {}

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {}
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {}
}
