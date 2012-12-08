package com.akdeniz.truststoresample;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.http.conn.ssl.SSLSocketFactory;


/**
 * SSL Socket Factory class that allows you to create SSL sockets. Underneath
 * it uses {@link TrustManagerFactory} to create fake or secure trust store.
 * 
 * @author akdeniz
 *
 */
class TrustedSSLSocketFactory extends SSLSocketFactory {
	
	javax.net.ssl.SSLSocketFactory socketFactory = null;

	public TrustedSSLSocketFactory(boolean secure) throws KeyManagementException, UnrecoverableKeyException,
			NoSuchAlgorithmException, KeyStoreException {
		super(null);
		
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, new TrustManager[] { TrustManagerFactory.get(secure) }, null);
		socketFactory = sslContext.getSocketFactory();
	}

	@Override
	public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException,
			UnknownHostException {
		return socketFactory.createSocket(socket, host, port, autoClose);
	}

	@Override
	public Socket createSocket() throws IOException {
		return socketFactory.createSocket();
	}
}
