package com.akdeniz.truststoresample;

import android.content.Context;
import android.util.Log;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

/**
 * TrustManager factory allows to create secure or fake trust managers. 
 * 
 * Fake trust manager does not make any certificate check.
 * 
 * Secure trust manager first checks server certificate against android internal truststore. 
 * If certificate is not allowed in that store, then it is checked against local application truststore.
 * Client certificates are only checked against android internal truststore.
 * 
 * This class can also add certificates to local application truststore.
 * 
 * @author akdeniz
 *
 */
public final class TrustManagerFactory {
	
	private static final String TAG = "TrustManagerFactory";

	private static X509TrustManager defaultTrustManager;
	private static X509TrustManager unsecureTrustManager;
	private static X509TrustManager secureTrustManager;
	private static X509TrustManager localTrustManager;

	private static X509Certificate[] lastCertChain = null;
	
	private static File keyStoreFile;
	private static KeyStore keyStore;

	private static class UnsecureX509TrustManager implements X509TrustManager {
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}

	private static class SecureX509TrustManager implements X509TrustManager {

		public SecureX509TrustManager() {
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			defaultTrustManager.checkClientTrusted(chain, authType);
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			
			TrustManagerFactory.setLastCertChain(chain);
			try {
				defaultTrustManager.checkServerTrusted(chain, authType);
			} catch (CertificateException e) {
				localTrustManager.checkServerTrusted(new X509Certificate[] { chain[0] }, authType);
			}
			try {
				String dn = chain[0].getSubjectDN().toString();
				if ((dn != null) && (dn.equalsIgnoreCase(keyStore.getCertificateAlias(chain[0])))) {
					return;
				}
			} catch (KeyStoreException e) {
				throw new CertificateException("Certificate cannot be verified; KeyStore Exception: " + e);
			}
		}

		public X509Certificate[] getAcceptedIssuers() {
			return defaultTrustManager.getAcceptedIssuers();
		}

	}

	static {
		InputStream fis = null;
		try {
			javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("X509");
			keyStoreFile = new File(TrustActivity.app.getDir("KeyStore", Context.MODE_PRIVATE) + File.separator + "KeyStore.bks");
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			try {
				fis = new java.io.FileInputStream(keyStoreFile);
			} catch (FileNotFoundException e1) {
				fis = null;
			}
			try {
				keyStore.load(fis, "".toCharArray());
			} catch (IOException e) {
				Log.e(TAG, "KeyStore IOException while initializing TrustManagerFactory ", e);
				keyStore = null;
			} catch (CertificateException e) {
				Log.e(TAG, "KeyStore CertificateException while initializing TrustManagerFactory ", e);
				keyStore = null;
			}
			tmf.init(keyStore);
			TrustManager[] tms = tmf.getTrustManagers();
			if (tms != null) {
				for (TrustManager tm : tms) {
					if (tm instanceof X509TrustManager) {
						localTrustManager = (X509TrustManager) tm;
						break;
					}
				}
			}
			tmf = javax.net.ssl.TrustManagerFactory.getInstance("X509");
			tmf.init((KeyStore) null);
			tms = tmf.getTrustManagers();
			if (tms != null) {
				for (TrustManager tm : tms) {
					if (tm instanceof X509TrustManager) {
						defaultTrustManager = (X509TrustManager) tm;
						break;
					}
				}
			}

		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "Unable to get X509 Trust Manager ", e);
		} catch (KeyStoreException e) {
			Log.e(TAG, "Key Store exception while initializing TrustManagerFactory ", e);
		} finally {
			try {
				fis.close();
			} catch (Exception e) {
				Log.e(TAG, "unable to close keystore file");
			}
		}

		unsecureTrustManager = new UnsecureX509TrustManager();
		secureTrustManager = new SecureX509TrustManager();
	}

	private TrustManagerFactory() {
	}

	public static X509TrustManager get(boolean secure) {
		return secure ? secureTrustManager : unsecureTrustManager;
	}

	public static KeyStore getKeyStore() {
		return keyStore;
	}
	
	public static void setLastCertChain(X509Certificate[] chain) {
        lastCertChain = chain;
    }
    public static X509Certificate[] getLastCertChain() {
        return lastCertChain;
    }
    
    public static X509Certificate[] getTrustedCertificates() {
    	if(localTrustManager!=null){
    		return localTrustManager.getAcceptedIssuers();
    	}
    	return null;
	}

	public static void addCertificateChain(X509Certificate[] chain) throws CertificateException {
		try {
			javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("X509");
			for (X509Certificate element : chain) {
				keyStore.setCertificateEntry(element.getSubjectDN().toString(), element);
			}

			tmf.init(keyStore);
			TrustManager[] tms = tmf.getTrustManagers();
			if (tms != null) {
				for (TrustManager tm : tms) {
					if (tm instanceof X509TrustManager) {
						localTrustManager = (X509TrustManager) tm;
						break;
					}
				}
			}
			java.io.OutputStream keyStoreStream = null;
			try {
				keyStoreStream = new java.io.FileOutputStream(keyStoreFile);
				keyStore.store(keyStoreStream, "".toCharArray());
			} catch (FileNotFoundException e) {
				throw new CertificateException("Unable to write keystore: " + e.getMessage());
			} catch (CertificateException e) {
				throw new CertificateException("Unable to write keystore: " + e.getMessage());
			} catch (IOException e) {
				throw new CertificateException("Unable to write keystore: " + e.getMessage());
			} finally {
				try {
					keyStoreStream.close();
				} catch (IOException e) {
					Log.e(TAG, "unable to close keystore file");
				}
			}
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "key store exception", e);
		} catch (KeyStoreException e) {
			Log.e(TAG, "key store exception", e);
		}
	}

	public static void updateTrustedCertificates(List<X509Certificate> certs) throws CertificateException {
		try {
			// wipe all cert entries
			Enumeration<String> aliases = keyStore.aliases();
			while(aliases.hasMoreElements()){
				String alias = aliases.nextElement();
				if(keyStore.isCertificateEntry(alias)){
					keyStore.deleteEntry(alias);
				}
			}

			addCertificateChain(certs.toArray(new X509Certificate[]{}));
		} catch (KeyStoreException e) {
			Log.e(TAG, "key store exception", e);
		}
	}
}
