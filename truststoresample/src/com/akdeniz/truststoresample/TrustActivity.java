package com.akdeniz.truststoresample;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLHandshakeException;

import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.impl.client.DefaultHttpClient;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 
 * @author akdeniz
 * 
 */

public class TrustActivity extends Activity {

	static String TAG = "TrustActivity";

	public static Application app = null;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		app = getApplication();
		setContentView(R.layout.activity_trust);
	}

	public void showText(String message) {
		Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
	}

	public void startTrustedCerts(View v) {
		startActivity(new Intent(this, TrustedCertificates.class));
	}

	public void connect(View v) {
		TextView urlAddressText = (TextView) findViewById(R.id.etUrlAddress);
		if (urlAddressText.getText() != null) {
			try {
				new URL(urlAddressText.getText().toString());
				new Connector().execute(urlAddressText.getText().toString());
			} catch (MalformedURLException e) {
				Log.e(TAG, e.getMessage());
				Toast.makeText(this, "Enter a valid url", Toast.LENGTH_SHORT).show();
			}
		}
	}

	class Connector extends AsyncTask<String, X509Certificate[], AsyncTaskResult<HttpEntity>> {

		static final String TAG = "Connector";

		@Override
		protected AsyncTaskResult<HttpEntity> doInBackground(String... urls) {

			HttpClient client = new DefaultHttpClient();
			try {
				Log.i(TAG, "Getting : " + urls[0].toString());
				client.getConnectionManager().getSchemeRegistry().register(getMockedScheme());
				HttpGet getRequest = new HttpGet(urls[0]);
				return new AsyncTaskResult<HttpEntity>(client.execute(getRequest).getEntity());
			} catch (Exception e) {
				return new AsyncTaskResult<HttpEntity>(e);
			}

		}

		@Override
		protected void onPostExecute(AsyncTaskResult<HttpEntity> result) {
			Exception exception = result.getException();
			if (exception != null && exception instanceof SSLHandshakeException) {
				acceptKeyDialog();
			}

			HttpEntity entity = result.getResult();
			if (entity != null) {
				showText("Url content succesfully fetched!");
				// handle entity
			}
		}

		public Scheme getMockedScheme() throws KeyManagementException, UnrecoverableKeyException,
				NoSuchAlgorithmException, KeyStoreException {
			return new Scheme("https", new TrustedSSLSocketFactory(true), 443);
		}

		private void acceptKeyDialog() {

			final X509Certificate[] chain = TrustManagerFactory.getLastCertChain();

			StringBuilder chainInfo = new StringBuilder(100);
			MessageDigest sha1 = null;
			try {
				sha1 = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "Error initializing MessageDigest", e);
			}
			for (int i = 0; i < chain.length; i++) {

				chainInfo.append("Certificate chain[").append(i).append("]:\n");
				chainInfo.append("Subject: ").append(chain[i].getSubjectDN().toString()).append("\n");

				try {
					final Collection<List<?>> subjectAlternativeNames = chain[i].getSubjectAlternativeNames();
					if (subjectAlternativeNames != null) {
						StringBuilder altNamesText = new StringBuilder();
						altNamesText.append("Subject has ").append(subjectAlternativeNames.size())
								.append(" alternative names\n");

						for (List<?> subjectAlternativeName : subjectAlternativeNames) {
							Integer type = (Integer) subjectAlternativeName.get(0);
							Object value = subjectAlternativeName.get(1);
							String name = "";
							switch (type.intValue()) {
							case 0:
								Log.w(TAG, "SubjectAltName of type OtherName not supported.");
								continue;
							case 1: // RFC822Name
								name = (String) value;
								break;
							case 2: // DNSName
								name = (String) value;
								break;
							case 3:
								Log.w(TAG, "unsupported SubjectAltName of type x400Address");
								continue;
							case 4:
								Log.w(TAG, "unsupported SubjectAltName of type directoryName");
								continue;
							case 5:
								Log.w(TAG, "unsupported SubjectAltName of type ediPartyName");
								continue;
							case 6: // Uri
								name = (String) value;
								break;
							case 7: // ip-address
								name = (String) value;
								break;
							default:
								Log.w(TAG, "unsupported SubjectAltName of unknown type");
								continue;
							}

							altNamesText.append("Subject(alt): ").append(name).append(",...\n");
						}
						chainInfo.append(altNamesText);
					}
				} catch (Exception e1) {
					Log.w(TAG, "cannot display SubjectAltNames in dialog", e1);
				}

				chainInfo.append("Issuer: ").append(chain[i].getIssuerDN().toString()).append("\n");
				if (sha1 != null) {
					sha1.reset();
					try {
						char[] sha1sum = Hex.encodeHex(sha1.digest(chain[i].getEncoded()));
						chainInfo.append("Fingerprint (SHA-1): ").append(new String(sha1sum)).append("\n");
					} catch (CertificateEncodingException e) {
						Log.e(TAG, "Error while encoding certificate", e);
					}
				}
			}

			new AlertDialog.Builder(TrustActivity.this).setTitle("UNTRUSTED CERTIFICATE")
					.setMessage(chainInfo.toString()).setCancelable(true)
					.setPositiveButton("ACCEPT", new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
							try {
								TrustManagerFactory.addCertificateChain(chain);
								showText("Certificate is added to local truststore. Try again to connect!");
							} catch (CertificateException e) {
								Toast.makeText(TrustActivity.this,
										"CertificateException : " + e.getMessage() == null ? "[]" : e.getMessage(),
										Toast.LENGTH_SHORT).show();
							}
						}
					}).setNegativeButton("CANCEL", new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
						}
					}).show();

		}
	}

	class AsyncTaskResult<T> {
		private T result;
		private Exception exception;

		public AsyncTaskResult(T result) {
			this.result = result;
		}

		public AsyncTaskResult(Exception exception) {
			this.exception = exception;
		}

		public T getResult() {
			return result;
		}

		public Exception getException() {
			return exception;
		}
	}
}
