package com.akdeniz.truststoresample;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import android.app.AlertDialog;
import android.app.ListActivity;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 
 * @author akdeniz
 *
 */

public class TrustedCertificates extends ListActivity implements OnClickListener {

	ArrayAdapter<X509Certificate> adapter;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.trustedcerts);

		((Button) findViewById(R.id.done)).setOnClickListener(this);

		X509Certificate[] trustedCertificates = TrustManagerFactory.getTrustedCertificates();
		ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
		for (X509Certificate x509Certificate : trustedCertificates) {
			certs.add(x509Certificate);
		}
		adapter = new CertificateListAdapter(this, certs);
		setListAdapter(adapter);
	}
	
	@Override
	public void onClick(View v) {

		switch (v.getId()) {
		case R.id.done:
			updateTrustStore();
			finish();
			break;
		default:
			break;
		}
	}


	private void updateTrustStore() {
		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		for (int i = 0; i < adapter.getCount(); i++) {
			certs.add(adapter.getItem(i));
		}
		
		try {
			TrustManagerFactory.updateTrustedCertificates(certs);
		} catch (CertificateException e) {
			Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
		}
	}

	@Override
	protected void onListItemClick(ListView l, View v, int position, long id) {
		deleteTrustedCert(position);
		super.onListItemClick(l, v, position, id);
	}

	private void deleteTrustedCert(final int position) {

		AlertDialog.Builder alert = new AlertDialog.Builder(this);
		alert.setTitle("Remove?");
		alert.setMessage("Do you want to delete this trusted certificate");
		alert.setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				adapter.remove(adapter.getItem(position));
				adapter.notifyDataSetChanged();
			}
		});
		alert.setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {

			}
		});
		alert.show();
	}
	
	class CertificateListAdapter extends ArrayAdapter<X509Certificate> {

		LayoutInflater inflater = null;
		
		public CertificateListAdapter(Context context, List<X509Certificate> certs) {
			super(context, R.layout.cert_row, certs);
			inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
		}
		
		@Override
		public View getView(int position, View convertView, ViewGroup parent) {
			
			View view;
	        TextView text;

	        if (convertView == null) {
	            view = inflater.inflate(R.layout.cert_row, parent, false);
	        } else {
	            view = convertView;
	        }

	        text = (TextView) view;

	        X509Certificate item = getItem(position);
            text.setText(item.getSubjectX500Principal().getName());

	        return view;
		}
	}
}


