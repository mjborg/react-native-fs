package com.rnfs;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

//start
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

import javax.net.ssl.HttpsURLConnection;  
import javax.net.ssl.SSLContext;  
import javax.net.ssl.SSLSocketFactory;  
import javax.net.ssl.TrustManager; 
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
//end

import android.util.Log;

import android.os.AsyncTask;

import com.facebook.react.bridge.ReadableMapKeySetIterator;

public class Downloader extends AsyncTask<DownloadParams, long[], DownloadResult> {
  private DownloadParams mParam;
  private AtomicBoolean mAbort = new AtomicBoolean(false);
  DownloadResult res;

  protected DownloadResult doInBackground(DownloadParams... params) {
    mParam = params[0];
    res = new DownloadResult();

    new Thread(new Runnable() {
      public void run() {
        try {
          download(mParam, res);
          mParam.onTaskCompleted.onTaskCompleted(res);
        } catch (Exception ex) {
          res.exception = ex;
          mParam.onTaskCompleted.onTaskCompleted(res);
        }
      }
    }).start();

    return res;
  }

  private void download(DownloadParams param, DownloadResult res) throws Exception {
    InputStream input = null;
    OutputStream output = null;
    HttpsURLConnection connection = null;

    try {
      connection = (HttpsURLConnection)param.src.openConnection();
      trustAllHosts(connection);
      connection.getHostnameVerifier();
      connection.setHostnameVerifier(DO_NOT_VERIFY);
      
      ReadableMapKeySetIterator iterator = param.headers.keySetIterator();

      while (iterator.hasNextKey()) {
        String key = iterator.nextKey();
        String value = param.headers.getString(key);
        connection.setRequestProperty(key, value);
      }

      connection.setConnectTimeout(param.connectionTimeout);
      connection.setReadTimeout(param.readTimeout);
      connection.connect();

      int statusCode = connection.getResponseCode();
      long lengthOfFile = getContentLength(connection);

      boolean isRedirect = (
        statusCode != HttpsURLConnection.HTTP_OK &&
        (
          statusCode == HttpsURLConnection.HTTP_MOVED_PERM ||
          statusCode == HttpsURLConnection.HTTP_MOVED_TEMP ||
          statusCode == 307 ||
          statusCode == 308
        )
      );

      if (isRedirect) {
        String redirectURL = connection.getHeaderField("Location");
        connection.disconnect();

        connection = (HttpsURLConnection) new URL(redirectURL).openConnection();
        connection.setConnectTimeout(5000);
        connection.connect();

        statusCode = connection.getResponseCode();
        lengthOfFile = getContentLength(connection);
      }
      if(statusCode >= 200 && statusCode < 300) {
        Map<String, List<String>> headers = connection.getHeaderFields();

        Map<String, String> headersFlat = new HashMap<String, String>();

        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
          String headerKey = entry.getKey();
          String valueKey = entry.getValue().get(0);

          if (headerKey != null && valueKey != null) {
            headersFlat.put(headerKey, valueKey);
          }
        }

        mParam.onDownloadBegin.onDownloadBegin(statusCode, lengthOfFile, headersFlat);

        input = new BufferedInputStream(connection.getInputStream(), 8 * 1024);
        output = new FileOutputStream(param.dest);

        byte data[] = new byte[8 * 1024];
        long total = 0;
        int count;
        double lastProgressValue = 0;

        while ((count = input.read(data)) != -1) {
          if (mAbort.get()) throw new Exception("Download has been aborted");

          total += count;
          if (param.progressDivider <= 0) {
            publishProgress(new long[]{lengthOfFile, total});
          } else {
            double progress = Math.round(((double) total * 100) / lengthOfFile);
            if (progress % param.progressDivider == 0) {
              if ((progress != lastProgressValue) || (total == lengthOfFile)) {
                Log.d("Downloader", "EMIT: " + String.valueOf(progress) + ", TOTAL:" + String.valueOf(total));
                lastProgressValue = progress;
                publishProgress(new long[]{lengthOfFile, total});
              }
            }
          }
          output.write(data, 0, count);
        }

        output.flush();
        res.bytesWritten = total;
      }
      res.statusCode = statusCode;
    } finally {
      if (output != null) output.close();
      if (input != null) input.close();
      if (connection != null) connection.disconnect();
    }
  }


//====================== 信任所有证书
private static final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
  public java.security.cert.X509Certificate[] getAcceptedIssuers() {
    return new java.security.cert.X509Certificate[]{};
  }
 
  public void checkClientTrusted(X509Certificate[] chain, String authType)
          throws CertificateException {
  }
 
  public void checkServerTrusted(X509Certificate[] chain, String authType)
          throws CertificateException {
  }
}};
 
  /**
   * 设置不验证主机
   */
  private static final HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
      return true;
    }
  };
 
  /**
   * 信任所有
   * @param connection
   * @return
   */
  private static SSLSocketFactory trustAllHosts(HttpsURLConnection connection) {
    SSLSocketFactory oldFactory = connection.getSSLSocketFactory();
    try {
      SSLContext sc = SSLContext.getInstance("TLS");
      sc.init(null, trustAllCerts, new java.security.SecureRandom());
      SSLSocketFactory newFactory = sc.getSocketFactory();
      connection.setSSLSocketFactory(newFactory);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return oldFactory;
  }
 //=================


  private long getContentLength(HttpURLConnection connection){
    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
      return connection.getContentLengthLong();
    }
    return connection.getContentLength();
  }

  protected void stop() {
    mAbort.set(true);
  }

  @Override
  protected void onProgressUpdate(long[]... values) {
    super.onProgressUpdate(values);
    mParam.onDownloadProgress.onDownloadProgress(values[0][0], values[0][1]);
  }

  protected void onPostExecute(Exception ex) {

  }
}
