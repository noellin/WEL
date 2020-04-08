package com.igpublish.wel;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.MediaType;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthController {

	private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    final int bufferSize = 1_000_000; // about 1 MB; must be large enough to hold all the http content
    
	@Value("${auth.server.url}")
	String auth_server_url;

	@Value("${auth.server.clientId}")
	String auth_client;

	@Value("${auth.server.clientSecret}")
	String auth_secret;   
	
	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/info", method = RequestMethod.GET)
	public String info(Model model, HttpServletRequest httprequest, HttpServletResponse httpresponse) {
		
        String auth_header = httprequest.getHeader("Authorization");
        if(auth_header == null) {
            auth_header = httprequest.getHeader("authorization");
        }
        
        // Add the Log to Report-Server
     	if(auth_header != null) {

     			Base64.Decoder decoder = Base64.getDecoder();
     			try {
     				  
     				HttpClient client = HttpClientBuilder.create().build();
     				
     		    	String url = auth_server_url+"/auth/me";
     		    	
     		    	HttpPost httpPost = new HttpPost(url);
     		    			 httpPost.addHeader("Authorization",auth_header);
     		    			
     		    	HttpResponse response;		    	
     				response = client.execute(httpPost);
     				
     				int statusCode = response.getStatusLine().getStatusCode();
     			
         		    HttpEntity entity = response.getEntity();
         		    InputStream  is = new BufferedInputStream(entity.getContent(), bufferSize);
         		    			 is.mark(bufferSize);
         		    			 
         		    String restext = IOUtils.toString(is, "utf-8");
         		    
         		    JSONObject resJson = new JSONObject(restext);
         		    
         		    return new String(decoder.decode(resJson.getString("name").getBytes()), "UTF-8");
         		    
     			} catch (ClientProtocolException e) {
     				e.printStackTrace();
     			} catch (IOException e) {
     				e.printStackTrace();
     			} 
     	}
		
		return "Error";
		
	}

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/ip", method = RequestMethod.GET)
	public String ip(Model model, HttpServletRequest httprequest, HttpServletResponse httpresponse) {
		String remoteAddress = httprequest.getRemoteAddr();
		return remoteAddress;
	}
	
	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/verify", method = RequestMethod.GET)
	public HashMap verifyAccessCommon(Model model, HttpServletRequest httprequest, HttpServletResponse httpresponse) {

		HashMap result = new HashMap();
		String remoteAddress = httprequest.getRemoteAddr();
        String remoteUrl = (String) httprequest.getSession().getAttribute("referer");
        String remoteAffiliate = (String) httprequest.getSession().getAttribute("affiliate");
        result = verify("ip", remoteAddress, remoteUrl, null, null, httprequest.getSession().getId(), httprequest);
        if(result.containsKey("error") && remoteUrl != null && remoteUrl.startsWith("http")) {
        	result = verify("referer", remoteAddress, remoteUrl, null, null, httprequest.getSession().getId(), httprequest);
            if(result.containsKey("error") && remoteAffiliate != null && !remoteAffiliate.trim().equals("")) {
        		return verify("key", remoteAddress, remoteUrl, remoteAffiliate, null, httprequest.getSession().getId(), httprequest);
            }
        }
		return result;
	}

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/verify/key", method = RequestMethod.GET)
	public HashMap verifyAccessAffiliateKey(Model model, HttpServletRequest httprequest, HttpServletResponse httpresponse) {
		HashMap result = new HashMap();
		String remoteAddress = httprequest.getRemoteAddr();
        String remoteUrl = httprequest.getHeader("referer");
		String key = httprequest.getParameter("AffiliateKey");
		return verify("key", remoteAddress, remoteUrl, key, null, httprequest.getSession().getId(), httprequest);
	}

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/verify/login", method = RequestMethod.POST)
	public HashMap verifyAccessLogin(Model model, HttpServletRequest httprequest, HttpServletResponse httpresponse) {
		HashMap result = new HashMap();
		String remoteAddress = httprequest.getRemoteAddr();
        String remoteUrl = httprequest.getHeader("referer");
		String username = (String) httprequest.getParameter("username");
		String password = (String) httprequest.getParameter("password");
		
		System.out.println(username + " \t " + password);
		
		return verify("login", remoteAddress, remoteUrl, username, password, httprequest.getSession().getId(), httprequest);
		
	}

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/revoke/{token}", method = RequestMethod.GET)
	public HashMap verifyAccessLogin(Model model, HttpServletRequest httprequest, HttpServletResponse httpresponse,
			@PathVariable("token") String token) {
		
		// Invalid the user's current session too
		HttpSession session = httprequest.getSession(false);
		
		if(session!=null)
			session.invalidate();

		return revoke(token);
	}
	
	private HashMap verify(String type, String ip, String referer, String access, String value, String sessionid, HttpServletRequest httprequest) {
		HashMap result = new HashMap();
		
		JSONObject authInfo = null;
		
		if(type.equalsIgnoreCase("ip")) {
			authInfo = new JSONObject();
			LOG.info("Verify ip " + ip);
			authInfo.put("session", sessionid);
			authInfo.put("type", "ip");
			authInfo.put("value", ip);
			authInfo.put("ip", ip);
			authInfo.put("referer", referer);
		}else if(type.equalsIgnoreCase("referer")) {
			LOG.info("Verify referer " + referer);
			authInfo = new JSONObject();
			authInfo.put("session", sessionid);
			authInfo.put("type", "referer");
			authInfo.put("value", referer);
			authInfo.put("ip", ip);
			authInfo.put("referer", referer);
		}else if(type.equalsIgnoreCase("key")) {
			LOG.info("Verify Key " + access);
			authInfo = new JSONObject();
			authInfo.put("session", sessionid);
			authInfo.put("type", "key");
			authInfo.put("value", access);
			authInfo.put("ip", ip);
			authInfo.put("referer", referer);
		}else if(type.equalsIgnoreCase("login")) {
			LOG.info("Verify " + access);
			authInfo = new JSONObject();
			authInfo.put("session", sessionid);
			authInfo.put("type", "login");
			authInfo.put("username", access);
			authInfo.put("password", value);
			authInfo.put("ip", ip);
			authInfo.put("referer", referer);
		}
	    
		// Add the Log to Report-Server
		if(authInfo != null) {

			Base64.Encoder encoder = Base64.getEncoder();

			try {
					
				String encodedUser = encoder.encodeToString(authInfo.toString().getBytes("UTF-8"));
    		    
				CredentialsProvider provider = new BasicCredentialsProvider();
				UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(auth_client, auth_secret);
				provider.setCredentials(AuthScope.ANY, credentials);
				  
				HttpClient client = HttpClientBuilder.create().setDefaultCredentialsProvider(provider).build();

		    	String url = auth_server_url+"/auth/oauth/token";

    		    //System.out.println("auth_server_url\t"+url);
		    	HttpPost httpPost = new HttpPost(url);
		    	
		    	List<NameValuePair> params = new ArrayList<NameValuePair>();
		    	
		    	    params.add(new BasicNameValuePair("grant_type", "password"));
		    	    params.add(new BasicNameValuePair("scope", "apiAccess"));
		    	    params.add(new BasicNameValuePair("client_id", auth_client));
		    	    params.add(new BasicNameValuePair("username", encodedUser));
		    	    params.add(new BasicNameValuePair("password", "password"));

		    	httpPost.setEntity(new UrlEncodedFormEntity(params));
		    	
		    	HttpResponse response;		    	
				response = client.execute(httpPost);
				
				int statusCode = response.getStatusLine().getStatusCode();
			
    		    HttpEntity entity = response.getEntity();
    		    InputStream  is = new BufferedInputStream(entity.getContent(), bufferSize);
    		    			 is.mark(bufferSize);
    		    			 
    		    String restext = IOUtils.toString(is, "utf-8");
    		   // System.out.println("response\t"+restext);
    		    
    		    JSONObject content = new JSONObject(restext);

    		    if(content.has("error")) {
    		    	result.put("error", content.get("error"));
    		    }else {
        		    result.put("access_token", content.get("access_token"));
        		    result.put("token_type", content.get("token_type"));
        		    result.put("expires_in", content.getInt("expires_in"));
        		    result.put("scope", content.get("scope"));    		    	
    		    }
    		    
    		    return result;
    		    
			} catch (ClientProtocolException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} 
		}
		
		return null;
	}
	
	private HashMap revoke(String token) {
		
		HashMap result = new HashMap();
		
		try {
			
			CredentialsProvider provider = new BasicCredentialsProvider();
			UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(auth_client, auth_secret);
			provider.setCredentials(AuthScope.ANY, credentials);
			
			HttpClient client = HttpClientBuilder.create().setDefaultCredentialsProvider(provider).build();

	    	String url = auth_server_url+"/auth/revoke/"+token;

		    System.out.println("revoke\t"+url);
		    
	    	HttpPost httpPost = new HttpPost(url);
	    	
	    	HttpResponse response;		    	
			response = client.execute(httpPost);
			
			int statusCode = response.getStatusLine().getStatusCode();
		
		    HttpEntity entity = response.getEntity();
		    InputStream  is = new BufferedInputStream(entity.getContent(), bufferSize);
		    			 is.mark(bufferSize);
		    			 
		    String restext = IOUtils.toString(is, "utf-8");
		    System.out.println("revoke\t"+restext);
		    JSONObject content = new JSONObject(restext);

		    result.put("status", content.get("status"));
		    
		    return result;
		    
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} 
		
		return null;
	}
	
	
}
