package com.igpublish.wel;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

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
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(1)
public class AuthFilter implements Filter {

	private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    final int bufferSize = 1_000_000;
    
	@Value("${auth.server.url}")
	String auth_server_url;

	@Value("${auth.server.clientId}")
	String auth_client;

	@Value("${auth.server.clientSecret}")
	String auth_secret;

	
	@Override
	public void doFilter(ServletRequest request, javax.servlet.ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest httprequest = (HttpServletRequest) request;	
		if(httprequest.getRequestURL() != null && httprequest.getHeader("referer") != null) {
	        String remoteUrl = httprequest.getHeader("referer");
	        String requestUrl = httprequest.getRequestURL().substring(0, httprequest.getRequestURL().indexOf("/", 12));
	        if(remoteUrl != null 
	        		&& !remoteUrl.trim().equals("") 
	        		&& remoteUrl.startsWith("http") 
	        		&& !remoteUrl.startsWith(requestUrl)) {
	           httprequest.getSession().setAttribute("referer", remoteUrl);
	        }
		}
		if(httprequest.getParameter("AffiliateKey") != null ) {
        	httprequest.getSession().setAttribute("affiliate", httprequest.getParameter("AffiliateKey"));
		}
		chain.doFilter(request, response);
		
	}
 
}
