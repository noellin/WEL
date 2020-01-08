package com.igpublish.wel;

import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class TomcatConfig {

	@Value("${tomcat.ajp.port}")
	int ajpPort;
	
	@Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> servletContainer() {
      return server -> {
        if (server instanceof TomcatServletWebServerFactory) {
            ((TomcatServletWebServerFactory) server).addAdditionalTomcatConnectors(redirectConnector());
        }
      };
    }

    private Connector redirectConnector() {
       Connector connector = new Connector("AJP/1.3");
       connector.setScheme("http");
       connector.setPort(ajpPort);
       connector.setSecure(false);
       connector.setAllowTrace(false);
       return connector;
    }
	
}

