package br.com.oauth.configure;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

@Configuration
public class WebConfig extends WebMvcConfigurerAdapter{
	
	@Override
	public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
		final MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter(objectMapper());
		converters.replaceAll(httpMessageConverter -> (httpMessageConverter instanceof MappingJackson2HttpMessageConverter) ? mappingJackson2HttpMessageConverter : httpMessageConverter);
	}
	
	@Bean
    public ObjectMapper objectMapper() {
        
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder(); 
        
        builder.serializationInclusion(Include.NON_NULL);
        builder.featuresToDisable(
        		SerializationFeature.FAIL_ON_EMPTY_BEANS,
                DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,
                DeserializationFeature.FAIL_ON_INVALID_SUBTYPE,
                SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        
        builder.featuresToEnable(
        		DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
        		DeserializationFeature.USE_BIG_INTEGER_FOR_INTS,
        		JsonParser.Feature.ALLOW_SINGLE_QUOTES,
        		JsonParser.Feature.ALLOW_NUMERIC_LEADING_ZEROS,
        		JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES);
        builder.modulesToInstall(new JavaTimeModule());
        return builder.build();
    }


}