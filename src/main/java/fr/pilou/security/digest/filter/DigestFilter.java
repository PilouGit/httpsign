package fr.pilou.security.digest.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.security.MessageDigest;
@Component
@Order(1)
public class DigestFilter extends OncePerRequestFilter {

    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {




        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance("SHA-256");

        digester.update(wrappedResponse.getContentAsByteArray());
            response.setHeader("Content-Digest","sha-256=:"+ Base64.getEncoder().encodeToString(digester.digest()));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        filterChain.doFilter(request, response);

    }


    @Bean
    public FilterRegistrationBean<DigestFilter> myCustomerFilter()
    {
        FilterRegistrationBean<DigestFilter> bean = new FilterRegistrationBean<>();

        bean.setFilter(new DigestFilter());
        bean.addUrlPatterns("/*");

        return bean;
    }

    private static class CaptureResponseWrapper extends HttpServletResponseWrapper {
            private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            private final PrintWriter writer = new PrintWriter(outputStream);

            public CaptureResponseWrapper(HttpServletResponse response) {
                super(response);
            }

            @Override
            public PrintWriter getWriter() throws IOException {
                return super.getWriter();
            }

            @Override
            public ServletOutputStream getOutputStream() throws IOException {
                return super.getOutputStream();
            }

            public String getCaptureAsString() {
                writer.flush();
                return outputStream.toString();
            }
        }
    }

