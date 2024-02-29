package fr.pilou.security.httpsign.filter;

import fr.pilou.security.httpsign.exception.SignerException;
import fr.pilou.security.httpsign.service.SigningResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Base64;

@Component
@Order(2)
public class SignFilter extends OncePerRequestFilter {

    SigningResponse signingResponse;

    public SignFilter( SigningResponse signingResponse) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        this.signingResponse = signingResponse;
    }

    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {


        try {
            Pair<String, String> signature=this.signingResponse.signResponse(request,response);
            response.setHeader("Signature-Input", "sig="+ signature.getLeft());
            response.setHeader("Signature", "sig=:"+ signature.getRight()+":");
        } catch (SignerException e) {
            throw new RuntimeException(e);
        }

        filterChain.doFilter(request, response);

    }


    @Bean
    public FilterRegistrationBean<SignFilter> mySignFilter(@Autowired SigningResponse signingResponse)
    {
        FilterRegistrationBean<SignFilter> bean = new FilterRegistrationBean<>();

        bean.setFilter(new SignFilter(signingResponse));
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

