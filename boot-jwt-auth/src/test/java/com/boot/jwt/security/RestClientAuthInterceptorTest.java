package com.boot.jwt.security;

import com.boot.jwt.core.JwtService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RestClientAuthInterceptorTest {

    public static final String JWT_TOKEN = "jwtToken";
    private RestClientAuthInterceptor testObject;

    @Mock
    private JwtService mockJwtService;

    @Mock
    private JwtAdditionalClaim additionalClaim;

    private HttpRequest mockHttpRequest;

    @Mock
    private ClientHttpRequestExecution mockClientExecution;

    @Mock
    private ClientHttpResponse mockClientResponse;

    @Captor
    private ArgumentCaptor<HttpRequest> httpRequestCaptor;

    @Before
    public void setUp() throws Exception {
        mockHttpRequest = new MockClientHttpRequest();
        testObject = new RestClientAuthInterceptor(mockJwtService);
    }

    @Test
    public void intercept_test() throws IOException {
        when(mockJwtService.generateToken(anyMap())).thenReturn(JWT_TOKEN);
        when(mockClientExecution.execute(httpRequestCaptor.capture(), any())).thenReturn(mockClientResponse);

        ClientHttpResponse rstObject = testObject.intercept(mockHttpRequest, new byte[]{}, mockClientExecution);

        Assert.assertThat(httpRequestCaptor.getValue().getHeaders().getFirst(RestClientAuthInterceptor.AUTH_HEADER), containsString(JWT_TOKEN));

    }

}