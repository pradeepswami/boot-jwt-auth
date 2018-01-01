package com.boot.ittest;

import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.security.JwtAuthenticationFilter;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(SampleApp.class)
@WebIntegrationTest({"server.port=21212"})
@ActiveProfiles("test")
public class SampleAppIT {

    private static final String LOCAL_HOST = "http://localhost:21212";

    private static final String HELLO_REQUSET = LOCAL_HOST + "/hello";
    @Autowired
    private JJwtServiceImpl JJwtServiceImpl;

    @Test
    public void requestWithoutToken() throws Exception {
        RestTemplate restTemplate = new TestRestTemplate();
        ResponseEntity<String> rst = restTemplate.getForEntity(HELLO_REQUSET, String.class);
        assertThat(rst.getStatusCode(), equalTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    public void requestWithValidToken() throws Exception {
        String token = JJwtServiceImpl.generateToken(Collections.emptyMap());
        System.err.println(token);
        HttpHeaders headers = new HttpHeaders();
        headers.add(JwtAuthenticationFilter.AUTHORIZATION, JwtAuthenticationFilter.BEARER + token);

        RestTemplate restTemplate = new TestRestTemplate();

        ResponseEntity<String> rst = restTemplate.exchange(HELLO_REQUSET, HttpMethod.GET, new HttpEntity<>(headers),
                String.class);

        assertThat(rst.getStatusCode(), equalTo(HttpStatus.OK));
        assertThat(rst.getBody(), equalTo("Hello! from SampleApp"));
    }

    @Test
    public void requestWithExpiredToken() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJzYW1wbGVhcHAiLCJpYXQiOjE0ODM3ODI4MDksImV4cCI6MTQ4Mzc4MjkyOSwic3ViIjoic2FtcGxlYXBwIn0.cuvEjI-KnoLZyJ2Xbx5zScTebBdifK1miHic1Bcs04uXSArC-WyMGcAJhe7Q-D6B2Q9OGXFZBcnMPnKj4_z9QOIJOUCmnBB2AGKrdvbVidvtrmNfQ9wlY6mVBj8BffPIn40dfAX_sKuCqUpskHClRz3ifxaETCJJbPimYyJTfK_mGOC3_gmSOIE3tFROlcnWS1IwSphoqCDcdr_uajoRZ84EWOdFb_6K7lhY5K59rmcb45ErrwoeDx1RekBK_ZzS8TouRFX6vGITmWQ-hfnKQJEwY_3FCRR3EcZCQWczk0G1lDMZs-wniG9v54EjlXl0BdRXzs9V64oQVEcir3kySA";
        HttpHeaders headers = new HttpHeaders();
        headers.add(JwtAuthenticationFilter.AUTHORIZATION, JwtAuthenticationFilter.BEARER + token);

        RestTemplate restTemplate = new TestRestTemplate();

        ResponseEntity<String> rst = restTemplate.exchange(HELLO_REQUSET, HttpMethod.GET, new HttpEntity<>(headers),
                String.class);

        assertThat(rst.getStatusCode(), equalTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    public void requestWithoutToken_unsecureResource() throws Exception {
        RestTemplate restTemplate = new TestRestTemplate();
        ResponseEntity<String> rst = restTemplate.getForEntity(LOCAL_HOST + "/unsecure/hello", String.class);
        assertThat(rst.getStatusCode(), equalTo(HttpStatus.OK));
        assertThat(rst.getBody(), equalTo("Hello! from SampleApp - Unsecure"));
    }

}
