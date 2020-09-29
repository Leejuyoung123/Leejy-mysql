package org.edu.util;

import com.github.scribejava.core.builder.api.DefaultApi20;

// 깃허브에서 제공해주는 defaultapi20
public class NaverLoginApi extends DefaultApi20 {

	protected NaverLoginApi() {
	}

	private static class InstanceHolder {
		private static final NaverLoginApi INSTANCE = new NaverLoginApi();
	}

	public static NaverLoginApi instance() {
		return InstanceHolder.INSTANCE;
	}

	@Override
	public String getAccessTokenEndpoint() {
		return "https://nid.naver.com/oauth2.0/token?grant_type=authorization_code";
	}

	/*
	 * // 똑같이 요청 변수 명세에 따라 파라미터를 추가한 후 보내주면 된다. (grant_type, client_id,
	 * client_secret, code, state)
	 * 별로 크게 어려울 것이 없다. 중요한 건 code이다.
	 * 저 code 파라미터가 바로 로그인 API를 통해 얻어온 인증코드(authorization code)이다. 파라미터를 넣고 요청 URL로
	 * 보낼 시 제대로 보내졌다면 access_token을 받아올 수 있을 것이다. 출처:
	 * https://mygumi.tistory.com/10?category=642348 [마이구미의 HelloWorld]
	 */
	@Override
	protected String getAuthorizationBaseUrl() {
		return "https://nid.naver.com/oauth2.0/authorize";
	}
}
