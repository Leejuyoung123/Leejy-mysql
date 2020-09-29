## 전자정부 표준프레임워크 커스터마이징 
### 파스타 클라우드 활용(공통)

###
### Spring Security 로그인 / 로그아웃 / Naver ID / 비밀번호 암호화 / 구현 


```
스프링 시큐리티로 돌아가는 로직은 60%이해하고 있는데 인터페이스나 상속받고있는 클래스들을 상속받아서 
리턴값을 재정의 해주는 과정이 필요함 , 거기서 개발자가 알아서 코드로 짜 맞추면 되는데 
클론 코딩을 하다보니 이게 정확히 맞는지 파악이 불가능 , 그래서 돌아가는 로직을 제대로 파악하기위해선 
로그인로직을 처음부터 끝까지 재정의 하는 과정이 필요하다고 판단이 됨 ,
Oauth2.0을 소셜로그인  로직을 제대로 모르니까 스프링 시큐리티로 알고있는 로직대로 구현해보았다 . db에있는 정보를 받아오려고 
수많은 글들을 보면서 이해하고 넘어갔지만 , 정확히 파싱하는방법, 회원가입시 기존회원인지 / 새로회원가입처리하는 로직을 
처음부터 끝까지 제대로 처리하는걸 구현시켜야함  기본 회원가입 로직 커스텀 / 스프링 시큐리티 회원가입 커스텀 / 스프링 시큐리티로 Oauth2.0 데이터를 주고받는방법을 이해해야함  전체적인 로직이 순서가안맞고 앞뒤가 안맞아서 
처음부터 구현할떄 순서대로 타이핑한뒤 , 절차대로 로직을 맞춰가면서 코딩하기

쇼핑몰 스프링 프로젝트 , 고객관리 프로그램 , js 테트리스 , 애니팡같은 퍼즐 맞추는게임 만들어보기 
java , css , html , jquery , jpa , spring MVC ,springboot 정확하게 이해하고 절차대로 코딩하기
python , nodejs,vue,js react rdbms 공부
로그인 로직처리 + oauth2.0 로직처리
스프링시큐리티 로그인 로직처리 + oauth2.0 로직처리 


```

```

사용자는 resouce owner 

쿠팡 Clien application에 접속

client app에서 resource 서버에 access 데이터 
사용자가 쿠팡에서 네이버 로그인을 통해 로그인 하고자함

oauth이용하는 sns 서버는 Resource (자원)서버 (authorizaition) 권한서버로 분리되어있음
즉 자원서버와 권한서버는 역할만 다를뿐 네이버의것

3.resource 서버는 delegate 인증 과 권한을 하기위해 권한서버에 보냄
자원서버는 로그인 사용자 자원을 인증하기위해 인증서버로 넘겨주는것

4.authorizaition는 clinetapp으로 authorizaiiton code /accesstoken 
 권한 서버는 접속한 웹페이지 (쿠팡)서버로 인증코드와 액세스 토큰 발행
발행받은 코드와 액세스 토큰을 통해 네이버의 로그인 서비스를 이용할수잇음

5.resouceowners는 authorazaiton server grant access
쿠팡 페이지에서는 사용자의 인증이 완료되어 네이버 로그인이 가능하게됨

https://lemontia.tistory.com/927 
oauth2.0 sns인증방법

https://doorisopen.github.io/spring/2020/03/03/spring-freelec-springboot-chap5.html
스프링부트 oauth2.0 인증방법

https://coding-start.tistory.com/153
스프링 시큐리티와 oauth2.0 인증방법

```


```
인증이 필요한 이유 
프론트엔드 관점 
사용자의 로그인 , 회원가입 사용자의 도입부분을 가리킴 백엔드 관점에서는 모든 요청 API에 대해 사용자를 확인하는 작업

사용자 A ,B 가  앱을 사용한다고 가정, 두 사용자는 기본적으로 정보가 다르고 보유하고있는 컨텐츠도 다름
서버에서는 A,B가 요청을 보냈을 떄 누구의 요청인지를 정확히 알아야함 , 그렇지 못하면 자신의 정보가 타인에게 노출 유출 되는 상황이 발생
자신이 누구인지 알만한 단서를 서버에 보내야하며 서버는 그 단서를 파악해 각 요청에 맞는 데이터를 뿌려주게 됨

HTTP 요청
- 모바일이나 웹서비스에 가장 많이 쓰이는 통신 방식은 HTTP통신 HTTP 통신은 응답후 연결이 끊기고 지난 데이터 정보를 담지 않는다
  지금 보낼 Http 요청은 지난 번에 내 정보를 담아 보냈던 Http 요청과 전혀 관계가 없다는 말, 각각의 요청에 주체가 누구인지
 정보가 필수적 서버에 요청을 보내는 작업은 Http 메세지를 보내는것 , http 메세지의 구조는
 바디 공백 헤더 요청라인  - 일반적으로 헤더와 바디 두가지로 구성 공백은 헤더와 바디를 구분짓는 역할  헤더에서는 기본적으로 
 요청에 대한 정보들이 들어감 , 바디에는 서버로 보내야할 데이터가 들어감 모바일 /웹 서비스의 인증은 http 메세지의 헤더에 인증수단을 넣어 
 요청을 보내게 됨 
- 인증방식 
1.계정 정보를 요청 헤더에 넣는 방식
가장 보안이 낮은 방식은 계정정보를 요청에 담아 보내는 방식 
데이터를 요청할떄마다 사용자의 프라이빗 정보를 계속해서 보내는건 보안에 취약 
앱에서는 서버로 http 요청을 할 떄 따로 암호화 되지 않음  http 요청을 가로채서(intercept) 사용자의 계정정보를 알수있음
2.Session / Cookie 방식
-사용자가 로그인을 함 
-서버에서는 계정 정보를 읽어 사용자를 확인 ㅡ 고유 id 값을 부여하여 세션저장 후 연결되는 세션 ID를 발행
-사용자는 서버에서 해당세션ID를 받아 쿠키에 저장  인증이 필요한 요청마다 쿠키를ㄹ 헤더에 실어 보냄
-서버에서는 쿠키를 받아 세션 저장소에 대조 한후 대응 되는 정보를 가져옴
-인증이 완료되고 서버는 사용자에 맞는 데이터를 보내줌
세션 저장소가 필요함 세션 저장소는 (redis)를 많이 사용 로그인을 했을 떄 사용자의 정보를 로그인 했을 떄 사용자의 정보를 저장
열쇠가 되는 세션ID값을 생성 http 헤더에 실어 사용자에게 돌려보냄 사용자는 쿠키로 보관 하고있음 인증이 필요한 요청에 
쿠키를(세션ID)넣어 보냄 웹 서버는 세션 저장소에 쿠키(세션ID)를 받고 저장되어 있는 정보와 매칭 시켜 인증을 완료

Session = 서버에서 가지고 있는 정보 
Cookie = 사용자에게 발급된 세션을 열기위한 열쇠 (Session ID) 
사용자 (클라이언트)는 쿠키를 이용 서버에서는 쿠키를 받아 세션의 정보를 접근 하는 방식으로 인증

단점 - 쿠키를 훔쳐 http의 요청을 보내면 서버의 세션 저장소에서는 사용자로 오인 / 정보를 잘못뿌려주게됨 ( 세션 하이재킹 공격)
-해결책 https를 사용해 요청 자체를 탈취해도 안의 정보를 읽기 힘들게 함 세션의 유효시간을 넣어준다.

3.Token 기반 인증 방식 (jwt)
jwt는 세션/쿠키와 할계 모바일 /웹의 인즈을 책임지는 대표적인 주자 jwt는 json Web Token 약자 
인증에 필요한 정보들을 암호화시킨 토큰을 뜻함 위의 세션/쿠키 방식과 유사하게 사용되는 Access Token(jwt)을 http 헤더에 실어 서버로 보냄 
토큰을 만들기 위해서는 3가지 Header Payload Verify Signature 필요
header : 3가지 정보를 암호할 방식 alg type 등이 들어감
Payload: 서버에 보낼 데이터가 들어감 일반적으로 유저의 고유 ID 값 , 유효기간이 들어감
VerifySignature: Base64 방식으로 인코딩한 header,payload secret key 를 더한후 서명
1. 사용자가 로그인을 한다.
2. 서버에서는 계정정보를 읽어 사용자를 확인 후, 사용자의 고유한 ID값을 부여한 후, 기타 정보와 함께 Payload에 넣습니다.
3. JWT 토큰의 유효기간을 설정합니다.
4. 암호화할 SECRET KEY를 이용해 ACCESS TOKEN을 발급합니다.
5. 사용자는 Access Token을 받아 저장한 후, 인증이 필요한 요청마다 토큰을 헤더에 실어 보냅니다.
6. 서버에서는 해당 토큰의 Verify Signature를 SECRET KEY로 복호화한 후, 조작 여부, 유효기간을 확인합니다.
7. 검증이 완료된다면, Payload를 디코딩하여 사용자의 ID에 맞는 데이터를 가져옵니다.  

세션/쿠키 방식과 가장 큰 차이점은 세션/쿠키는 세션 저장소에 유저의 정보를 넣는 반면, JWT는 토큰 안에 유저의 정보들이 넣는다는 점입니다. 물론 클라이언트 입장에서는 HTTP 헤더에 세션ID나 토큰을 실어서 보내준다는 점에서는 동일하나, 서버 측에서는 인증을 위해 암호화를 하냐, 별도의 저장소를 이용하냐는 차이가 발생합니다.
장점
1. 간편합니다. 세션/쿠키는 별도의 저장소의 관리가 필요합니다. 그러나 JWT는 발급한 후 검증만 하면 되기 때문에 추가 저장소가 필요 없습니다. 이는 Stateless 한 서버를 만드는 입장에서는 큰 강점입니다. 여기서 Stateless는 어떠한 별도의 저장소도 사용하지 않는, 즉 상태를 저장하지 않는 것을 의미합니다. 이는 서버를 확장하거나 유지,보수하는데 유리합니다.
2. 확장성이 뛰어납니다. 토큰 기반으로 하는 다른 인증 시스템에 접근이 가능합니다. 예를 들어 Facebook 로그인, Google 로그인 등은 	모두 토큰을 기반으로 인증을 합니다. 이에 선택적으로 이름이나 이메일 등을 받을 수 있는 권한도 받을 수 있습니다. 
단점
1. 이미 발급된 JWT에 대해서는 돌이킬 수 없습니다. 세션/쿠키의 경우 만일 쿠키가 악의적으로 이용된다면, 해당하는 세션을 지워버리면 됩니다. 하지만 JWT는 한 번 발급되면 유효기간이 완료될 때 까지는 계속 사용이 가능합니다. 따라서 악의적인 사용자는 유효기간이 지나기 전까지 신나게 정보들을 털어갈 수 있습니다. 
-> 해결책
기존의 Access Token의 유효기간을 짧게 하고 Refresh Token이라는 새로운 토큰을 발급합니다. 그렇게 되면 Access Token을 탈취당해도 상대적으로 피해를 줄일 수 있습니다. 이는 다음 포스팅에 나올 Oauth2에 더 자세히 다루도록 하겠습니다.

2. Payload 정보가 제한적입니다. 위에서 언급했다시피 Payload는 따로 암호화되지 않기 때문에 디코딩하면 누구나 정보를 확인할 수 있습니다. (세션/쿠키 방식에서는 유저의 정보가 전부 서버의 저장소에 안전하게 보관됩니다) 따라서 유저의 중요한 정보들은 Payload에 넣을 수 없습니다.

3. JWT의 길이입니다. 세션/쿠키 방식에 비해 JWT의 길이는 깁니다. 따라서 인증이 필요한 요청이 많아질 수록 서버의 자원낭비가 발생하게 됩니다.


```

```
전자정부 프레임워크 / js / jquery 부분 기술참조
https://offbyone.tistory.com/category/

// 시큐리티 컨텍스트 객체를 얻습니다. SecurityContext context = SecurityContextHolder.getContext(); // 인증 객체를 얻습니다. Authentication authentication = context.getAuthentication(); // 로그인한 사용자정보를 가진 객체를 얻습니다. Principal principal = authentication.getPrincipal(); // 사용자가 가진 모든 롤 정보를 얻습니다. Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities(); Iterator<? extends GrantedAuthority> iter = authorities.iterator(); while (iter.hasNext()) { GrantedAuthority auth = iter.next(); System.out.println(auth.getAuthority()); }
출처: https://offbyone.tistory.com/217 [쉬고 싶은 개발자]

// 로그인 사용자 정보 객체(LoginVO)
public static Object getAuthenticatedUser()

// 사용자의 롤 리스트를 얻습니다.
public static List getAuthorities()

// 로그인 여부를 확인합니다.
public static Boolean isAuthenticated()

https://offbyone.tistory.com/217

스프링 시큐리티 기술 참조 
https://github.com/codevang/
깃 허브 소스
https://codevang.tistory.com/267
auth List
https://zgundam.tistory.com/49
스프링 시큐리티 로직 
https://coding-start.tistory.com/153
스프링 시큐리티 로직 
https://github.com/todyDev/Spring-Security 
스프링 시큐리티 깃허브
https://shxrecord.tistory.com/108 ajax 로직 
https://bumcrush.tistory.com/category/%EA%B3%B5%EB%B6%80/JSP%26Servlet?page=2
네아로 -로직 - ajax 좋아요
https://bumcrush.tistory.com/124?category=598298
https://bumcrush.tistory.com/151 - 좋아요로직
스프링 시큐리티 - 네아로 로직
https://m.blog.naver.com/sam_sist/220964537132
스프링 시큐리티 - 구조 
https://www.egovframe.go.kr/wiki/doku.php?id=egovframework:rte2:ptl:annotation-
어노테이션 설정 약속 규칙
based_controllerhttps://zuminternet.github.io/ZUM-PILOT-WONOH/
 스프링프로젝틑 가이드 제안서
https://hunit.tistory.com/211

```


```
2020-09-15
Part 06(스프링 시큐리티) 
/* 로그인 암호화된 DB 패스워드로 인증 */
1. 커스터마이징한 UserDetailsService 구현 클래스가 DB에서 계정 정보를 가져옴
2. 정보를 담은 UserDetails 객체를 디폴트 authentication-provider에게 전달해서 자동 인증 진행
 
DB에 저장된 데이터가 평문 패스워드일때는 디폴트 Provider 클래스에서 인증을 진행해줬지만, 이제 DB에서는 암호화된 패스워드를 건내주고 사용자는 평문 패스워드를 입력합니다. 기존처럼 equals()를 사용해 문자열을 비교하는 방식이 아닌 평문 패스워드를 암호화해서 DB의 데이터와 비교해주는 작업이 필요하다는 것이죠.

따라서 이전 커스터마이징 방법과 마찬가지로, Authentication-Provider 역할을 할 클래스를 하나 만들어서 바꿔치기(DI) 해주도록 하면 됩니다. 아래와 같이 고쳐주면 됩니다.

user-service-ref 는 디폴트 Provider에게 커스터마이징한 UserDetailsService를 주입해주기 위한 것이므로 삭제해도 됩니다. Provider를 우리가 직접 만들테니 해당 클래스 안에서 UserDetailsService Bean을 직접 주입받으면 되니까요.

<!-- DB 연동 설정 -->
<s:authentication-manager>
	<s:authentication-provider ref="userLoginAuthenticationProvider">
	</s:authentication-provider>
</s:authentication-manager>
1. AuthenticationProvider 인터페이스 구현 및 메소드 오버라이딩
Provider 역할을 하는 클래스는 해당 인터페이스를 구현하고 있습니다. 따라서 우리도 같이 구현해서 클래스 타입과 실행 메소드를 동일하게 맞춰줍니다.

2)authenticate()메소드 작성
실제 인증을 구현하는 로직 파라미터로 받은 Authentication 에는 사용자가 입력한 ID/PW 정보를 담고 있음
객체에서 필요한 정보를 쓰고 인증에 성공하면 새로운 Authentication 객체를 만들어 계정 정보와 권한정보를 넣어 리턴하면 됨
파라미터로 받은 객체를 재활용 setter 메서드가 없고 생성자로만 데이터를 넣을수 있도록 되어있어 어쩔수없이 새로 만들어 줘야함
아마 인증 정보를 담은 객체를 생성한 이후로 데이터를 변조 할수 없도록 하기위해 setter가 없는 부분 
객체는 세션으로 자동으로 저장되기 떄문에 MVC 어느곳에 가져다 사용할수 있다

인증 실패할 경우 적절한 예외 객체를 생성해 던져 주면 이전에 커스터마이징 했던 Fail Handler로 예외 객체를 던져줌
provider , failhandler 의 예외상황을 동일하게 맞춰준다
인증에 관련된 대부분의 부분들을  커스터마이징 했기 떄문에 지금 Provider 제외하고 UserDetailsService 구현체,
데이터 전달하는 UserDetails 는 구현체는 굳이 사용할 필요없음 스프링 시큐리티의 모든 동작 과정을 완전히 파악하고있는 것이 아닌 이상
기존 구조를 유지하면서 커스터 마이징 하는것이 가장 안정적 
아래 전체 코드  패스워드는 인증후에 필요없으므로 Null 처리 getClass()로 확인해보면 Authentication 인터페이스의
실제 구현체를 확인할수 있음 같은 구현체를 만들면서 생성자로 값을 넣어주면 됨
new UsernamepasswodAuthenticationToken(생성자)
그리고 해당 객체를 만들떄는 String 타입이 아닌 Userdetails 구현체를 넣어주는것이 좋음
authentication 객체는ㄴ 세션 scope 로 공유 되기때문 사용자 인증 정보를ㄹ 필요한 곳에서 꺼내 쓰는 용도로 편리하게 사용할수잇음
그냥 ID를 String 타입으로 넣어버리면 기능을 제대로 사용할수 있음 

ackage hs.spring.hsweb.service.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import hs.spring.hsweb.mapper.vo.user.UserDetailsVO;

@Service
public class UserLoginAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	// DB의 값을 가져다주는 커스터마이징 클래스
	UserDetailsService userDetailsServcie;

	// 패스워드 암호화 객체
	@Autowired
	BCryptPasswordEncoder pwEncoding;

	@Override
	// 인증 로직
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {

		/* 사용자가 입력한 정보 */
		String userId = authentication.getName();
		String userPw = (String) authentication.getCredentials();

		/* DB에서 가져온 정보 (커스터마이징 가능) */
		UserDetailsVO userDetails = (UserDetailsVO) userDetailsServcie
				.loadUserByUsername(userId);

		
		
		/* 인증 진행 */
		
		// DB에 정보가 없는 경우 예외 발생 (아이디/패스워드 잘못됐을 때와 동일한 것이 좋음)
		// ID 및 PW 체크해서 안맞을 경우 (matches를 이용한 암호화 체크를 해야함)
		if (userDetails == null || !userId.equals(userDetails.getUsername())
				|| !pwEncoding.matches(userPw, userDetails.getPassword())) {

			throw new BadCredentialsException(userId);

		// 계정 정보 맞으면 나머지 부가 메소드 체크 (이부분도 필요한 부분만 커스터마이징 하면 됨)
		// 잠긴 계정일 경우
		} else if (!userDetails.isAccountNonLocked()) {
			throw new LockedException(userId);

		// 비활성화된 계정일 경우
		} else if (!userDetails.isEnabled()) {
			throw new DisabledException(userId);

		// 만료된 계정일 경우
		} else if (!userDetails.isAccountNonExpired()) {
			throw new AccountExpiredException(userId);

		// 비밀번호가 만료된 경우
		} else if (!userDetails.isCredentialsNonExpired()) {
			throw new CredentialsExpiredException(userId);
		}

		// 다 썼으면 패스워드 정보는 지워줌 (객체를 계속 사용해야 하므로)
		userDetails.setPassword(null);

		/* 최종 리턴 시킬 새로만든 Authentication 객체 */
		Authentication newAuth = new UsernamePasswordAuthenticationToken(
				userDetails, null, userDetails.getAuthorities());

		return newAuth;
	}

	@Override
	// 위의 authenticate 메소드에서 반환한 객체가 유효한 타입이 맞는지 검사
	// null 값이거나 잘못된 타입을 반환했을 경우 인증 실패로 간주
	public boolean supports(Class<?> authentication) {

		// 스프링 Security가 요구하는 UsernamePasswordAuthenticationToken 타입이 맞는지 확인
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
```


```
		/* 로그인 성공 대응 로직 */
로그인 인증 성공 직후 처리할 로직을 커스터마이징 하는 부분 
로그인 실패 대응 로직 작성과 동일한 원리 / 커스터마이징의 구조와 원리 자체는 
완전동일하기 떄문에 별도의 설명은 하지않는다 .
로그인 직후 어떤 페이지로 보내줄 것인지 결정하거나 방문자수를 카운트하는 등의 로직을 작성할수있다


[ 커스텀 Success Handler 클래스 작성 ]

로그인 인증 성공 후 로직을 전개하는 디폴트 클래스는 아래 인터페이스를 상속받고 있습니다. 커스텀 클래스 또한 해당 인터페이스를 상속받기만 하면 됩니다. 사실 Provider를 커스터마이징하게되면 인터페이스 상속 없이 마음대로 작성할 수 있지만 구조를 그대로 가져가 주는게 더 안정적일 것 같습니다.

* AuthenticationSuccessHandler : 로그인 성공 처리 핸들러가 상속받는 인터페이스

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class UserLoginSuccessHandler implements AuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {

인터페이스에서 상속받은 메소드를 오버라이딩합니다. 이 메소드가 로그인 인증 후 디폴트 Provider에서 실행하는 메소드입니다. 필요한 로직을 전개한 뒤 포워딩 또는 리다이렉트를 해 원하는 페이지로 연결해주면 됩니다.

"Authentication" 파라미터는 인증된 사용자 정보를 담고 있는 객체입니다. 핸들러에서 사용할만한 메소드는 아래 세가지 정도가 있을 것 같습니다. 사용법과 개념은 글을 계속 보다보시면 자연스레 알 수 있습니다. 

Authentication 메소드	설명
String getName()	- 사용자 ID 반환
Collection<> getAuthorities()	- 사용자 권한 리스트 반환
Object getPrincipal()	
- Userdetails 객체 반환 (Provider에서 Authentication 객체에 제대로 첨부했을 경우)
- 타입 캐스팅 필요
Object getDetails()	
- IP, 세션 ID를 가진 WebAuthenticationDetails 객체 반환
- 타입 캐스팅 필요
```





```
2020-09-14 (스프링 시큐리티 설정)
Part (3)
스프링의 기본적인 인증 로직을 완료 / 가장 중요한 뼈대가 완성 되었으므로  이번 글부터는 계속해서  부가기능들을 추가해 나가도록 함

다룰 내용은 로그인 실패에 대한 대응 로직 가장 기본이 되는 대표적인 로직은  왜 로그인에 실패했는지 사용자에게 알려주는것
디폴트 설정일 경우 
별다른 설정을 하지 않았다면 로그인 실패시 아래 설정에 등록해둔 URL 을 호출 다시 로그인 화면 으로 보내 다시 로그인을  시도하게끔 함
<!-- 로그인 설정 -->
		<s:form-login	
			username-parameter="userId" 
			password-parameter="userPw"
			login-processing-url="/loginAsk" 
			login-page="/loginView" default-target-url="/"
			authentication-failure-url="/loginView" />
로그인 화면에서는 왜 로그인에 실패 했는지 알려줘야함 , 아무것도 따로 만들지 않았을떄 스프링 시큐리티는 
인증 실패시 발생하는 예외 종류에 따라 만들어진 객체를 Session Attribute로 담아줍니다 
해당 객체에서 message를 꺼내오면 메세지를 받을수 있다. 아래와 같이 JSP 페이지에서 해당 메세지를 꺼내오면됨
<!-- 로그인 실패 시 출력할 메세지 -->
${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}

세션에 메세지를 담아 View에 전달하는 방법은 그리좋지 않다 . 요청 한번에 만들어졌다 소멸되는 request객체와 달리 
ssesion 객체는 일정한 기간동안 메모리에 상주하고 있기 때문에 로그인 화면에ㅐ서 메세지를 출력 session Attribute에 지워줘야함

또한 메세지 외의 로그인 실패에 따른 여러 로직을 처리 해야한다면 복잡해짐  인증이 5번 틀리면 계정이 잠긴다거나 하는 로직을 들 수 있다.
jsp에서 로직을 조금 넣어주면 충분히 해결이 가능하긴 하지만 MVC패턴에서 VIEW에 로직을 넣는것은 최대한 지양하는것이 좋다

그리고 무엇보다 스프링 시큐리티에서 대부분 기능들을 커스터마이징 처리해서 할수있는 방법들을 충분히 제공하고 있다.
깔끔하게 프레임워크를 이용해 로직을 구현하는것이 스마트한 방법 ? 디포트로 지정된 방법은 사용하지 않을것

[ 로그인 실패 시 대응 로직 커스터마이징 ]
이전 글에서는 UserDetailsService 인터페이스를 상속받은 클래스의 Bean 객체를 authentication-provider의 레퍼런스로 DI(의존성 주입)해서, 우리가 원하는 인증 DB의 데이터를 스프링 Security에게 전달해줬습니다. 
아래 설정 부분입니다. DI를 하면 직접 작성한 로직으로, 생략하면 디폴트로 지정된 로직으로 동작했었죠.
	<!-- DB 연동 설정 -->
	<s:authentication-manager>
		<s:authentication-provider user-service-ref="userLoginService">
		</s:authentication-provider>
	</s:authentication-manager>
	
다른 커스터 마이징 방식도 대부분 동일 본래 있던 디폴트 클래스를 대체할 클래스를 작성한 뒤 적절한 부분에 
레퍼런스로 DI를 바꿔치기 해주면 됨 약속된 실행 메소드는 인터페이스에서 미리 정의해두기 떄문에 우리는 필요한 기능의 인터페이스를 상속받아 
각자 입맛에 맞게 오버라이딩 해서 리턴 값만 제대로 보내주면 됩니다 .

 AuthenticationFailureHandler : 로그인 실패 처리 핸들러가 상속받는 인터페이스
  로그인 실패를 처리하는 디폴트 클래스는 위의 인터페이스를 구현해 만들어진 Exception 어쩌고 하는 이름도 아주 긴 클래스입니다 
  로그인에 실패하면 예외 객체를 넘겨받아 세션에다가 메세지를 남기고 다시 지정된 페이지로 리다이렉트로 시켜줍니다
 따라서 우리는 이 녀석을 대체할 클래스를 하나 만들어서 컨텍스트 설정 DI만 해주면 됩니다 
 같은 인터페이스를 상속받아 메소드를 오버라이딩 해주면 된다는 의미 

오버라이딩 해야 하는 메소드는 "request, response와 에러 내용을 넘겨줄테니까 알아서 처리해" 라는 의미입니다. 일반적으로는 필요한 로직을 처리하고 request Attribute에 메세지를 담은 뒤, 최종적으로 다시 로그인 페이지로 포워딩 시켜줍니다. 또는 다른 로직으로 맘대로 구현해도 무방합니다.
인증 실패 시 인증을 담당하는 Provider가 던진 예외를 Fail Handler에게 전달해주는데, 이 부분은 Provider를 커스터마이징하면 어떤 상황에서 어떤 예외를 던져줄지 직접 결정해야하므로 어떤 종류가 있는지만 대략적으로 보고 넘어가면 될 것 같습니다.
 

Fail Handler가 받는 예외					디폴트 Provider가 리턴하는 결과 (커스터마이징 가능)
AuthenticationServiceException	- null 값을 리턴

BadCredentialException	
										- UsernameNotFoundException 예외를 throw

										- UserDetails 객체를 리턴했으나, 아이디 또는 비밀번호가 틀림

LockedException						- UserDetails 객체의 isAccountNonLocked() 
										   	메소드의 리턴값이 false
DisabledException					- UserDetails 객체의 isEnabled() 메소드의 리턴값이 false

AccountExpiredException			- UserDetails 객체의 isAccountNonExpired() 
											메소드의 리턴값이 false

CredentialExpiredException			- UserDetails 객체의 isCredentialsNonExpired() 
											메소드의 리턴값이 false

 로그인 실패를 처리할 클래스를 작성만 하면 됩니다. 먼저 인터페이스를 상속받아줍니다.
 
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Service;

@Service
		/* 로그인 실패 대응 로직 */
public class UserLoginFailHandler implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException exception)
			throws IOException, ServletException {

	}
}
[ 컨텍스트 설정 - 디폴트로 등록된 Fail Handler 바꿔치기 ]

이제 모든 준비가 완료되었으므로 컨텍스트 설정 파일만 수정해주면 됩니다. 위에서 말했듯이 디폴트로 설정된 녀석말고 우리가 만든 클래스의 Bean 객체를 의존 주입해서 바꿔주는 부분입니다.

로그인 설정 부분을 아래와 같이 바꿔줍니다.
* 기존 설정 삭제 : authentication-failure-url="/loginView" 

* 추가 설정 부여 : authentication-failure-handler-ref="핸들러 클래스의 Bean ID"
// 로그인 실패시 출력할 메세지
${requestScope.loginFailMsg}

<!-- 로그인 설정 -->
		<s:form-login	
			username-parameter="userId" 
			password-parameter="userPw"
			login-processing-url="/loginAsk" 
			login-page="/loginView" default-target-url="/"

			authentication-failure-handler-ref="userLoginFailHandler" />
		
		<!-- 설정 제거 -->
		<!-- authentication-failure-url="/loginView" /> -->
위 설정을 통해 인증 실패의 경우 핸들러로 지정된 Bean 객체에 처리를 요청하도록 합니다. @Service 어노테이션을 클래스에 붙여줬으므로 클래스는 자동으로 루트 컨테이너의 Bean으로 등록되며, 이름을 따로 지정해주지 않았다면 클래스명에서 앞글자만 소문자로 써주면 됩니다. 
이것으로 로그인 실패 대응 로직은 완료되었습니다		
	}
}
```

```
2020-09-14(스프링 시큐리티 설정)
Part (2)

part1에서 다뤘던 내용은 컨텍스트 설정을 완료 / 로그인 요청한 사용자의 ID,PW,권한정보를 DB에서 가져와 스프링 Security 전달해주는 클래스만작성하면됨

DB는 Mysql, 연동은 Mybatis를 사용 / 사용하는 방법은 상관없다 . 정해진 형식으로 스프링시큐리티에게 해당 사용자에 대한 정보를 전달해주면됨

- 데이터 전달구조
스프링 시큐리티에서 제공해주는 클래스들은 생소하고 복잡해 보이지만 순차적으로 하나씩 까보면 그렇게 많이 어려운편은 아니다. 
이미 만들어진 클래스들을 구현해 필요한 정보만 담아주면 되기떄문에 

데이터 클래스의 데이터는 어떻게 채워넣든 개발자 마음 , 중요한 부분은 서비스 클래스가 최종적으로 완성된 데이터 클래스의 객체를 리턴만 하면됨

1) 데이터 전달 클래스 (VO,DTO) 작성 (UserDetails 인터페이스 구현)
DB에 저장된 사용자의 ID , PW , 권한 " 정보를 저장하는 데이터 전달 객체 ,  UserDetails 인터페이스를 구현받아야 하고 
7개의 메소드를 오버라이딩 해줘야함 / ID PW 권한 의 가장 기본적인 세가지 제외 나머지는 추가로 활용할수 있는 기능 /
나중에 Provider 까지 커스터마이징 하고나면 그대로 구성할 필요는 없지만 일단 기본 구조대로 구조를 따라가봄 .
스프링 구조에 맞춰서 커스터마이징 하는것은 가장 편리하고 깔끔함 

UserDetailsService 인터페이스를 구현한 서비스 클래스에서 최종적으로 완성된 데이터 클래스 객체를 return 시키면 
스프링 시큐리티에게 전달이 됨  오버라이딩 된 7개의 메소드를 실행해 정보를 가져가므로 7개의 메소드에서 필요한 부분의 리턴값을 잘 설정하면 됨
3개는 getter 메소드이고 4개는 계정에 대한 부가 정보.

아래 설명 메소드는 어떻게 구현하건 리턴값만 적용하면됨 아래는 전체 코드 , 각 메소드에 대한 설명입니다.

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/* Spring Security 로그인을 위한 UserDetails VO 객체 */
public class UserDetailsVO implements UserDetails {

	// 안만들어도 상관없지만 Warning이 발생함
	private static final long serialVersionUID = 1L;

	private String username; // ID
	private String password; // PW
	private List<GrantedAuthority> authorities;

	// setter
	public void setUsername(String username) {
		this.username = username;
	}

	// setter
	public void setPassword(String password) {
		this.password = password;
	}

	// setter
	public void setAuthorities(List<String> authList) {

		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		for (int i = 0; i < authList.size(); i++) {
			authorities.add(new SimpleGrantedAuthority(authList.get(i)));
		}

		this.authorities = authorities;
	}

	@Override
	// ID
	public String getUsername() {

		return username;
	}

	@Override
	// PW
	public String getPassword() {

		return password;
	}

	@Override
	// 권한
	public Collection<? extends GrantedAuthority> getAuthorities() {

		return authorities;
	}

	@Override
	// 계정이 만료 되지 않았는가?
	public boolean isAccountNonExpired() {

		return true;
	}

	@Override
	// 계정이 잠기지 않았는가?
	public boolean isAccountNonLocked() {

		return true;
	}

	@Override
	// 패스워드가 만료되지 않았는가?
	public boolean isCredentialsNonExpired() {

		return true;
	}

	@Override
	// 계정이 활성화 되었는가?
	public boolean isEnabled() {

		return true;
	}
}
필드에 대한 setter 메소드 
나중에 객체의 데이터를 완성 시켜줘야하므로 setter 추가 , 필드 위의 세개가 가장 기본인데 추가로 더 구성해도 상관없음

public String getUsername():ID 값
ID 정보의 필드에 대한 getter 입니다 .security 에서는 Id를 username 이라고 표현함

public Collection <? extends GrantedAuthority> getAuthorities():권한

권한은 GrantedAuthority 인터페이스를 구현한 SimpleGrantedAuthority 클래스에 하나씩 담아주면 됩니다
한 객체당 하나의 권한이며 컬렉션 계열에 모두 담아 주면 됨 .

한사람이 여러 권한을 가질수 있기 떄문에 복수의 데이터를 담을수 있도록 되어있고 이름은 복잡하지만 실질적으로 
그냥 String 타입의 권한명만 객체에[ 담아주면 되는 구조 매우간단함

List<String> 타입으로 권한 데이터를 받아서 해당 타입으로 변환해주는 setter 만들어서 주입 
스프링 시큐리티에서 고정된 권한 리스트 타입이기 떄문에 그대로 구현해줘야함

권한 객체 생성 :new SimpleGrantedAuthority ( " 권한명 " ) 

스프링 시큐리티 : Collection / GrantedAuthority / SimpleGrantedAuthority  클래스에 대한 명세를 상세히 적어 놓기

나머지 메서드는 필요하면 추가로 구현하는 값들 일단 기본값 세팅  DB에 상태값을 저장해뒀다가 가져와서 판별해주면 됨 
모든 커스터마이징을 끝내고 나면 그대로 사용하지 않아도 되지만 일단 구현되어있으니 필요하면 적당히 재활용 해주는것이 좋다.

@Override
	// 계정이 만료 되지 않았는가?
	public boolean isAccountNonExpired() {
	DB에 만료여부에 대한 컬럼을 따로 만들어 두고 판별해서 만료된 계정이면 false 만료되지 않았다면 .true를 반환
		return true;
	}

	@Override
	// 계정이 잠기지 않았는가?
	public boolean isAccountNonLocked() {
	
		return true;
	}

	@Override
	// 패스워드가 만료되지 않았는가?
	public boolean isCredentialsNonExpired() {
	Credential은 패스워드를 의미합니다. 역시 true가 정상을 의미합니다.
		return true;
	}

	@Override
	// 계정이 활성화 되었는가?
	public boolean isEnabled() {
	그냥 마음대로 해석해서 로직을 대응시키면 됩니다. 이번에는 '가능한가?'로 물었기 때문에 true가 정상을 의미합니다. 네 가지 메소드 모두 	true가 정상적인 계정을 의미한다고 보면 됩니다. 
		return true;
	}
	
	2) 서비스 클래스 작성 (UserDetailsService 인터페이스 구현)
	컨텍스트 설정의 아래 설정 부분에 Bean객체로 주입해준 클래스 
	이 클래스를 작성해두고 위에서 작성한 데이터 전달 클래스 객체의 완성본을  return 시키면
	스프링 시큐리티로 인증을위한 정보가 최종 전달 됨 
	
	직접 작성한 클래스의 Bean을 Authentication-provider 주입해주면 
	해당 bean에 오버라이딩된 메서드의 리턴값을 통해 ID , PW , 권한을 데이터를 받아 인증을 진행
	래퍼런스를 비워두면 미리 만들어진 디폴트 클래스를 Bean으로 등록해 사용합니다 .  스프링 시큐리티의 
	디폴트 로직에는 DB 연동이 없으므로 실제 사용할 일은 거의 없다
	나중에 Provider도 커스터마이징 하면 아래 설정은 필요 없다 .
	
	<!-- DB 연동 설정 https://codevang.tistory.com/266 -->
	<s:authentication-manager>
		<s:authentication-provider user-service-ref="userLoginService">
		</s:authentication-provider>
	</s:authentication-manager>
	구현 코드 (아래)
	import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import hs.spring.hsweb.mapper.user.UserMapper;
import hs.spring.hsweb.mapper.vo.user.UserDetailsVO;
import hs.spring.hsweb.mapper.vo.user.UserInfoVO;

@Service
public class UserDetailsServiceCustom implements UserDetailsService {

	@Autowired
	private UserMapper mapper;

	@Override
	public UserDetails loadUserByUsername(String inputUserId) {

		// 최종적으로 리턴해야할 객체
		UserDetailsVO userDetails = new UserDetailsVO();

		// 사용자 정보 select
		UserInfoVO userInfo = mapper.selectUserInfoOne(inputUserId);

		// 사용자 정보 없으면 null 처리
		if (userInfo == null) {
			return null;

		// 사용자 정보 있을 경우 로직 전개 (userDetails에 데이터 넣기)
		} else {
			userDetails.setUsername(userInfo.getUserId());
			userDetails.setPassword(userInfo.getUserPw());

			// 사용자 권한 select해서 받아온 List<String> 객체 주입
			userDetails.setAuthorities(mapper.selectUserAuthOne(inputUserId));
		}

		return userDetails;
	}
}
```


```
2020-09-14(스프링시큐리티 기본설정)
Part (1)
1.Context.xml 설정

로그인의 권한 인증 로직 자체는 매우 간단하게 짤수 있지만 보안적인 요소까지 고려하면
작성하기가 매우어렵다. 스프링 시큐리티는 보안적용 프레임 워크로 몇가지 설정과 커스터마이징을
거치면 높은 수준의 보안성을 가진 로직을 구현이 가능함

구조 자체는 복잡하지만 우리가 실제로 손대야할 부분은 많지 않아서 큰 그림만 이해하면 쉽게 구성이 가능

(1).- Spring Security 의존 설정 (pom.xml)
기본 내장된 라이브러리가 아니므로 아래 3가지의 의존 설정을 해줌, 사용하고 있는 스프링 버전에 맞춰야 하기 떄문에
버전은 아래와 같이 기입 , pom.xml 가장 윗 부분에 해당 프로퍼티에 버전이 명시 되어있음 태그 라이브러리는 선택 사항이지만 아주 편리하므로 같이 사용해주는 것이 좋다.
 

<!-- Spring security -->
<dependency>
	<groupId>org.springframework.security</groupId>
	<artifactId>spring-security-web</artifactId>
	<version>${org.springframework-version}</version>
</dependency>
<dependency>
	<groupId>org.springframework.security</groupId>
	<artifactId>spring-security-config</artifactId>
	<version>${org.springframework-version}</version>
</dependency>
<dependency>
	<groupId>org.springframework.security</groupId>
	<artifactId>spring-security-taglibs</artifactId>
	<version>${org.springframework-version}</version>
</dependency>

(2).필터 설정 (web.xml)
로그인 권한 인증은 사용자가 서비스를 요청할떄마다 이루어져야 함 , 
인코딩 필터와 마찬가지로 필터 기능을 사용해 서블릿에 도달하기 전 요청을 가로채 작업을 할수 있도록 해줍니다 
모든 URL(/*) 요청을 해당 필터에서 먼저 가로채겠다는 의미

필터 클래스로 등록된 DelegatingProxy 객체는 사용자 요청을 가로채 개발자가 설정 파일에 등록해둔 여러 요소들을 가지고 
스프링의 보안 요소들을 가지고 스프링 보안 로직을 적용하는 시작점  내부 로직을 보면 많은 필터 체인과 처리클래스들이 연동 되어있음

<!-- 스프링 Security 필터 -->
<filter>
	<filter-name>springSecurityFilterChain</filter-name>
	<filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
	<filter-name>springSecurityFilterChain</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>

 (3).root-context 또는 새로 만든 설정 파일 
 스프링에서 제공 해주는 기능을 이용할떄 컨테이너 (컨텍스트)에 등록 해주면 됩니다 . 컨테이너가
 생성 되면서 그 안의 설정을 읽어 적절한 Bean 객체를 생성해주고 사용자가 필요할때 제공해주기 때문
 
 전체 설정 코드 
 (4).security-context.xml  
  xmlns:security="http://www.springframework.org/schema/security" 추가적으로 
  xmlns:s="http://www..~~  네임스페이스의 값을 s로만 주고 <security:login ~<s:login> 코드와 같이 간단한 문자로 변경해서 사용하면 더 공수를 줄일수있음>
  
 <?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:s="http://www.springframework.org/schema/security"
	xsi:schemaLocation="http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd
		http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

	<s:http auto-config="true" use-expressions="true">

		<!-- 정적 리소스는 모두 접근 허용 -->
		<s:intercept-url pattern="/resources/**" access="permitAll" />

		<!-- 로그인된 상태에서는 로그인이나 회원가입 화면에 접근 못하도록 함 -->
		<s:intercept-url pattern="/loginView" access="isAnonymous()" />
		<s:intercept-url pattern="/registerUserView" access="isAnonymous()" />

		<!-- 관리자페이지는 관리자만 접근 허용 -->
		<s:intercept-url pattern="/admin/**" access="hasRole('admin')" />

		<!-- 로그인 설정 -->
		<s:form-login	
			username-parameter="userId" 
			password-parameter="userPw"
			login-processing-url="/loginAsk" 
			login-page="/loginView" default-target-url="/"
			authentication-failure-url="/loginView" />

		<!-- 로그아웃 설정 -->
		<s:logout 
			logout-url="/logoutAsk"
			logout-success-url="/"
			invalidate-session="true"
			delete-cookies="true" />
	</s:http>

	<!-- 권한이 없어서 금지된 URI 접속할 때 보여줄 페이지(403 에러 페이지 대체) -->
	<s:access-denied-handler error-page="/" />

	<!-- DB 연동 설정 -->
	<s:authentication-manager>
		<s:authentication-provider user-service-ref="userLoginService">
		</s:authentication-provider>
	</s:authentication-manager>
	로그인과 로그아웃 설정 부분이 핵심 스프링이 디폴트로 가지고있는 RoLE_USER등의 권한이름이 있고 표현식을 쓰지 않을수도 있지만 그렇게 사용할 일은 거의 없을 거같음 생략
	
	Security 핊터는 사용자가 요청한 Url을 서블릿에게 주지 않고 먼저 가로챔  
	인텁셉터설정은 가로챈 URL을 어떻게 처리할지 결정해주는 부분 / "pattern=/url"을 요청한 사용자가 "access 권한에 맞으면 true 서블릿으로 보내주고 "
	아닐경우에  접근을 금지 시키거나 로그인 페이지로 이동시키겠다 라는 의미 / 권한 표현식 (access= "표현식")에 따라 조정할수 있다.
   
     위에서 부터 순서대로 적용 허용할 범위 > 금지할 범위 > 순으로 작성 같은범위를 ㅈ금지하고 허용하면 먼저 순서인 금지만 적용됨
   나머지 기술적 내용은 Security-context.xml 내용에 담겨있음 
   기술참조 :https://codevang.tistory.com/266 블로그 참조 1-9 단계까지 상세하게 도식화되어 정리되어있음


</beans>
 ```


```
.
회원가입  기능추가 
-주소 api연동후 , 가이드라인 따라서 순차적으로 실행
-회원가입 약관,google , naver , facebook 으로 연동하기
- 이 회원이 실재 주민등록번호에 고유값이 일치한지 체크 < 주민등록번호 < 
- 이메일 api 존재하는지 일치하는지 확인
- 갤러리 공지 사항 다양하게 보여주기 
- 애니메이션 기능 넣어보기 
- 비슷한 쇼핑몰 사이트 구축하기
- 안드로이드앱 제작 및 배포 
- 회원관리 프로그램 제작하기
```
Procfile = heroku 설정파일 / manifest.yml = Cloud Foundry 파스타 설정파일 / 아마존 ?
1. 스프링프로젝트 Leejy_mysql 변경.
2. 이클립스에서 Leejy_mysql 프로젝트를 파스타에 배포.(Hsql용)
3. Leejy_mysql 로컬 mysql서버와 연동처리.
4. 파스타 클라우드에서 Mysql서비스 생성.(원격접속이름과 암호를 확인가능)
5. 원격 phpmyadmin 툴(워크벤치와 비슷)을 파스타 클라우드에 PHP앱 생성 후 배포.
6. Leejy_mysql 프로젝트를 클라우드용 DB사용으로 변경 후 파스타에 	재배포.
   http://kimilguk_mysql.paas-ta.org 
7. egov_sht 프로젝트 이름 변경: Leejy_egov 파스타에 	배포(Mysql클라우드사용).
   http://Leejy_egov.paas-ta.org
***
### 20200812(수) 작업내역 (아래)
- 4. 스프링 Mysql 프로젝트를 로컬Mysql 설정 -> 클라우드 파스타 용으로 변경

```

- 1-0).서비스 생성이후 binding작업하고 푸시
```


```
- 3).작업결과 확인 이클립스에서 파스타 서버 더블 클릭 -> Application and Service 탭에서
	-> 오른쪽에 Update and Restart 버튼을 클릭해서 클라우드 배포  수정사항 적용 
- 2).root-context.xml 파일에 DB 커넥션 설정을 클라우드용으로 추가  spring 관련 설정 파일은 내 프로젝트 수정후 업데이트
- 1).pom.xml 메이븐 파일에 클라우드용 모듈 추가.
```

- 3. 로컬에서 테스트 ok 된후 클라우드에 Mysql 서비스를 생성


```
-4).http://leejy-myadmin.paas-ta.org 접속 후 edu 데이터베이스 자동생성 및 더미 데이터 입력.
-3).아래 php 프로젝트를 파스타에 푸시 (manifest.yml)사용: 클라우드 파운더리cf cli(커맨드라인 인터페이스)설치.
	https://github.com/cloudfoundry/cli#downloads
	터미널 상태에서 phpmyadmin 프로젝트로 이동
	>cf login
	API endpoint: https://api.paas-ta.org
	Email> boramcom@daum.net (본인 파스타 이메일)
	Password> (본인 파스타 패스워드)
	Authenticating...
OK
>cf push 또는 cf push -s cflinuxfs3 (cflinuxfs3으로 스택을 지정해서 배포)
-2).생성된 Mysql 서비스를 웹으로 제어하는 php 프로젝트를 이클립스로 임포트.(Leejy-myadmin 프로젝트명).
-1).온라인 파스타 클라우드에서 Leejy-mysql-db 이름의 Mysql 서비스를 생성
```

-2.Leejy-mysql 프로젝트를 Hsql - > Mysql 변경(아래)

```
- 2). Wamp 실행.후 프로젝트를 톰캣 서버로 확인
- 1). root-context.xml Hsql 주석처리 > mysql 주석해제
```


-1.어제한 내용 리뷰(아래)
-파스타 클라우드에 접속할떄 https://api.paas-ta.org 주소사용
-RestAPI 서버가 htts://api.paas-ta.org
-RestAPI 서버에 Json데이터를 보내서 앱을 생성+ 실행 하게됨

```
manifest.yml (매니페스트 야믈파일)
---
applications:
- name: Leejy-mysql
  memory: 1024M
  disk_quota: 1024M
  instances: 1
  host: leejy-mysql
  domain: paas-ta.org

```


### 20200811(화) 작업내역(아래)
-Junit test로 DAO의 selectMember 실행하기.

```
-Junit code
package Leejy_egov;

import javax.inject.Inject; //inject
import javax.sql.DataSource; //ds
import java.sql.Connection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import edu.human.com.member.service.impl.MemberDAO;
import edu.human.org.member.service.EmployerInfoVO;
import edu.human.org.member.service.MemberService;


/*@RunWith(SpringJUnit4ClassRunner.class)

이 애노테이션을 붙여줘야 스프링 테스트를 Junit으로 돌릴 수 있음.
@ContextConfiguration(classes = { RootContextConfig.class }, loader = AnnotationConfigWebContextLoader.class)

RootContextConfig.class를 spring context의 빈 설정 파일로 사용한다는 의미.
@WebAppConfiguration

이 애너테이션을 붙이면 Controller및 web환경에 사용되는 빈들을 자동으로 생성하여 등록하게됨.*/

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "file:src/main/webapp/WEB-INF/config/egovframework/springmvc/egov-com-servlet.xml",
		"file:src/main/resources/egovframework/spring/com/*.xml" })
@WebAppConfiguration
public class TestMember {
	@Inject
	private MemberDAO dao;
	
	@Inject
	private DataSource ds;
	
	@Test
	public void testInsertMember() throws Exception{
		EmployerInfoVO vo = new EmployerInfoVO();
	}
	@Test
	public void testSelectMember() throws Exception{
		List <EmployerInfoVO> list = dao.selectMember(); 
		//dao 에있는  쿼리메서드를 리스트에 넣어주고 List VO에있는 데이터 list 형을 
		// 출력하기위에 향상된 for문을 해줌
		for (EmployerInfoVO vo:list) {
			System.out.println("회원아이디:"+vo.getEmplyr_id());
			System.out.println("회원이름 :"+vo.getUser_nm());
		}
	}
	@Test
	public void testDbConnect() throws Exception {
		Connection con = ds.getConnection();
		System.out.println("데이터 베이스 커넥션 결과" + con);
		// 커넥션 클래스를 사용  
	}
	// junit No such Bean 파일 등록이 안되는이유는 
	// 루트를 잡아주는 경로 xml 파일이 exclude 가 되어있기떄문에 include로 경로를 
	// 바꾸면서 빈등록과동시에 error처리 해결
	@Test
	public void test() throws Exception {
		System.out.println("Junit 테스트 확인");
	}
}
3. // junit No such Bean 파일 등록이 안되는이유는 
	// 루트를 잡아주는 경로 egov-com-servlet.xml 파일이 exclude 가 되어있기떄문에 include로 경로를 
	// 바꾸면서 빈등록과동시에 error처리 해결
	junit test 중 select member에 bean이 등록 
	egov-com-servlet.xml 파일에서 component-scan 부분에서 제외한 (exclude)를 > 포함시킴(include)
2. src/test/java~ TestMember.java 추가함 @ContextConfiguration 경로 2개 추가
1.전자정부 프로젝트는 기본 junit 이 없기 떄문에 테스트 환경 만들어야함 pox.xml에 junit 모듈 추가하기
- maven update 4.3.22 jar 파일  offline으로 다운받아줘야함
<!-- Test 참조 https://offbyone.tistory.com/155 -->
<dependency>
	<groupId>junit</groupId>
	<artifactId>junit</artifactId>
	<version>4.12</version>
	<scope>test</scope>
</dependency>
<dependency>
	<groupId>javax.servlet</groupId>
	<artifactId>javax.servlet-api</artifactId>
	<version>3.0.1</version>
	<scope>test</scope>
</dependency>
<dependency>
	<groupId>org.springframework</groupId>
	<artifactId>spring-core</artifactId>
	<version>4.3.22.RELEASE</version>
 </dependency>
 <dependency>
	<groupId>org.springframework</groupId>
	<artifactId>spring-test</artifactId>
	<version>4.3.22.RELEASE</version>
</dependency>
<dependency>
	<groupId>javax.inject</groupId>
	<artifactId>javax.inject</artifactId>
	<version>1</version>
</dependency>

```


-DAO(@Repostiory), Service(@service)만들기

```
3.MemberServiceImpl.java ( 구현 클래스 ) @Resource()> @Inject 사용
2.MemberService.java ( 인터 페이스 )
1.MemberDAO.java (추상클래스를 사용 , extends EgovAbstract Mapper 추가)
```


- 프로젝트에서 Mybatis 사용하기 

```
5.
-mapper folder 생성 , config folder 생성
-Leejy2_egov/src/main/resources/egovframework/mapper/config
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE configuration PUBLIC "-//mybatis.org//DTD Config 3.0//EN" "http://mybatis.org/dtd/mybatis-3-config.dtd">
<configuration>
	<!--Mybatis 설정 -->
	<settings>
		<!-- 전통적인 데이터베이스 컬럼명 형태인 A_COLUMN을 CamelCase형태의 자바 프로퍼티명 형태인 aColumn으로 자동으로 매핑하도록 함 -->
		<setting name="mapUnderscoreToCamelCase" value="true"></setting>
		<!--  파라미터에 Null 값이 있을 경우 에러 처리 -->
		<setting name="jdbcTypeForNull" value="VARCHAR"></setting>
	</settings>
</configuration>
4.Spring-Mybatis 설정파일 context.mapper.xml
- configLoaction: 마이바티스 설정파일 위치 mapper-config.xml 추가
- mapperLocation: 쿼리가 존재하는 폴더 위치 : member_mysql.xml 추가
- Leejy2_egov/src/main/resources/egovframework/spring/com 경로에 
- context-mapper.xml 생성
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-4.0.xsd">
    <!-- 실행환경에서 빈이름 참조(EgovAbstractDAO) -->
	<bean id="egov.lobHandler" class="org.springframework.jdbc.support.lob.DefaultLobHandler" lazy-init="true" />
	<!-- Mybatis setup for Mybatis Database Layer -->
	<bean id="egov.sqlSession" class="org.mybatis.spring.SqlSessionFactoryBean">		
		<property name="dataSource" ref="egov.dataSource"/>
		<property name="configLocation" value="classpath:/egovframework/mapper/config/mapper-config.xml" />
		<property name="mapperLocations">
			<list>
				<value>classpath:/egovframework/mapper/com/**/*_${Globals.DbType}.xml</value>
			</list>
		</property>
	</bean>
	<!-- Mybatis Session Template -->
	<bean id="egov.sqlSessionTemplate" class="org.mybatis.spring.SqlSessionTemplate">
		<constructor-arg ref="egov.sqlSession"/>
	</bean>
</beans>

3.관리자 관리 테이블과 get,set하는 VO 만들기 : EmployerinfoVO.java
  -테이블 생성 쿼리에서 필드명 복사 VO 자바파일에서 사용, 특이사항: 대 >소  ctrl shift+y 단축키 소문자로 변경
2.관리자 관리에 사용되는 테이블 확인 :emplyrinfo
1.Pom.xml 메이븐 모듈추가(아래)
<!-- 마이바티스 사용 -->
		<dependency>
			<groupId>org.mybatis</groupId>
			<artifactId>mybatis</artifactId>
			<version>3.2.8</version>
		</dependency>
		<dependency>
			<groupId>org.mybatis</groupId>
			<artifactId>mybatis-spring</artifactId>
			<version>1.2.2</version>
		</dependency>
```


### 20200810(월) 작업내역(아래)
- context-datasource.xml: Hsql 데이터베이스 사용 주석처리

```
<!-- hsql -->
<!-- 여기만 주석처리
<jdbc:embedded-database id="dataSource-hsql" type="HSQL">
	<jdbc:script location= "classpath:/db/shtdb.sql"/>
</jdbc:embedded-database>
-->
```

- globals.properties :(주,유니코드 에디터로 수정) DB에 관련된 전역변수 지정(아래)

```
# DB서버 타입(mysql,oracle,altibase,tibero) - datasource 및 sqlMap 파일 지정에 사용됨
Globals.DbType = mysql
Globals.UserName=root
Globals.Password=apmsetup
# mysql
Globals.DriverClassName=net.sf.log4jdbc.DriverSpy
Globals.Url=jdbc:mysql://127.0.0.1:3306/sht
#Hsql - local hssql 사용시에 적용
#Globals.DriverClassName=net.sf.log4jdbc.DriverSpy
#Globals.Url=jdbc:log4jdbc:hsqldb:hsql://127.0.0.1/sampledb
```
- web.xml : 톰캣(WAS)가 실행될때 불러들이는 xml설정들 확인.

```
egov-com-serlet.xml(아래) 
- DispatcherServlet(서블렛배치=콤포넌트-scan:@Controller,@Service,@Repository에 관련된 설정 수정)
- <context:component-scan base-package="egovframework,edu">
- 위에서 ,edu 추가: edu.human.com패키지추가로 해당패키지로 시작하는 콤포넌트를 빈(실행가능한 클래스)으로 자동등록하게 처리
```
- pom.xml : 메이븐 설정 파일중 Hsql DB를 Mysql DB사용으로 변경(아래)

```
<!-- 주석처리
<dependency>
	<groupId>org.hsqldb</groupId>
	<artifactId>hsqldb</artifactId>
	<version>2.3.2</version>
</dependency>
 -->
<!-- mysql driver 주석해제 -->	
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>5.1.31</version>
</dependency>

<!-- log4jdbc driver 주석해제. 기능:Console창에 쿼리보이기 -->        
<dependency>
    <groupId>com.googlecode.log4jdbc</groupId>
    <artifactId>log4jdbc</artifactId>
    <version>1.2</version>
    <exclusions>
        <exclusion>
            <artifactId>slf4j-api</artifactId>
            <groupId>org.slf4j</groupId>
        </exclusion>
    </exclusions>
</dependency>
```