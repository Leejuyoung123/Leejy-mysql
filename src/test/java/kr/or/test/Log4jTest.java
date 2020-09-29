package kr.or.test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.log4j.Logger;

public class Log4jTest {
	private Logger log = Logger.getLogger(Log4jTest.class);
//  기술참조 https://smujihoon.tistory.com/121
	private void test() {
	MemberVO memberVO =new MemberVO();
	memberVO.setName("홍길동");
	memberVO.setAge(30);
	try {
		InetAddress localpc = InetAddress.getLocalHost();
		String ip = localpc.getHostAddress();
		log.info("test 메서드를 사용한 PC의 아이피는:"+ip);
	} catch (UnknownHostException e) {
		e.printStackTrace();
	}
	
	log.debug("디버그"+memberVO);
	log.info("info");
	log.warn("warn");
	log.error("error");
	log.fatal("fatal");
	// * logger level : debug < info < warn < error < fatal
	}

	public static void main(String[] args) {
		new Log4jTest().test();
		
	}
	
}
