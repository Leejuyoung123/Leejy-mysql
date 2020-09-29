package org.edu.test;

import javax.inject.Inject; //inject
import javax.sql.DataSource; //ds
import java.sql.Connection;
import java.util.List;

import org.edu.service.IF_MemberService; //service IF_MemberService 인터페이스 호출 현재 패키지는 org.edu.test
import org.edu.vo.MemberVO;
import org.edu.vo.PageVO;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;



@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations ={"file:src/main/webapp/WEB-INF/spring/**/*.xml"})
@WebAppConfiguration
public class DataSourceTest {
	@Inject
	private IF_MemberService memberService;
	@Inject
	private DataSource ds;	
	
	@Test
	public void testConection()throws Exception{
		
		try(Connection con = ds.getConnection()){
			
			System.out.println(con);
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}	
		@Test
		public void testInsertMember() throws Exception{
		//memberVO를 사용하기위해 클래스변수를 생성
		MemberVO memberVO = new MemberVO();
		memberVO.setUser_id("Lee2Jy");
		memberVO.setUser_pw("1234");
		memberVO.setUser_name("이주2영");
		memberVO.setEmail("Lee2jy@test.com");
		memberVO.setPoint(100);
		memberVO.setEnabled(true);
		memberVO.setLevels("ROLE_USER");
		memberService.insertMember(memberVO);
		/*try (Connection con = ds.getConnection()) {
			System.out.println("=========================================================");
			System.out.println("데이터베이스 커넥션 성공:" + con);
			System.out.println("=========================================================");
		}
		hsql db 생성시 서버가 열려있을떄만 남아있고 
		다시 접속하면 남아있지 않고 초기화
		 													*/		
		}
		@Test
	public void testSelectMember() throws Exception {
		System.out.println("회원 리스트 입니다");
		
		PageVO pageVO =new PageVO();
		pageVO.setPage(1);
		pageVO.setPerPageNum(10);
		memberService.selectMember(pageVO);
		List<MemberVO> list = memberService.selectMember(pageVO);
		System.out.println(list);
		/*
		 * List<MemberVO> list = memberService.selectMember();
		 * for(MemberVO vo:list) { System.out.println("사용자 아이디"+ vo.getUser_id());
		 * System.out.println("사용자 이메일"+ vo.getEmail());}
		 */
		}
		@Test
		public void testUpdateMember() throws Exception{
		//memberVO를 사용하기위해 클래스변수를 생성
		MemberVO memberVO = new MemberVO();
		memberVO.setUser_id("user00");
		memberVO.setUser_pw("1234");
		memberVO.setUser_name("이주영");
		memberVO.setEmail("Leejy@test.com");
		memberVO.setPoint(100);
		memberVO.setEnabled(true);
		memberVO.setLevels("ROLE_ADMIN");
		memberService.updateMember(memberVO);
		
		}
		@Test
		public void testDeleteMember() throws Exception{
		//memberVO를 사용하기위해 클래스변수를 생성
		memberService.deleteMember("user02");
		}
}