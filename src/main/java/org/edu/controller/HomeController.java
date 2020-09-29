package org.edu.controller;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.edu.service.IF_BoardService;
import org.edu.service.IF_MemberService;
import org.edu.util.FileDataUtil;
import org.edu.vo.BoardVO;
import org.edu.vo.MemberVO;
import org.edu.vo.PageVO;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.github.scribejava.core.model.OAuth2AccessToken;

/**
 * Handles requests for the application home page.
 */
@Controller
public class HomeController {
	
	@Inject
	private IF_MemberService memberService;
	
	@Inject
	private IF_BoardService boardService;
	
	@Inject
	private FileDataUtil fileDataUtil;
	
	@Inject
	private NaverLoginController naverLoginController;
	
	private static final Logger logger = LoggerFactory.getLogger(HomeController.class);
	
	/**
	 * 게시물관리 > 삭제 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/board/delete", method = RequestMethod.POST)
	public String boardDelete(@RequestParam("bno") Integer bno, Locale locale, RedirectAttributes rdat) throws Exception {
		List<String> files = boardService.selectAttach(bno);
		
		boardService.deleteBoard(bno);
		
		//첨부파일 삭제(아래)
		for(String fileName : files) {
			//삭제 명령문 추가(아래)
			File target = new File(fileDataUtil.getUploadPath(), fileName);
			if(target.exists()) {
				target.delete();
			}
		}		
		
		rdat.addFlashAttribute("msg", "삭제");
		return "redirect:/board/list";
	}
	
	/**
	 * 게시물관리 > 수정 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/board/update", method = RequestMethod.GET)
	public String boardUpdate(@ModelAttribute("pageVO") PageVO pageVO, @RequestParam("bno") Integer bno, Locale locale, Model model) throws Exception {
		BoardVO boardVO = boardService.viewBoard(bno);
		model.addAttribute("boardVO", boardVO);
		model.addAttribute("pageVO", pageVO);
		return "board/board_update";
	}
	@RequestMapping(value = "/board/update", method = RequestMethod.POST)
	public String boardUpdate(@ModelAttribute("pageVO") PageVO pageVO, MultipartFile file,@Valid BoardVO boardVO,Locale locale, RedirectAttributes rdat) throws Exception {
		if(file.getOriginalFilename() == "") {//조건:첨부파일 전송 값이 없다면
			boardService.updateBoard(boardVO);
		} else {
			//기존등록된 첨부파일 삭제처리(아래)
			List<String> delFiles = boardService.selectAttach(boardVO.getBno());
			for(String fileName : delFiles) {
				//실제파일 삭제
				File target = new File(fileDataUtil.getUploadPath(), fileName);
				if(target.exists()) { //조건:해당경로에 파일명이 존재하면
					target.delete();  //파일삭제
				}//End if
			}//End for
			//아래 신규파일 업로드
			String[] files = fileDataUtil.fileUpload(file);//실제파일업로드후 파일명 리턴
			boardVO.setFiles(files);//데이터베이스 <-> VO(get,set) <-> DAO클래스
			boardService.updateBoard(boardVO);
		}//End if
		rdat.addFlashAttribute("msg", "수정");
		return "redirect:/board/view?bno=" + boardVO.getBno() + "&page=" + pageVO.getPage();
	}
	
	/**
	 * 게시물관리 > 등록 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/board/write", method = RequestMethod.GET)
	public String boardWrite(Locale locale, Model model) throws Exception {
		
		return "board/board_write";
	}
	@RequestMapping(value = "/board/write", method = RequestMethod.POST)
	public String boardWrite(MultipartFile file,@Valid BoardVO boardVO,Locale locale, RedirectAttributes rdat) throws Exception {
		//System.out.println("========첨부파일없이 저장===" + file.getOriginalFilename());
		if(file.getOriginalFilename() == "") {
			//첨부파일 없이 저장
			boardService.insertBoard(boardVO);
		}else {
			String[] files = fileDataUtil.fileUpload(file);
			boardVO.setFiles(files);
			boardService.insertBoard(boardVO);			
		}
		rdat.addFlashAttribute("msg", "입력");
		return "redirect:/board/list";
	}
	
	/**
	 * 게시물관리 상세보기 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/board/view", method = RequestMethod.GET)
	public String boardView(@ModelAttribute("pageVO") PageVO pageVO, @RequestParam("bno") Integer bno,Locale locale, Model model) throws Exception {
		BoardVO boardVO = boardService.viewBoard(bno);
		//여기서 부터 첨부파일명 때문에 추가
		List<String> files = boardService.selectAttach(bno);
		String[] filenames = new String[files.size()];
		int cnt = 0;
		for(String fileName : files) {
			filenames[cnt++] = fileName;
		}
		//여러개 파일에서 1개 파일만 받는 것으로 변경
		//String[] filenames = new String[] {files};
		boardVO.setFiles(filenames);//String[]
		//여기까지 첨부파일때문에 추가
		model.addAttribute("boardVO", boardVO);
		model.addAttribute("pageVO", pageVO);
		model.addAttribute("extNameArray", fileDataUtil.getExtNameArray());
		return "board/board_view";
	}
	
	/**
	 * 게시물관리 리스트 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/board/list", method = RequestMethod.GET)
	public String boardList(@ModelAttribute("pageVO") PageVO pageVO, Locale locale, Model model) throws Exception {
		//PageVO pageVO = new PageVO();//매개변수로 받기전 테스트용
		if(pageVO.getPage() == null) {
			pageVO.setPage(1);//초기 page변수값 지정
		}
		pageVO.setPerPageNum(10);//1페이지당 보여줄 게시물 수 강제지정
		pageVO.setTotalCount(boardService.countBno(pageVO));//강제로 입력한 값을 쿼리로 대체OK.
		List<BoardVO> list = boardService.selectBoard(pageVO);
		//모델클래스로 jsp화면으로 boardService에서 셀렉트한 list값을 boardList변수명으로 보낸다.
		//model { list -> boardList -> jsp }
		model.addAttribute("boardList", list);
		model.addAttribute("pageVO", pageVO);
		return "board/board_list";
	}
	
	/**
	 * 스프링 시큐리티 secutiry-context.xml설정한 로그인 처리 결과 화면
	 * @param locale
	 * @param request
	 * @param rdat
	 * @return
	 * @throws Exception 
	 */
	@RequestMapping(value = "/login_success", method = RequestMethod.GET)
	public String login_success(Locale locale,HttpServletRequest request, RedirectAttributes rdat) throws Exception {
		logger.info("Welcome login_success! The client locale is {}.", locale);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String userid = "";//아이디
		String levels = "";//ROLE_ANONYMOUS
		Boolean enabled = false;
		Object principal = authentication.getPrincipal();
		if (principal instanceof UserDetails) {
			//인증이 처리되는 로직(아이디,암호를 스프링시큐리티 던져주고 인증은 스프링에서 알아서 해줌.)
			enabled = ((UserDetails)principal).isEnabled();
		}
		HttpSession session = request.getSession();//세션을 초기화 시켜줌.
		if (enabled) { //인증처리가 완료된 사용자의 권한체크(아래)
			Collection<? extends GrantedAuthority>  authorities = authentication.getAuthorities();
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ANONYMOUS")).findAny().isPresent())
			{levels = "ROLE_ANONYMOUS";}
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_USER,")).findAny().isPresent())
			{levels = "ROLE_USER,";}
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ADMIN")).findAny().isPresent())
			{levels = "ROLE_ADMIN";}
			userid =((UserDetails)principal).getUsername();
			//로그인 세션 저장
			session.setAttribute("session_enabled", enabled);//인증확인
			session.setAttribute("session_userid", userid);//사용자아이디
			session.setAttribute("session_levels", levels);//사용자권한
			//=========== 상단은 스프링시큐리티에서 기본제공하는 세션 변수처리
			//=========== 하단은 우리가 추가한는 세션 변수처리
			//회원이름 구하기 추가
			MemberVO memberVO = memberService.viewMember(userid);
			session.setAttribute("session_username", memberVO.getUser_name());//사용자명
        	}
		rdat.addFlashAttribute("msg", "로그인");//result 데이터를 숨겨서 전송
		return "redirect:/";//새로고침 자동 등록 방지를 위해서 아래처럼 처리
	}
	
	/**
	 * 네이버 아이디 로그인 (SNS로그인,외부로그인,통합로그인) 에서 사용하는
	 * 인증 후 리턴값 처리(파싱) 로직이 들어가는 곳.
	 */
	@RequestMapping(value="/login_callback", method= {RequestMethod.GET, RequestMethod.POST})
	public String login_callback(@ModelAttribute MemberVO memberVO ,Model model, @RequestParam String code, @RequestParam String state, HttpSession session, RedirectAttributes rdat) throws Exception {
		OAuth2AccessToken oauthToken;//인증정보가 저장된 데이터 변수
		oauthToken = naverLoginController.getAccessToken(session, code, state);
		//네이버에 로그인한 사용자 정보를 읽어온다(아래) 토큰인증정보에서 String으로 사용자정보 뽑기
		String apiResult = naverLoginController.getUserProfile(oauthToken);
		//model.addAttribute("result",apiResult);
		//위에 jsp로 변수값 보내는 로직을 타지 않고, 스프링 시큐리티 로직을 탈겁니다.
		/* Json 데이터 파싱 시작 */
		/** apiResult의 데이터 형태구조는 아래와 같습니다.
		 * {
		 * "resultcode":"00",
		 * "message":"success",
		 * "response":{"id":"33555449","nickname":"닉네임","age":"20-29"
		 * ,"gender":"M","email":"kimilguk@knou.ac.kr","name":"유니코드이름"}
		 * }
		 */
		JSONParser parser = new JSONParser();
		Object obj = parser.parse(apiResult);
		JSONObject jsonObj = (JSONObject) obj;
		//Top레벨 단계의 response 파싱(아래) 왜 2번 하냐하면, 위 데이터값이 배열안 배열이 있기때문
		JSONObject response_obj = (JSONObject) jsonObj.get("response");
		//파싱 마지막인 response 객체의 name 값과 email값 뽑기(아래)
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String username = (String) response_obj.get("name");
		String useremail = (String) response_obj.get("email");
		String Status = (String) jsonObj.get("message");
		
		String levels="";
		String userid="";
		memberVO.setUser_id(useremail);
		memberVO.setUser_name(username);
		boolean enabled=false;
		
		Object principal = authentication.getPrincipal();
		if (principal instanceof UserDetails) {
			//인증이 처리되는 로직(아이디,암호를 스프링시큐리티 던져주고 인증은 스프링에서 알아서 해줌.)
			enabled = ((UserDetails)principal).isEnabled();
		}
		Map<String,String> log = new HashMap<String,String>();
		log.put("userid", userid);
		log.put("useremail", useremail);
		if (enabled) { //인증처리가 완료된 사용자의 권한체크(아래)
			Collection<? extends GrantedAuthority>  authorities = authentication.getAuthorities();
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ANONYMOUS")).findAny().isPresent())
			{levels = "ROLE_ANONYMOUS";}
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_USER,")).findAny().isPresent())
			{levels = "ROLE_USER,";}
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ADMIN")).findAny().isPresent())
			{levels = "ROLE_ADMIN";}
			userid =((UserDetails)principal).getUsername();
			//로그인 세션 저장
			
			session.setAttribute("session_enabled", enabled);//인증확인
			session.setAttribute("session_userid", log);//사용자아이디
			session.setAttribute("session_levels", levels);//사용자권한
			}
		/* Json 데이터 파싱 끝 */
		if(Status.equals("success")) {
			//진짜 핵심: 스크링시큐리티와 연동시키는 로직(아래)
			/* 네이버로 SNS로 로그인한 사람들은 강제로 스프링 시큐리티 인증처리 함 아래 */
			List<SimpleGrantedAuthority> authorities = new ArrayList<>();
			//authority 권한에 ROLE_USER 권한만 줍니다.(아래)
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
			//authentication 인증에 강제로 email을 부여하고, 암호는 null로 처리(아래)
			authentication = new UsernamePasswordAuthenticationToken(log,null,authorities);
			//실제로 스프링 시큐리티에 인증처리 get/set중에서 set처리.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			 // db 정보를 받아오는 클래스르
			/* 로그인 세션=전역변수역할 저장 (아래) */
			session.setAttribute("session_enabled", true);//인증확인
			session.setAttribute("session_userid", log);//네이버사용자이메일
			session.setAttribute("session_levels", "ROLE_USER");//사용자권한
			session.setAttribute("session_username", username);//네이버사용자이름
			rdat.addFlashAttribute("msg", "SNS 로그인");//msg데이터를 숨겨서 jsp로 전송
		}else {
			//즉, 네이버 로그인이 실패했을때(아래)
			rdat.addFlashAttribute("param.msg","fail");
			return "redirect:/login";
		}
		return "redirect:/";//새로고침시 자동등록을 방지 하기 위해서.
	}

	/**
	 * 로그인 페이지 파일 입니다.
	 */
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String login(Locale locale, Model model, HttpSession session) {
		/* 
		 * 네이버아이디로 인증 URL을 생성하기 위하여 naverLoginController클래스의
		 * getAuthorizationUrl메서드 호출 session은 전역변수와 같은 역할을 합니다.
		 * naverAuthUrl는 http://127.0.0.1:8080/login 이고, 이 값을 
		 * 네이버API에서 가져오는 메서드가 getAuthorizationUrl(session)
		 */
		String naverAuthUrl = naverLoginController.getAuthorizationUrl(session);
		model.addAttribute("url", naverAuthUrl);//url변수값이 login.jsp 전송됩니다.
		return "login";
	}
	
	/**
	 * 슬라이드 페이지 파일 입니다.
	 */
	@RequestMapping(value = "/sample/slide", method = RequestMethod.GET)
	public String slide(Locale locale, Model model) {
		
		return "sample/slide";
	}
	
	/**
	 * CONTACT US 페이지 파일 입니다.
	 */
	@RequestMapping(value = "/sample/contactus", method = RequestMethod.GET)
	public String contactus(Locale locale, Model model) {
		
		return "sample/contactus";
	}
	
	/**
	 * BLOG 페이지 파일 입니다.
	 */
	@RequestMapping(value = "/sample/blog", method = RequestMethod.GET)
	public String blog(Locale locale, Model model) {
		
		return "sample/blog";
	}
	
	/**
	 * WORK 페이지 파일 입니다.
	 */
	@RequestMapping(value = "/sample/work", method = RequestMethod.GET)
	public String work(Locale locale, Model model) {
		
		return "sample/work";
	}
	
	/**
	 * we are 페이지 파일 입니다.
	 */
	@RequestMapping(value = "/sample/weare", method = RequestMethod.GET)
	public String weare(Locale locale, Model model) {
		
		return "sample/weare";
	}
	
	/**
	 * html5 테스트용 파일 입니다.
	 */
	@RequestMapping(value = "/sample/htmltest", method = RequestMethod.GET)
	public String htmltest(Locale locale, Model model) {
		
		return "sample/htmltest";
	}
	
	/**
	 * 샘플 파일 홈 입니다.
	 */
	@RequestMapping(value = "/sample", method = RequestMethod.GET)
	public String sample(Locale locale, Model model) {
		
		return "sample/home";
	}
	
	/**
	 * Simply selects the home view to render by returning its name.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String home(Locale locale, Model model) throws Exception {
		PageVO pageVO = new PageVO();
		if(pageVO.getPage() == null) {
			pageVO.setPage(1);//초기 page변수값 지정
		}
		pageVO.setPerPageNum(5);//1페이지당 보여줄 게시물 수 강제지정
		pageVO.setTotalCount(boardService.countBno(pageVO));//강제로 입력한 값을 쿼리로 대체OK.
		List<BoardVO> list = boardService.selectBoard(pageVO);
		//첨부파일 출력 때문에 추가 Start
		List<BoardVO> boardListFiles = new ArrayList<BoardVO>();
		for(BoardVO vo:list) {
			List<String> files = boardService.selectAttach(vo.getBno());
			String[] filenames = new String[files.size()];
			int cnt = 0;
			for(String fileName : files) {
				filenames[cnt++] = fileName;
			}
			vo.setFiles(filenames);//여기까지는 view상세보기와 똑같다
			boardListFiles.add(vo);//상세보기에서 추가된 항목
		}
		model.addAttribute("extNameArray", fileDataUtil.getExtNameArray());//첨부파일이 이미지인지 문서파일인 구분용 jsp변수
		//첨부파일 출력 때문에 추가 End
		model.addAttribute("boardList", boardListFiles);		
		return "home";
	}
	
}