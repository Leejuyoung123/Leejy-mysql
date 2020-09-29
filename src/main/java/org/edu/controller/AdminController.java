package org.edu.controller;

import java.io.File;
import java.util.List;
import java.util.Locale;

import javax.inject.Inject;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.edu.service.IF_BoardService;
import org.edu.service.IF_MemberService;
import org.edu.util.FileDataUtil;
import org.edu.vo.BoardVO;
import org.edu.vo.MemberVO;
import org.edu.vo.PageVO;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin")
public class AdminController {
	
	@Inject
	private IF_BoardService boardService;
	
	@Inject
	private IF_MemberService memberService;
	
	@Inject
	private FileDataUtil fileDataUtil;
	
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
		return "admin/board/board_list";
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
		return "admin/board/board_view";
	}
	
	/**
	 * 게시물관리 > 등록 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/board/write", method = RequestMethod.GET)
	public String boardWrite(Locale locale, Model model) throws Exception {
		
		return "admin/board/board_write";
	}
	@RequestMapping(value = "/board/write", method = RequestMethod.POST)
	public String boardWrite(MultipartFile file,@Valid BoardVO boardVO,Locale locale, RedirectAttributes rdat,HttpSession session) throws Exception {
		
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
		return "redirect:/admin/board/list";
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
		return "admin/board/board_update";
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
		return "redirect:/admin/board/view?bno=" + boardVO.getBno() + "&page=" + pageVO.getPage();
	}
	
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
		return "redirect:/admin/board/list";
	}
	
	
	/**
	 * 회원관리 리스트 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/member/list", method = RequestMethod.GET)
	public String memberList(@ModelAttribute("pageVO") PageVO pageVO, Locale locale, Model model) throws Exception {
		if(pageVO.getPage() == null) {
			pageVO.setPage(1);
		}
		pageVO.setPerPageNum(10);
		pageVO.setTotalCount(memberService.countUserId(pageVO));
		List<MemberVO> list = memberService.selectMember(pageVO);
		//모델클래스로 jsp화면으로 memberService에서 셀렉트한 list값을 memberList변수명으로 보낸다.
		//model { list -> memberList -> jsp }
		model.addAttribute("memberList", list);
		model.addAttribute("pageVO", pageVO);
		return "admin/member/member_list";
	}
	
	/**
	 * 회원관리 상세보기 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/member/view", method = RequestMethod.GET)
	public String memberView(@ModelAttribute("pageVO") PageVO pageVO, @RequestParam("user_id") String user_id, Locale locale, Model model) throws Exception {
		MemberVO memberVO = memberService.viewMember(user_id);
		model.addAttribute("pageVO", pageVO);
		model.addAttribute("memberVO", memberVO);
		return "admin/member/member_view";
	}
	
	/**
	 * 회원관리 > 등록 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/member/write", method = RequestMethod.GET)
	public String memberWrite(Locale locale, Model model) throws Exception {
		
		return "admin/member/member_write";
	}
	@RequestMapping(value = "/member/write", method = RequestMethod.POST)
	public String memberWrite(@Valid MemberVO memberVO, Locale locale, RedirectAttributes rdat) throws Exception {
		String new_pw = memberVO.getUser_pw();//예를 들면 1234
		if(new_pw != "") {
			//스프링 시큐리티 4.x BCryptPasswordEncoder 암호화 사용
			BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder(10);
			String bcryptPassword = bcryptPasswordEncoder.encode(new_pw);//예, 1234 -> 암호화 처리됨
			memberVO.setUser_pw(bcryptPassword);//DB에 들어가기전 값 set시킴.
		}
		memberService.insertMember(memberVO);
		rdat.addFlashAttribute("msg", "입력");
		return "redirect:/admin/member/list";
	}
	
	/**
	 * 회원관리 > 수정 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/member/update", method = RequestMethod.GET)
	public String memberUpdate(@ModelAttribute("pageVO") PageVO pageVO, @RequestParam("user_id") String user_id, Locale locale, Model model) throws Exception {
		MemberVO memberVO = memberService.viewMember(user_id);
		model.addAttribute("memberVO", memberVO);
		model.addAttribute("pageVO", pageVO);
		return "admin/member/member_update";
	}
	@RequestMapping(value = "/member/update", method = RequestMethod.POST)
	public String memberUpdate(@ModelAttribute("pageVO") PageVO pageVO, MemberVO memberVO, Locale locale, RedirectAttributes rdat) throws Exception {
		String new_pw = memberVO.getUser_pw();//예를 들면 1234
		if(new_pw != "") {
			//스프링 시큐리티 4.x BCryptPasswordEncoder 암호화 사용
			BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder(10);
			String bcryptPassword = bcryptPasswordEncoder.encode(new_pw);//예, 1234 -> 암호화 처리됨
			memberVO.setUser_pw(bcryptPassword);//DB에 들어가기전 값 set시킴.
		}		
		memberService.updateMember(memberVO);
		rdat.addFlashAttribute("msg", "수정");
		return "redirect:/admin/member/view?user_id=" + memberVO.getUser_id() + "&page=" + pageVO.getPage();
	}
	
	/**
	 * 회원관리 > 삭제 입니다.
	 * @throws Exception 
	 */
	@RequestMapping(value = "/member/delete", method = RequestMethod.POST)
	public String memberDelete(@RequestParam("user_id") String user_id, Locale locale, RedirectAttributes rdat) throws Exception {
		memberService.deleteMember(user_id);
		rdat.addFlashAttribute("msg", "삭제");
		return "redirect:/admin/member/list";
	}
	
	/**
	 * 관리자 홈 입니다.
	 */
	@RequestMapping(value = "", method = RequestMethod.GET)
	public String home(Locale locale, Model model) {
		
		return "admin/home";
	}
	
}