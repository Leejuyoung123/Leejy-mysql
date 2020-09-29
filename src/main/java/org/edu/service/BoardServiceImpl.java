package org.edu.service;

import java.util.List;

import javax.inject.Inject;

import org.edu.dao.IF_BoardDAO;
import org.edu.vo.BoardVO;
import org.edu.vo.PageVO;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class BoardServiceImpl implements IF_BoardService {
	@Inject
	private IF_BoardDAO boardDAO;
	@Transactional
	@Override
	public void insertBoard(BoardVO boardVO) throws Exception {
		boardDAO.insertBoard(boardVO);
		//첨부파일용 서비스추가
		String[] files = boardVO.getFiles();
		if(files == null) { return; }
		for(String fileName : files) {
			boardDAO.insertAttach(fileName);
		}
	}

	@Override
	public List<BoardVO> selectBoard(PageVO pageVO) throws Exception {
		return boardDAO.selectBoard(pageVO);
	}
	@Transactional
	@Override
	public void updateBoard(BoardVO boardVO) throws Exception {
		
		boardDAO.updateBoard(boardVO);
		//첨부파일용 서비스 추가
		String[] files = boardVO.getFiles();
		Integer bno = boardVO.getBno(); //tbl_attach 테이블 수정용 변수
		if(files == null ) {return;}
		boardDAO.deleteAttach(bno); // 기존 첨부파일 내용을 삭제
		for(String fileName : files ) {
		boardDAO.updateAttach(fileName, bno); // 신규 첨부파일 내용 입력
		}
	}
	@Transactional
	@Override
	public void deleteBoard(Integer bno) throws Exception {
		boardDAO.deleteAttach(bno);
	// attach가 밑에있으면 삭제가 안되는이유:	
		boardDAO.deleteBoard(bno);
		
	}

	@Override
	public BoardVO viewBoard(Integer bno) throws Exception {
		boardDAO.updateViewCount(bno);
		return boardDAO.viewBoard(bno);
	}

	@Override
	public List<String> selectAttach(Integer bno) throws Exception {
		return boardDAO.selectAttach(bno);
	}

	@Override
	public int countBno(PageVO pageVO) throws Exception {
		return boardDAO.countBno(pageVO);
	}

}