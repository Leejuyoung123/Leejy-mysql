package org.edu.service;

import java.util.List;

import org.edu.vo.BoardVO;
import org.edu.vo.PageVO;

public interface IF_BoardService  {
	 public void insertBoard(BoardVO boardVO) throws Exception;
	 public List<BoardVO> selectBoard(PageVO pageVO)throws Exception;
	 public void updateBoard(BoardVO boardVO) throws Exception;
	 public void deleteBoard(Integer bno) throws Exception;
	 public BoardVO viewBoard(Integer  bno) throws Exception;
	 public List<String> selectAttach(Integer bno)throws Exception;
	 public int countBno(PageVO pageVO) throws Exception;
}
