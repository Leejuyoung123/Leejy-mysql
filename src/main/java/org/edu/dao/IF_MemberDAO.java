package org.edu.dao;

import java.util.List;

import org.edu.vo.MemberVO;
import org.edu.vo.PageVO;
import org.edu.vo.SnsVO;
public interface IF_MemberDAO {
	public void insertMember(MemberVO memberVO) throws Exception;
	public String memberList(MemberVO memberVO)throws Exception;
	public List<MemberVO> selectMember(PageVO pageVO) throws Exception;
	public void updateMember(MemberVO memberVO) throws Exception;
	public void deleteMember(String user_id) throws Exception;
	public MemberVO viewMember(String user_id) throws Exception;
	public int countUserId(PageVO pageVO) throws Exception;
	public List<MemberVO> androidMember() throws Exception;
	}
