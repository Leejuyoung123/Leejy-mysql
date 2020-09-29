package org.edu.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.edu.dao.IF_MemberDAO;
import org.edu.vo.MemberVO;
import org.edu.vo.PageVO;
import org.edu.vo.SnsVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Service;

@Service
public class MemberServiceImpl implements IF_MemberService {

	@Inject
	private IF_MemberDAO memberDAO;
	
	@Override
	public void insertMember(MemberVO memberVO) throws Exception {
		memberDAO.insertMember(memberVO);		
	}

	@Override
	public List<MemberVO> selectMember(PageVO pageVO) throws Exception {
		return memberDAO.selectMember(pageVO);
	}

	@Override
	public void updateMember(MemberVO memberVO) throws Exception {
		memberDAO.updateMember(memberVO);
	}

	@Override
	public void deleteMember(String user_id) throws Exception {
		memberDAO.deleteMember(user_id);
	}

	@Override
	public MemberVO viewMember(String user_id) throws Exception {
		return memberDAO.viewMember(user_id);
	}

	@Override
	public int countUserId(PageVO pageVO) throws Exception {
		return memberDAO.countUserId(pageVO);
	}

	@Override
	public String memberList(MemberVO memberVO) throws Exception {
		return memberDAO.memberList(memberVO);
	}
}