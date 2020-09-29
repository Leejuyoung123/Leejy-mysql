package org.edu.dao;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.apache.ibatis.session.SqlSession;
import org.edu.vo.MemberVO;
import org.edu.vo.PageVO;
import org.edu.vo.SnsVO;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;

@Repository
public class MemberDAOImpl implements IF_MemberDAO {

	private static String mapperQuery = "org.edu.dao.IF_MemberDAO";
	
	@Inject
	private SqlSession sqlSession; 
	
	@Override
	public void insertMember(MemberVO memberVO) throws Exception {
		sqlSession.insert(mapperQuery + ".insertMember", memberVO);
	}

	@Override
	public List<MemberVO> selectMember(PageVO pageVO) throws Exception {
		return sqlSession.selectList(mapperQuery + ".selectMember", pageVO);
	}

	@Override
	public void updateMember(MemberVO memberVO) throws Exception {
		sqlSession.update(mapperQuery + ".updateMember", memberVO);
	}

	@Override
	public void deleteMember(String user_id) throws Exception {
		sqlSession.delete(mapperQuery + ".deleteMember", user_id);
		
	}

	@Override
	public MemberVO viewMember(String user_id) throws Exception {
		return sqlSession.selectOne(mapperQuery + ".viewMember", user_id);
	}

	@Override
	public int countUserId(PageVO pageVO) throws Exception {
		return sqlSession.selectOne(mapperQuery + ".countUserId", pageVO);
	}

	@Override
	public String memberList(MemberVO memberVO) throws Exception {
		return sqlSession.selectOne(mapperQuery +".memberList", memberVO);
	}

	@Override
	public List<MemberVO> androidMember() throws Exception {
		return sqlSession.selectList(mapperQuery +".androidMember");
	}
}