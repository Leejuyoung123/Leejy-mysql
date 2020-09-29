<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ include file="../include/header.jsp"%>
<!-- //container -->
<div id="container">
		<!-- location_area -->
		<div class="location_area customer">
			<div class="box_inner">
				<h2 class="tit_page">스프링 <span class="in">in</span> 자바</h2>
				<p class="location">고객센터 <span class="path">/</span> 공지사항</p>
				<ul class="page_menu clear">
					<li><a href="#" class="on">공지사항</a></li>
					<li><a href="#">문의하기</a></li>
				</ul>
			</div>
		</div>	
		<!-- //location_area -->

		<!-- bodytext_area -->
		<div class="bodytext_area box_inner">
			<form action="/board/list" class="minisrch_form">
				<fieldset>
					<legend>검색</legend>
					<input name="searchType" type="hidden" value="all"> 
					<input name="searchKeyword" type="text" class="tbox" title="검색어를 입력해주세요" placeholder="검색어를 입력해주세요">
					<button type="submit" class="btn_srch">검색</button>
				</fieldset>
			</form>
			<table class="bbsListTbl" summary="번호,제목,조회수,작성일 등을 제공하는 표">
				<caption class="hdd">공지사항  목록</caption>
				<thead>
					<tr>
						<th scope="col">번호</th>
						<th scope="col">제목</th>
						<th scope="col">조회수</th>
						<th scope="col">작성일</th>
					</tr>
				</thead>
				<tbody>
					<c:forEach items="${boardList}" var="boardVO" varStatus="status">
					<tr> 
						<td>${boardVO.bno}</td>
						<td><a href="/board/view?bno=${boardVO.bno}&page=${pageVO.page}">${boardVO.title}</a></td>
						<td class="right badge badge-danger">${boardVO.view_count }</td>
						<td><fmt:formatDate pattern="yyyy-MM-dd HH:mm" value="${boardVO.regdate}"/></td>
					</tr>
					</c:forEach>
				</tbody>
				
			</table>
			<!-- pagination -->
			<div class="pagination">
			<c:if test="${pageVO.prev}">
				<a href=/board/list?page=${pageVO.startPage -1}&searchType=${pageVO.searchType}&searchKeyword=${pageVO.searchKeyword}" class="prevpage pbtn"> <img src="/resources/home/img/btn_prevpage.png" alt="이전 페이지로 이동"></a>
			</c:if>
			<c:forEach begin="${pageVO.startPage}" end="${pageVO.endPage}" var="idx">
					<a href="/board/list?page=${idx}&searchType=${pageVO.searchType}&searchKeyword=${pageVO.searchKeyword}"><span class='pagenum <c:out value="${idx == pageVO.page?'currentpage':''}"/>'>${idx}</span></a>
			</c:forEach>
			<c:if test= "${pageVO.next}">
				<a href="/board/list?page=${pageVO.endPage +1}&searchType=${pageVO.searchType}&searchKeyword=${pageVO.searchKeyword}" class="nextpage  pbtn"><img src="/resources/home/img/btn_nextpage.png" alt="다음 페이지로 이동"></a>
			</c:if>
			
			</div>
			<!-- //pagination -->
			
			<p class="btn_line">
				<a href="/board/write" class="btn_baseColor">등록</a>
			</p>
		</div>
		<!-- //bodytext_area -->

	</div>
	<!-- //container -->
<%@ include file="../include/footer.jsp"%>