<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>  
<%@ include file="../include/header.jsp" %>
<style>
.board table , .board table td{border:1px solid;}
</style>
<!-- container -->
	<div id="container" class="board" >
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
			<ul class="bbsview_list">
				<li class="bbs_title">${boardVO.title}</li>
				<li class="bbs_writer">작성자	<span>${boardVO.writer}</span></li>
				<li class="bbs_hit">작성일 : <span><fmt:formatDate pattern="yyyy-MM-dd HH:mm" value="${boardVO.regdate}" /></span></li>
				<li class="bbs_date">조회수 : <span>${boardVO.view_count}</span></li>
				<li class="bbs_content">
					<div class="editer_content">
					${boardVO.content}
                    </div>
				</li>
				<c:if test="${boardVO.files[0] != null}">
					<li class="bbs_content">
					<a href="/download?filename=${boardVO.files[0]}">${boardVO.files[0]} 다운로드</a>
					<br>
					<c:set var="extName" value="${fn:split(boardVO.files[0],'.')}" />
					<c:set var="ext" value="${extName[fn:length(extName)-1]}" />
					<c:if test="${fn:containsIgnoreCase(extNameArray, ext)}">
						<img src="/download?filename=${boardVO.files[0]}" title="첨부파일 이미지" style="width:100%;">
					</c:if>
					</li>
				</c:if>
			</ul>
			<p class="btn_line txt_right">
				<c:out value="${session_id}"/>
				<c:out value="${boardVO.writer}"/>
				<a href="javascript:;" id="deleteBno" class="btn_bbs">삭제</a>
				<a id="updateBno" href="/board/update?page=${pageVO.page}&amp;bno=${boardVO.bno}" class="btn_bbs">수정</a>
				<a href="/board/list?page=${pageVO.page}" class="btn_bbs">목록</a>
			</p>
		</div>
		<!-- //bodytext_area -->

	</div>
<!-- //container -->
<form id="deleteForm">
	<input name="bno" id="bno" type="hidden" value="${boardVO.bno}">
</form>
<form id="updateForm">
	<input name="bno" id="bno" type="hidden" value="{boardVO.bno}">
</form>
<script>
$(document).ready(function(){
	$("#deleteBno").bind("click",function(){
		if(confirm("정말 삭제 하시겠습니까?")) {
			var formObj = $("#deleteForm");
			formObj.attr("action", "/board/delete");
			formObj.attr("method", "post");
			//alert($("#bno").val());//디버그용
			formObj.submit();
		}else{
			return false;
		}
		
	})
});

</script>
<%@ include file="../include/footer.jsp" %>