<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ include file="include/header.jsp"%>
<!-- container start -->
<div id="container">
	<!-- location_area -->
	<div class="location_area member">
		<div class="box_inner">
			<h2 class="tit_page">
				스프링 <span class="in">in</span> 자바
			</h2>
			<p class="location">
				에러페이지 <span class="path">/</span> 에러페이지
			</p>
			<ul class="page_menu clear">
				<li><a href="javascript:;" class="on">${exception.getMessage()}</a></li>
			</ul>
		</div>
	</div>
	<!-- //location_area -->

	<!-- bodytext_area -->
	<div class="bodytext_area box_inner">
		<p>
			<a href='<c:out value="${prevPage}"/>'>이전페이지로 가기</a>
		</p>
		<p>에러 상세 내역</p>
		<ul>
			<c:forEach items="${exception.getStackTrace()}" var="stack">
				<li class="clear">${stack.toString()}</li>
			</c:forEach>
		</ul>
	</div>
	<!-- //bodytext_area -->
</div>
<!-- //container -->
<%@ include file="include/footer.jsp"%>