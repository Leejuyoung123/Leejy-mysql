<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ include file="include/header.jsp"%>
<script type="text/javascript" src="https://static.nid.naver.com/js/naverLogin_implicit-1.0.2.js" charset="utf-8"></script>
<script>
	if ('${param.msg}' == "fail") {
		alert('로그인에 실패했습니다.! 상세메세지 ${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}');
	}
</script>
<!-- container start -->
<div id="container">
	<!-- location_area -->
	<div class="location_area member">
		<div class="box_inner">
			<h2 class="tit_page">
				스프링 <span class="in">in</span> 자바
			</h2>
			<p class="location">
				MEMBER <span class="path">/</span> 로그인
			</p>
			<ul class="page_menu clear">
				<li><a href="javascript:;" class="on">로그인</a></li>
			</ul>
		</div>
	</div>
	<!-- //location_area -->

	<!-- bodytext_area -->
	<div class="bodytext_area box_inner">
		<!-- appForm -->
		<form action="/login" method="post" class="appForm">
			<fieldset>
				<legend>로그인</legend>
				<p class="info_pilsoo pilsoo_item">필수입력</p>
				<ul class="app_list">
					<li class="clear"><label for="name_lbl"
						class="tit_lbl pilsoo_item">아이디</label>
						<div class="app_content">
							<input name="user_id" type="text" class="w100p" id="name_lbl"
								placeholder="아이디를 입력해주세요" />
						</div></li>
					<li class="clear"><label for="pwd_lbl"
						class="tit_lbl pilsoo_item">암호</label>
						<div class="app_content">
							<input name="user_pw" type="password" class="w100p" id="pwd_lbl"
								placeholder="암호를 입력해주세요" />
						</div></li>
				</ul>
				<p class="btn_line">
					<button type="submit" class="btn_baseColor">로그인</button>
				</p>
			</fieldset>
		</form>
		<!-- //appForm -->
		<p class="btn_line">
			<a href="${url}" class="btn_baseColor"
				style="background-color: green; width: 200px;">네이버ID로 로그인</a>
		</p>
	</div>
	<!-- //bodytext_area -->

</div>
<!-- //container -->
<%@ include file="include/footer.jsp"%>