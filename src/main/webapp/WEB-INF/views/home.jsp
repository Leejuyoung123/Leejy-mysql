<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>
<%@ include file="include/header.jsp"%>
<style>
.board table, .board table td {
	border:   1px solid;
}
</style>
<!-- Content Wrapper. Contains page content -->
<div id="container">

	<div class="main_rolling_pc">
		<div class="visualRoll">
			<ul class="viewImgList">
				<li class="imglist0">
					<div class="roll_content"></div>
				</li>
				<li class="imglist1">
					<div class="roll_content"></div>
				</li>
				<li class="imglist2"></li>
			</ul>

			<div class="rollbtnArea">
				<ul class="rollingbtn">
					<li class="seq butt0"><a href="#butt"><img
							src="/resources/home/img/btn_rollbutt_on.png" alt="1번" /></a></li>
					<li class="seq butt1"><a href="#butt"><img
							src="/resources/home/img/btn_rollbutt_off.png" alt="2번" /></a></li>
					<li class="seq butt2"><a href="#butt"><img
							src="/resources/home/img/btn_rollbutt_off.png" alt="3번" /></a></li>
					<li class="rollstop"><a href="#" class="stop"><img
							src="/resources/home/img/btn_roll_stop.png" alt="멈춤" /></a></li>
					<li class="rollplay"><a href="#" class="play"><img
							src="/resources/home/img/btn_roll_play.png" alt="재생" /></a></li>
				</ul>
			</div>
			<!-- //rollbtnArea -->

		</div>
		<!-- //visualRoll -->
	</div>
	<!-- //main_rolling_pc -->

	<div class="main_rolling_mobile">
		<div class="swiper-container">
			<div class="swiper-wrapper">
				<div class="swiper-slide">
					<a href="/resources/home/javascript:;"><img
						src="/resources/home/img/mainslide_mob01.jpg"
						alt="OOOO OOOOO 믿을 수 있는 스프링정보, 스프링... OOOO OOOOO?" /></a>
				</div>
				<div class="swiper-slide">
					<a href="/resources/home/javascript:;"><img
						src="/resources/home/img/mainslide_mob02.jpg"
						alt="OOOO OOOOO 믿을 수 있는 스프링정보, 스프링... OOOO OOOOO?" /></a>
				</div>
				<div class="swiper-slide">
					<a href="/resources/home/javascript:;"><img
						src="/resources/home/img/mainslide_mob03.jpg"
						alt="OOOO OOOOO 믿을 수 있는 스프링정보, 스프링... OOOO OOOOO?" /></a>
				</div>
			</div>
			<div class="swiper-pagination"></div>
			<!-- <div class="swiper-button-next"></div>
                <div class="swiper-button-prev"></div> -->

		</div>
		<!--//swiper-container-->
	</div>
	<!--//main_rolling_mobile -->

	<!-- about_area -->
	<div class="about_area">
		<h2>
			스프링 프로젝트<b>TOP 3</b>
		</h2>
		<div class="about_box">
			<ul class="place_list box_inner clear">
				<c:forEach items="${boardList}" var="boardVO" varStatus="status">
					<c:if test="${status.count <= 3}">
						<li style="overflow: hidden"><a
							href="/board/view?bno=${boardVO.bno}&page=1"> <!-- 첨부파일이 있을때 if -->
								<c:if test="${boardVO.files[0] != null }">
									<c:set var="extName" value="${fn:split(boardVO.files[0],'.')}" />
									<c:set var="ext" value="${extName[fn:length(extName)-1]}" />
									<!-- 첨부파일이 있는데 이미지일때와 이미지가 아닐때 choose -->
									<c:choose>
										<c:when test="${fn:containsIgnoreCase(extNameArray, ext)}">
											<img src="/download?filename=${boardVO.files[0]}"
												title="첨부파일 이미지" style="width: 100%;">
										</c:when>
										<c:otherwise>
											<img class="img_topplace"
												src="/resources/home/img/img_topplace01.jpg" alt="이미지 없음" />
										</c:otherwise>
									</c:choose>
								</c:if> <!-- 첨부파일이 없을때 if --> <c:if test="${boardVO.files[0] == null }">
									<img class="img_topplace"
										src="/resources/home/img/img_topplace01.jpg" alt="이미지 없음" />
								</c:if>

								<h3>${boardVO.title}</h3>
								<p class="txt">
									<c:out value="${boardVO.content}" escapeXml="false" />
								</p> <span class="view">VIEW</span></a></li>
					</c:if>
				</c:forEach>
			</ul>
		</div>
	</div>
	<!-- //about_area -->

	<!-- app_area -->
	<div class="appbbs_area">
		<div class="appbbs_box box_inner clear">
			<h2 class="hdd">상담과 최근게시물</h2>
			<p class="app_line">
				<a href="/resources/home/javascript:;">카카오톡 1:1 상담</a> <a
					href="/resources/home/javascript:;">전화 상담 신청</a>
			</p>
			<div class="bbs_line">
				<h3>
					<a href="/board/list">NOTICE</a>
				</h3>
				<ul class="notice_recent">
					<c:forEach items="${boardList}" var="boardVO" varStatus="status">
						<li><a href="/board/view?bno=${boardVO.bno}&page=1">${boardVO.title}</a></li>
					</c:forEach>
				</ul>
			</div>
		</div>
	</div>
	<!-- //app_area -->

</div>
<!-- //Content Wrapper -->
<%@ include file="include/footer.jsp"%>
