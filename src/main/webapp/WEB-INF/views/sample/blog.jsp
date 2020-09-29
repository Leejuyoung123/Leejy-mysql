<%@ page contentType="text/html; charset=utf-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ page session="false"%>

<!DOCTYPE HTML>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport"
	content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scaleable=no">
<title>HOME</title>
<link rel="shortcut icon" href="/images/favicon/favicon.ico">
<link rel="apple-touch-icon-precomposed"
	href="/images/favicon/home-touch-icon.png">
<link rel="stylesheet" type="text/css" href="/resources/css/reset.css">
<link rel="stylesheet" type="text/css" href="/resources/css/common.css">
<style>
/* BLOG 영역 CSS */
.blog-section {
	margin-top: 77px;
}

.blog-section .sec-tit {
	margin-bottom: 47px;
	text-align: center;
}

.blog-section .blog-list li {
	width: 100%;
	margin-top: 45px;
}

.blog-section .blog-list li:first-child {
	margin-top: 0;
}

.blog-section .blog-list li img {
	display: block;
	width: 100%;
	max-width: 100%;
	height: auto;
}

.blog-section .blog-list li time {
	display: block;
	margin: 11px 0 10px 0;
	font-size: 11px;
	color: #9e9e9e;
}

.blog-section .blog-list li h3 {
	color: #424242;
	font-weight: normal;
	line-height: 1.6;
}
/* 태블릿용 CSS */
@media all and (min-width:768px) {
	.blog-section {
		margin-top: 124px;
	}
	.blog-section .sec-tit {
		margin-bottom: 76px;
	}
	.blog-section .blog-list li {
		float: left;
		width: 31.59722222222%;
		margin-left: 2.60416666666%;
		margin-top: 0;
	}
	.blog-section .blog-list li:first-child {
		margin-left: 0;
	}
}
/* PC용 BLOG 영역 CSS */
@media all and (min-width: 1132px) {
.blog-section .sec-tit {
float :left ;
margin-bottom:0;
}
.blog-section .blog-list{
float:right;
width:74.5583038869258%;
/* 844px / 1132px */
}
.blog-section .blog-list li {
width:31.75355450236967%;
/* 268px / 844px  */
margin-left:2.369668246445498%;
/* 20px / 844px */
}
}
</style>
<script src="/resources/js/jquery.min.js"></script>
<script src="/resources/js/common.js"></script>
<!-- 사용자 스크립트 -->
<script>
	
</script>
</head>
<body>
	<!-- 더미 데이터:CSS작업전 내용 -->
	<div id="wrap">
		<header class="header cfixed">
			<h1 class="logo">
				<a href="">LOGO</a>
			</h1>
			<nav>
				<ul class="gnb">
					<li><a href="/">HOME</a></li>
					<li><a href="/weare">WE ARE</a></li>
					<li><a href="/work">WORK</a></li>
					<li><a href="/blog">BLOG</a></li>
					<li><a href="contactus">CONTACT US</a></li>
				</ul>
			</nav>
			<span class="menu-toggle-btn"> <span></span> <span></span> <span></span>
			</span>
		</header>
		<section class="blog-section">
			<div class="container">
				<h2 class="sec-tit">BLOG</h2>
				<ul class="blog-list">
					<li><a href="#" onclick="return false"><img
							src="/resources/images/summer.jpg" alt=""></a> <time
							datetime="2016-10-30">OCT 30, 2016</time> <a href=""><h3>타임스페이스는
								사용자 중심의 웹페이지를 제작하는 회사 입니다.</h3></a></li>
					<li><a href="#" onclick="return false"><img
							src="/resources/images/summer.jpg" alt=""></a> <time
							datetime="2016-10-30">OCT 30, 2016</time> <a href=""><h3>타임스페이스는
								사용자 중심의 웹페이지를 제작하는 회사 입니다.</h3></a></li>
					<li><a href="#" onclick="return false"><img
							src="/resources/images/summer.jpg" alt=""></a> <time
							datetime="2016-10-30">OCT 30, 2016</time> <a href=""><h3>타임스페이스는
								사용자 중심의 웹페이지를 제작하는 회사 입니다.</h3></a></li>
				</ul>
			</div>
		</section>
		<footer class="footer">
			<p class="copyright">LOGO</p>
		</footer>
	</div>
</body>
</html>