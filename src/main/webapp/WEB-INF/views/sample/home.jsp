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
<link rel="stylesheet" type="text/css" href="/resources/css/user.css">
<style>
.go_top {
	position: fixed;
	right: 20px;
	bottom: 112px;
	text-align: center;
	background: red;
	z-index: 100;
	padding: 20px;
	opacity: 0.5;
	color: blue !important;
}
</style>
<script src="/resources/js/jquery.min.js"></script>
<script src="/resources/js/common.js"></script>
<!-- 사용자 스크립트 -->
<script>
	
</script>
<!-- 부트스트랩 -->
<link href="/resources/bootstrap/css/bootstrap.min.css" rel="stylesheet">
<!-- 모든 컴파일된 플러그인을 포함합니다 (아래), 원하지 않는다면 필요한 각각의 파일을 포함하세요 -->
<script src="/resources/bootstrap/js/bootstrap.min.js"></script>
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
					<li><a href="#weare">WE ARE</a></li>
					<li><a href="#work">WORK</a></li>
					<li><a href="#blog">BLOG</a></li>
					<li><a href="#contactus">CONTACT US</a></li>
				</ul>
			</nav>
			<span class="menu-toggle-btn"> <span></span> <span></span> <span></span>
			</span>
		</header>

		<article class="slider">
			<img src="/resources/images/summer.jpg" alt="">
		</article>
		<section class="content">

			<section class="display-section">
				<div class="container">
					<h2 class="sec-tit" id="weare">WE ARE</h2>
					<p class="desc">
						"휴먼 교육센터 디지털 컨버전스 과정 입니다." <br> "그리고, 지금은 화면 설계 시간 입니다."
					</p>
				</div>
			</section>

			<section class="promotion-section">
				<div class="container">
					<ul class="promo-list">
						<li><a href="#" onclick="return false"> <img
								src="/resources/images/summer.jpg" alt="">
								<h3>HOME</h3>
								<p>휴면 교육센터 디지털 컨버전스 과정 입니다.</p>
						</a></li>
						<li><a href="#" onclick="return false"> <img
								src="/resources/images/summer.jpg" alt="">
								<h3>HOME</h3>
								<p>휴면 교육센터 디지털 컨버전스 과정 입니다.</p>
						</a></li>
						<li><a href="#" onclick="return false"> <img
								src="/resources/images/summer.jpg" alt="">
								<h3>HOME</h3>
								<p>휴면 교육센터 디지털 컨버전스 과정 입니다.</p>
						</a></li>
						<li><a href="#" onclick="return false"> <img
								src="/resources/images/summer.jpg" alt="">
								<h3>HOME</h3>
								<p>휴면 교육센터 디지털 컨버전스 과정 입니다.</p>
						</a></li>
					</ul>
				</div>
			</section>

		</section>
		<section class="work-section cfixed">
			<h2 class="sec-tit" id="work">WORK</h2>
			<ul class="work-list">
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
				<li><a href="#" onclick="return false">
						<div class="info">
							<h3>작업1</h3>
							<span>소스/작업1</span>
						</div> <img src="/resources/images/summer.jpg" alt="">
				</a></li>
			</ul>
		</section>
		<section class="blog-section">
			<div class="container">
				<h2 class="sec-tit" id="blog">BLOG</h2>
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
		<section class="contact-section">
			<div class="container">
				<h2 class="sec-tit" id="contactus">CONTACT</h2>
				<div class="form-box">
					<form action="" method="GET">
						<fieldset class="cfixed">
							<legend class="blind">CONTACT US</legend>
							<div class="form">
								<label for="name" class="blind">name</label> <input type="text"
									id="name" placeholder="Name"> <label for="phone"
									class="blind">phone</label> <input type="tel" id="phone"
									placeholder="Phone"> <label for="email" class="blind">email</label>
								<input type="email" id="email" placeholder="Email Address">
							</div>
							<div class="textarea">
								<label for="message" class="blind">message</label>
								<textarea name="message" id="message" placeholder="Message"></textarea>
							</div>
						</fieldset>
						<div class="send-btn">
							<button type="button" class="" data-toggle="modal"
								data-target="#exampleModal">메세지 보내기</button>
						</div>
					</form>
				</div>
			</div>
		</section>

		<footer class="footer">
			<p class="copyright">LOGO</p>
		</footer>
	</div>
	<a href="#" class="s_point"><p class="go_top">TOP</p></a>

	<!-- Modal -->
	<div class="modal fade" id="exampleModal" tabindex="-1" role="dialog"
		aria-labelledby="exampleModalLabel" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<div class="modal-header">
					<h5 class="modal-title" id="exampleModalLabel">Modal title</h5>
					<button type="button" class="close" data-dismiss="modal"
						aria-label="Close">
						<span aria-hidden="true">&times;</span>
					</button>
				</div>
				<div class="modal-body">
					<input class="form-control" type="text" id="message"
						placeholder="메세지 내용을 입력해주세요">
				</div>
				<div class="modal-footer">
					<button type="button" class="btn btn-info"
						data-dismiss="modal">수정</button>
					<button type="button" class="btn btn-danger"
						data-dismiss="modal">삭제</button>
					<button type="button" class="btn" data-dismiss="modal">닫기</button>
				</div>
			</div>
		</div>
	</div>

</body>
</html>