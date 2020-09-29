<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<title>Html 5 test 입니다.</title>
<style>
h1 {
	background-color: rgb(255, 0, 255);
}
</style>
<script src="http//code.jquery.com/jquery-Latest.min.js"></script>
<script src="/resources/js/user.js"></script>
</head>
<body>
	<h1>HTML 이란?</h1>
	<h2>HTML 의역사</h2>
	<h3>팀 버너스리에 대해 </h3>
	<h4>HTML 의 태그</h4>
	<h5>HTML 의 태그</h5>
	<p>  
	<strong>이것은</strong>문단입니다.<br> <b>이것은 </b> 문단입니다
	</p>
	<p>
	이것은&nbsp; &nbsp; &nbsp; &nbsp; &amp; &lt; &copy; &nbsp;&nbsp;&nbsp;&nbsp; 문단입니다.
	<hr>
	이것은 문단입니다.
	</p>
	<ul>
		<li>리스트1</li>
		<li>리스트2</li>
	</ul>
	<ol> 
		<li>리스트1</li>
		<li>리스트2</li>>
	</ol>
	<img src="/resources/images/summer.jpg"  alt="" >
	<div>
	<h2> 회원가입 폼입니다.</h2>
	<form method ="get" action = "http://localhost:8080/" class=adminlogin_form">
	성별을 선택해 주세요
	<select name="score">
	<option value="m">남자</option>
	<option value="w">여자</option>
	</select>
	<br>
	<input type="text" name ="userid" preholder="user ID">
	<input type ="file"> <br> 본인 소개글 작성:
	<textarea name="contents" cols="100" rows="5">여기에 글을 입력</textarea>
	<input type="submit"  name ="submit" value ="회원가입" class="loigin">
	</form>
	</div>
	<table summary="00학교 00반 성적표" sytle="border:1px solid black";>
	<table border="1">
		<caption>이 테이블은 학생들의 성적표 입니다.</caption>
		<tr>
			<th >이름</th>
			<th >성적</th>
		</tr>
		<tr>
			<td>AAA</td>
			<td>AB</td>
		</tr>
		<tr>
			<td colspan="2">BBB</td>
			<td>B</td>
		</tr>
		<tr>
			<td>CCC</td>
			<td>C</td>
		</tr>
	</table>
	<form>
		<input type="text" value="text"> <br /> <input
			type="password" value="password"> <br /> <input
			type="button" value="button"><br /> <input type="submit"
			value="submit"><br /> <input type="date"><br /> <input
			type="radio" value="radio">radio<br /> <input type="checkbox"
			value="checkbox"> check box<br /> <input type="file"><br />
		<input type="search"> <input type="hidden" value="hidden">
	</form>
	<form>
		<fieldset>
			<legend> Login</legend>
			ID <input type="text" /> password <input type="password" />
		</fieldset>

		<fieldset>
			<legend> Login2</legend>
			E-mail <input type="e-mail" /> password <input type="password" />
		</fieldset>
	</form>
	<header id="main">
		로고 및 회사명 /초기메뉴
		<nav id="main_gnb">메인 메뉴</nav>
	</header>
	<div id="content">
		<section id="main_section">
			<article class="main_article">공지사항 등</article>
		</section>
		<footer id="main_footer"> 개인정보 보호 및 주소 등 </footer>
		<h1>header - 1</h1>
		<h2>header - 2</h2>
		<h3>header - 3</h3>
		<h4>header - 4</h4>
		<h5>header - 5</h5>
		<h6>header - 6</h6>
		<h1>JavaScript 구현예</h1>
		<p id="exam">변경 전</p>
		<button type="button" onclick="myFunction()">변경</button>
</body>
</html>