<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

	<footer>
		<div class="foot_area box_inner">
			<ul class="foot_list clear">
				<li><a href="/resources/home/javascript:;">이용약관</a></li>
				<li><a href="/resources/home/javascript:;">개인정보취급방침</a></li>
			</ul>
			<h2>스프링</h2>
            <p class="addr">OOOO OOOOO OOOO OOOOOOOOO OOOOO <span class="gubun">/</span>        
				<span class="br_line">대표전화 <span class="space0">02-1234-5678</span> <span class="gubun">/</span>        
					<span class="br_line">E-mail : <span class="space0"> admin@OOOO OOOOO.com</span></span>
				</span>
			</p>
			<p class="copy box_inner">Copyright(c) OOOO OOOOO all right reserved</p>
			<ul class="snslink clear">
				<li><a href="/resources/home/javascript:;">blog</a></li>
				<li><a href="/resources/home/javascript:;">facebook</a></li>
				<li><a href="/resources/home/javascript:;">instargram</a></li>
			</ul>
		</div>
	</footer>

</div>
<!-- //wrap -->

<h2 class="hdd">빠른 링크 : 전화 문의,카카오톡,오시는 길,꼭대기로</h2>
<div class="quick_area">
	<ul class="quick_list">
		<li><a href="/resources/home/tel:010-1234-5678"><h3>전화 문의</h3><p>010-1234-5678</p></a></li>
		<li><a href="/resources/home/javascript:;"><h3>카카오톡 <em>상담</em></h3><p>1:1상담</p></a></li>
		<li><a href="/resources/home/javascript:;"><h3 class="to_contact">오시는 길</h3></a></li>
	</ul>
	<p class="to_top"><a href="#layout0" class="s_point">TOP</a></p>
</div>

<script type="text/javascript" src="/resources/home/js/swiper.min.js"></script>
<script type="text/javascript">
   $(document).ready(function(){
		var swiper = new Swiper('.swiper-container', {
			loop: true,
			autoplay:5500,
		    autoplayDisableOnInteraction: false,
			pagination: '.swiper-pagination',
            paginationClickable: true
		});
	});
</script>

<!-- contact_pop -->
<div class="popup_base contact_pop">
	<div class="pop_content">
		<p class="btn_xpop"><a href="#" onclick="$(this).parent().parent().parent().hide();">닫기</a></p>
		<ul class="pop_list">
			<li>
				<h2 class="tit_pop">OOOO OOOOO</h2>
				<img class="pop_img"src="/resources/home/img/img_pop1_1.jpg" alt="OOOO OOOOO" />
				<div class="pop_txt"><p>OOOO OOOOOOOOO OOOOO. <br>OOOO OOOOOOOOO OOOOOOOOO OOOOOOOOO OOOOOOOOO OOOOOOOOO OOOOO. </p></div>
			</li>
		</ul>		
	</div>
</div>
<!-- //contact_pop -->

<!-- space_pop -->
<div class="popup_base space_pop">
	<div class="pop_content">
		<p class="btn_xpop"><a href="#" onclick="$(this).parent().parent().parent().hide();">닫기</a></p>
		<ul class="pop_list">
			<li>
				<h2 class="tit_pop">OOOO OOOOO</h2>
				<img class="pop_img"src="/resources/home/img/img_pop2_1.jpg" alt="OOOO OOOOO" />
				<div class="pop_txt"><p>OOOO OOOOOOOOO OOOOOOOOO OOOOO. <br> OOOO OOOOOOOOO OOOOOOOOO OOOOO. </p></div>
			</li>
			<li>
				<h2 class="tit_pop">OOOO OOOOO</h2>
				<img class="pop_img"src="/resources/home/img/img_pop2_2.jpg" alt="OOOO OOOOO" />
				<div class="pop_txt"><p>OOOO OOOOOOOOO OOOOO.<br>OOOO OOOOOOOOO OOOOOOOOO OOOOOOOOO OOOOO.</p></div>
			</li>
		</ul>		
	</div>
</div>
<!-- //space_pop -->

<!-- program_pop -->
<div class="popup_base program_pop">
	<div class="pop_content">
		<p class="btn_xpop"><a href="#" onclick="$(this).parent().parent().parent().hide();">닫기</a></p>
		<ul class="pop_list">
			<li>
				<h2 class="tit_pop">OOOO OOOOO</h2>
				<img class="pop_img"src="/resources/home/img/img_pop3_1.jpg" alt="OOOO OOOOO" />
				<div class="pop_txt"><p>OOOO OOOOOOOOO OOOOOOOOO OOOOO.<br>OOOO OOOOO, OOOO OOOOO, OOOO OOOOOOOOO OOOOO.</p></div>
			</li>
		</ul>		
	</div>
</div>
<!-- //program_pop -->

</body>
</html>