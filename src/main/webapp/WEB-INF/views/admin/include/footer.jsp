<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!-- Control Sidebar -->
		<aside class="control-sidebar control-sidebar-dark">
			<!-- Control sidebar content goes here -->
			<div class="p-3">
				<h5>Title</h5>
				<p>Sidebar content</p>
				<a href="/logout" class="btn btn-primary btn-lg btn-block">로그아웃</a>
			</div>
		</aside>	
<!-- Main Footer -->
<footer class="main-footer">
	<!-- To the right -->
	<div class="float-right d-none d-sm-inline">Anything you want</div>
	<!-- Default to the left -->
	<strong>Copyright &copy; 2014-2020 <a
		href="https://adminlte.io">AdminLTE.io</a>.
	</strong> All rights reserved.
</footer>
<!-- ./wrapper -->

<!-- REQUIRED SCRIPTS -->

<!-- Bootstrap 4 -->
<script src="/resources/plugins/bootstrap/js/bootstrap.bundle.min.js"></script>
<!-- AdminLTE App -->
<script src="/resources/dist/js/adminlte.min.js"></script>

<!-- footer.jsp 하단에 저장 : 아래 [클래스명을입력]부분을 학생이 채우세요... -->
<script>
$(document).ready(function() {
    var current = location.pathname;
  	//alert(current.split("/",3)[2]);
    var current_split = current.split("/",3)[2];
    
    $('.nav-treeview li a').each(function(){
        var $this = $(this);
		if (current=="/admin" || current=="/admin/"){
       	}else{
        // if($this.attr('href').includes(current) == true){
        	//  크로스 브라우징 : //웹브라우저에서는 active 활성화가되는데 이클립스 브라우저 에서는 되지 않아서 수정 indexof 0 ,-1 비교 
        if($this.attr('href').indexOf(current_split) != -1){
        	$this.addClass('active');
           
        }else{
        	$this.removeClass('active');
        }
       }
    })
 });
</script>
