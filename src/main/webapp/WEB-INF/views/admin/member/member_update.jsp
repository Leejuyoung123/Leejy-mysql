<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ include file="../include/header.jsp"%>

<!-- Content Wrapper. Contains page content -->
<div class="content-wrapper">
	<!-- Content Header (Page header) -->
	<div class="content-header">
		<div class="container-fluid">
			<div class="row mb-2">
				<div class="col-sm-6">
					<h1 class="m-0 text-dark">
						DashBoard Management <small>priview</small>
					</h1>
				</div>
				<!-- /.col -->
				<div class="col-sm-6">
					<ol class="breadcrumb float-sm-right">
						<li class="breadcrumb-item"><a href="#">Home</a></li>
						<li class="breadcrumb-item active">Starter Page</li>
					</ol>
				</div>
				<!-- /.col -->
			</div>
			<!-- /.row -->


			<div class="col-12">
				<!-- general form elements disabled -->
				<div class="card card-primary">
					<div class="card-header" style="padding-top: 0px;">
						<h3 class="card-title"></h3>
					</div>
					<!-- /.card-header -->
					<div class="card-body">
						<form role="form" action="/admin/member/update" method="post">
							<div class="row">
								<div class="col-sm-12">
									<!-- text input -->
									<div class="form-group">
										<h3>CREATE Member</h3>
										<label>user_id</label><br> ${memberVO.user_id}
										<input value="${memberVO.user_id}"
											name="user_id" type="hidden" class="form-control"
											placeholder="Enter user_id">
									</div>
								</div>
								<div class="col-sm-12">
									<div class="form-group">
										<label>user_pw</label> <input value=""
											name="user_pw" type="text" class="form-control"
											placeholder="${memberVO.user_pw}">
									</div>
								</div>
							</div>
							<div class="row">
								<div class="col-sm-12">
									<!-- textarea -->
									<div class="form-group">
										<label>user_name</label> <input value="${memberVO.user_name}"
											name="user_name" type="text" class="form-control"
											placeholder="Enter user_name">
									</div>
								</div>
								<div class="col-sm-12">
									<div class="form-group">
										<label>이메일</label> <input value="${memberVO.email}"
											name="email" type="text" class="form-control"
											placeholder="Enter email">
									</div>
									<div class="col-sm-12">
										<div class="form-group">
											<label>point</label> <input value="${memberVO.point}"
												name="point" type="text" class="form-control"
												placeholder="0">
										</div>
										<lable>enabled</lable>
										<div>
											<select name="enabled">
												<option value=''>-- 선택 --</option>
												<option value="0"
													<c:out value="${(memberVO.enabled eq 'false')?('selected'):('')}" />>
													false</option>
												<option value="1"
													<c:out value="${(memberVO.enabled eq 'true')?('selected'):('') }" />>
													true</option>
											</select>
										</div>
										<br>
										<lable>levels</lable>
										<div>
											<select name="levels">
												<option value=''>-- 선택 --</option>
												<option value="ROLE_USER"
													<c:out value="${memberVO.levels eq 'ROLE_USER'?'selected':''}" />>ROLE_USER</option>
												<option value="ROLE_ADMIN"
													<c:out value="${memberVO.levels eq 'ROLE_ADMIN'?'selected':''}" />>ROLE_ADMIN</option>
											</select>
										</div>
									</div>
									<hr>
									<br>
									<hr>
									<!-- //줄바꿈
             		// 수평선 -->
									<button type="submit" class="btn btn-warning">Submit</button>
									<a href="/admin/member/list?page=${pageVO.page}" class="btn btn-primary">List
										All</a>
								</div>
								<input type="hidden" name="page" value="${pageVO.page}">
								<!-- col -sm -12  -->
							</div>
							<!-- row  -->
					</div>
					<!-- card body -->
				</div>
				<!-- card card-primary -->
				</form>
			</div>
			<!-- col12  -->
		</div>
		<!--content-fluid  -->
	</div>
	<!-- Content Header (Page header) -->
</div>
<!-- Content Wrapper. Contains page content -->
<%@ include file="../include/footer.jsp"%>
