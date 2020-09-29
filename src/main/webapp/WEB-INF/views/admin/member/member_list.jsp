<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<!-- ../ 밖경로 list.jsp= member 폴더에 위치해 있기떄문에 
							include 경로 밖 			-->
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ include file="../include/header.jsp"%>

<!-- Content Wrapper. Contains page content -->
<div class="content-wrapper">
	<div class="box3">
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
				<!-- /.row mb-2 -->
			</div>
			<!-- container -->
		</div>
		<!-- content-header -->
		<div class="col-12">
			<div class="card card-secondary">
				<div class="card-header" style="padding-top: 0px;">
					<h3 class="card-title"></h3>
				</div>
				<!-- /.card-header -->
				<div class="card">
					<div class="card-body">

							<div class="row">
								<div class="col-sm-12">
									<!-- text input -->
									
									<div class="form-group">
										<h1 class="m-0 text-dark">멤버검색</h1>
										<br>
										<hr>
										<form action="/admin/member/list">
										<div>
												<select name="searchType">
													<option value='all'>전체</option>
												</select> 
												<input type="text" name="searchKeyword"> <input type="button" value="검색">
										</div>
										</form>
										<!-- select  -->
									</div>
									<!-- form-group -->
									
								</div>
								<!-- col -->
							</div>
							<!-- row -->

					</div>
					<!-- card body -->
				</div>
				<!-- card -->
			</div>
			<!-- card card-secondary -->
		</div>
		<!-- col-12 -->

		<div class="col-12">
			<div class="card card-secondary">
				<div class="card-header" style="padding-top: 0px;">
					<h3 class="card-title"></h3>
				</div>
				<!-- /.card-header -->
				<div class="card">
					<div class="card-body">
						<form role="form">
							<div class="row">
								<div class="col-sm-12">
									<!-- text input -->
									<div class="form-group">
										<h1 class="m-0 text-dark">LIST ALL PAGE</h1>
										<br>
										<table class="table table-hover text-nowrap">
											<thead>
												<tr>
													<th>ID</th>
													<th>User_name[point]</th>
													<th>email</th>
													<th>Use</th>
													<th>REGDATE</th>
													<th>level</th>
												</tr>
											</thead>
											<tbody>
												<c:forEach items="${memberList}" var="memberVO"
													varStatus="status">
													<tr>
														<td>${memberVO.user_id}</td>
														<td><a href="/admin/member/view?user_id=${memberVO.user_id}&page=${pageVO.page}">${memberVO.user_name}[${memberVO.point}]</a></td>
														<td>${memberVO.email}</td>
														<td>${memberVO.enabled}</td>
														<td><span class="tag tag-success"><fmt:formatDate pattern="yyyy-MM-dd HH:mm" value="${memberVO.reg_date}"/></span></td>
														<td class="right badge badge-danger">${memberVO.levels}</td>
													</tr>
												</c:forEach>
											</tbody>
										</table>
									</div>
									<!-- form group  -->
								</div>
								<!-- col sm- 12 -->
							</div>
						</form>
						<!-- form -->
					</div>
					<!-- card body -->
				</div>
				<!-- card -->
			</div>
			<!-- card card-secondary -->
		
			<div>
				<a href="/admin/member/write" class="btn btn-primary">CREATE</a>
			</div>
			<!-- 페이징 처리 로직  start -->
			<nav aria-label="Page navigation example">
				<ul class="pagination">

					<c:if test="${pageVO.prev}">
						<li class="page-item"><a class="page-link"
							href="/admin/member/list?page=${pageVO.startPage -1}&searchType=${pageVO.searchType}&searchKeyword=${pageVO.searchKeyword}">이전</a></li>
					</c:if>
					
					<c:forEach begin="${pageVO.startPage}" end="${pageVO.endPage}"
						var="idx">
						<li
							class='page-item <c:out value="${idx == pageVO.page?'active':''}"/>'>
							<a class="page-link"
							href='/admin/member/list?page=${idx}&searchType=${pageVO.searchType}&searchKeyword=${pageVO.searchKeyword}'>${idx}</a>
					</c:forEach>

					<c:if test="${pageVO.next}">
						<li class="page-item"><a class="page-link"
							href="/admin/member/list?page=${pageVO.endPage +1}&searchType=${pageVO.searchType}&searchKeyword=${pageVO.searchKeyword}">다음</a></li>
					</c:if>
					
				</ul>
			</nav>
			<!-- 페이징 처리 로직  END -->
		</div>
		<!-- col-12 -->
	</div>
	<!-- box -->
</div>
<!-- /.content-header -->

<!-- Main content -->
<div class="content"></div>
<!-- /.content -->
<%@include file="../include/footer.jsp"%>