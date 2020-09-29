$(document).ready(function($) {
	//alert('jquery잘 되나?');
	$(".menu-toggle-btn").click(function() {
		$(".gnb").stop().slideToggle("fast");
	})
})