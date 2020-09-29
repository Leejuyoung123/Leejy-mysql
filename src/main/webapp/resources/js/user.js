function myFunction() {
			//alert(documnet.getElementbyId("exam").innerHtml);  //디버그
			if (document.getElementById("exam").innerHTML == "변경전")
				document.getElementById("exam").innerHTML = "변경 후"
			else
				document.getElementById("exam").innerHTML = "변경전"
		}