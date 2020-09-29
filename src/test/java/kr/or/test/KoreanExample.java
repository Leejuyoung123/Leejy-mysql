package kr.or.test;

 class Korean {

	String nation = " 대한민국";
	String name;
	String ssn;
	public Korean(String n, String s){
		this.name =n;
		this.name =s;
	}
}


public class KoreanExample {
public static void main(String[] args) {
	Korean k1= new Korean ("박자바","010010");
	System.out.println(k1.name);
	System.out.println(k1.ssn);
}
}
