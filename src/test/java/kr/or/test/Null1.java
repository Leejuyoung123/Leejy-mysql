package kr.or.test;

public class Null1 {
public static void main(String[] args) {
	// int [] intarray=null;  참조하는 객체가 없으면 null point exception 
	// 오류가 나옴 intarray는 배열 객체가 없기떄문
	   
	int [] intarray= {10,20,30};
	   
	System.out.println(intarray[0]);
}
}
