package kr.or.test;

public class TryCatchFinally {
public static void main(String[] args) {
String[] strArray = {"10","2a"};
int value=0;
for(int cnt =0; cnt<=2; cnt++) {
	try {
		value=Integer.parseInt(strArray[cnt]);
	}catch(ArrayIndexOutOfBoundsException e) {
		System.out.println("배열의 인덱스를 초과했습니다");
	}catch(NumberFormatException e) {
		System.out.println("숫자로 변환할수 없음");
	}finally {
		System.out.println(value);
	}
}
	}
}

