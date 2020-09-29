package kr.or.test;

import java.util.StringTokenizer;

public class Split {
	public static void main(String[] args) {
		String str = "아이디,이름,패스워드";
		// 방법1 split () 메서드 사용

		System.out.println("split을 사용한 문자열 분리");
		String[] tokens = str.split(",");
		int cnt = 0;
		for (String token : tokens) {
			System.out.println(cnt++ + token);
		}
		System.out.println();
		// tokenizer 방법2
		System.out.println("String Tokenizer를 사용한 문자열 분리");
		StringTokenizer st = new StringTokenizer(str, ",");
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			System.out.println(token);
		}
	}
}
