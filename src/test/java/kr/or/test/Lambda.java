package kr.or.test;

import java.util.function.IntSupplier;

public class Lambda {
	public static int method(int x, int y) {
		//람다식 메서드
		IntSupplier supplier = () -> {
			int result = x + y;
			return result;
		};
		//기존 메서드
		/*
		 IntSupplier supplier2 = new IntSupplier() {
			@Override
			public int getAsInt() {
				int result = x + y;
				return result;
			}
		};
		*/
		int result = supplier.getAsInt();
		return result;
	}
	public static void main(String[] args) {
		System.out.println(method(3,5));

	}

}