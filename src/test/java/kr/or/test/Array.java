package kr.or.test;

public class Array {
	// 값의 리스트 배열생성
	private int speed;
	
	 public int getSpeed() {
		return speed;
	}

	public void setSpeed(int speed) {
		this.speed = speed;
	}

	public static int add(int[] scores) { 
		 int sum1=0;
		 for(int i=0; i<3; i++) {
			 sum1 = sum1+scores[i];
		 }//for
		 return sum1;
	  }//add

	public static void main(String[] args) {
	// 값 의 목록으로 배열생성
	int [] array = {83 , 90 , 87 };
	int array2 [] = { 50 , 40 ,30};
	String [] names = { "신용권" , "홍길동" , "감자바" };
	System.out.println(names[2]);
	System.out.println(array[0] );
	System.out.println(array2[0]);
	names[2]="홍삼원";
	System.out.println(names[2]);
	
	// 값 목록으로 배열 생성할시 주의점 
	/*	  int lisk [];
	 *	  lisk = {  15 ,30 ,45}; 
	 * 배열변수 이미 선언후 { 중괄호를 사용한 선언은 허용x}
	 *	
	 * 배열 변수를 미리 선언후 값 목록이 나중에 결정되는 상황이면 
	 * new 연산자를 사용해 값목록 지정 
	 * 							
	  int lisk []; 
	  	  lisk = new int [] {}; 
	  	  //{ 15, 30 ,45} 중괄호에는 값을 나중에 지정해주면됨
	  System.out.println( lisk[2]);	  
*/	  
	 // 값의 리스트 배열생성
	 int [] scores;
	 scores = new int[] {20,40,60};
	 int sum1= 0;
	 for (int i=0; i<3; i++) {
		 sum1 = sum1+scores[i];
	 } //for
	 System.out.println(sum1);
	}//main
}// class
