package kr.or.test;

import java.util.ArrayList;
import java.util.List;

/*import java.util.Scanner;
class Tire {
	public void run(){
		System.out.println("일반 타이어가 굴러갑니다.");
	}
}
class SnowTire extends Tire{
	@Override
	public void run () {
		System.out.println(" 스노우 타이어가 굴러갑니다");
	}
}
*/

/* 클래스 선언시 *
 * public class hello << 동일한 클래스를 생성 해야만 접근제한자를 붙일수 있다. 
 * 소스파일 하나당 동일한 이름의 클래스 하나 선언*/  
public class HelloWorld {

	public static void main(String[] args) {
		//https://tmxhsk99.tistory.com/70
		// (page:jsp클릭변수 - 1) * 10 perPageNum:페이지당 보여줄 개수;
		int startBno = (1-1) * 10; // 1페이지
		System.out.println("쿼리변수 (page:1page - 1) * 10 perPageNum:"+ startBno);
		startBno = (2-1) * 10; // 2페이지
		System.out.println("쿼리변수 (page:2page - 1) * 10 perPageNum:"+ startBno);
		startBno = (3-1) * 10; // 3페이지
		System.out.println("쿼리변수 (page:3page - 1) * 10 perPageNum:"+ startBno);
		// 천장함수 사용법 1페이지 , 2페이지 ,3,페이지
		int endpage= (int)(Math.ceil(1/10.0)*10);
		System.out.println("Math.ceil(1/10.0)*10 :" + endpage);
		endpage= (int)(Math.ceil(2/10.0)*10);
		System.out.println("Math.ceil(2/10.0)*10 :" + endpage);
		endpage= (int)(Math.ceil(3/10.0)*10);
		System.out.println("Math.ceil(3/10.0)*10 :" + endpage);
		List<String> files = new ArrayList<>();
		files.add("sample1.jpg");
		files.add("sample2.jpg");
		files.add("sample3.jpg");
		String[] filenames =new String[files.size()];
		int cnt=0;
		for (String fileName:files) {
			filenames[cnt++] = fileName;
		}
		System.out.println(filenames[0] + filenames[1] + filenames[2]);
		/*SnowTire snowTire =new SnowTire();
			Tire tire = snowTire;
			
			snowTire.run();
			tire.run();
			
		
		 * int score=85; String result = (!(score>90))? "가":"나"; // score가 90보다 크면 가 /
		 * 90보다 작으면 나 if (!(score>90)) { result="가"; }else{ result="나"; }
		 * System.out.println(result); int x = 10; int y = 5;
		 * System.out.println((x>7)&&(y<=5)); System.out.println((x<7)&&(y<=5));
		 * System.out.println((x<7)||(y<=5));
		 * 
		 * int hap = 0; for (int i = 1; i <= 100; i++) { hap += i; }
		 * System.out.println("1부터 100까지의 합은 " + hap + "입니다"); int cnt=1; int hop=0;
		 * while(cnt <=100) { hop = hop+cnt; cnt = cnt+1; } System.out.println(hop);
		 * 
		 * boolean run = true; int balance = 0; Scanner scanner = new
		 * Scanner(System.in);
		 * 
		 * while (run) { System.out.println("-------------------------");
		 * System.out.println(" 1.입금 |2.출금 |3.잔고 |4.종료");
		 * System.out.println("-------------------------");
		 * System.out.println("↑위 번호를 입력 해주세요>:"); int menuNum = scanner.nextInt();
		 * switch (menuNum) { case 1: System.out.println("입금액을 입력하세요>:"); balance +=
		 * scanner.nextInt(); break; case 2: System.out.println("출금액>:"); balance -=
		 * scanner.nextInt(); break; case 3: System.out.print("잔고>:");
		 * System.out.println(balance); break; case 4: run=false; break; default :
		 * System.out.println(" 해당 사항 없음 "); break; } System.out.println("종료"); }
		 
		String name = "123";
		char var3 = 'a';
		int num_name = Integer.parseInt(name);
		System.out.println(num_name*2);
			*/
		/*int score = 85;
	 	result = (!(score>90))?"가":"나";
		if (!score > 90) {
			result="가"; 
		}else {
			result="나";
		}
		System.out.println(result);
		
		int x= 10;
		int y= 5;
		System.out.println((x>7)&&(y<=5));
		System.out.println((x<7)&&(y<=5));
		System.out.println((x<7)||(y<=5));
		System.out.println((x>7)||(y==5));*/
		/*int cnt =1;
		int sum=0;
		while(cnt <=100) {
		sum += cnt;
		cnt = cnt +1;
		int sum=0;
		for(int cnt=1; cnt<=100; cnt++) {
			sum += cnt;
		}
		System.out.println(sum);*/
	}
}