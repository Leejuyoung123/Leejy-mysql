package kr.or.test;

class MovieThread extends Thread {
	@Override
	public void run() {
		for (int cnt = 0; cnt < 3; cnt++) {
			System.out.println("동영상을 재생합니다");
		} // for

		while (true) {
			System.out.println("동영상을 무한 재생합니다");
			/*
			 * try { Thread.sleep(1); } catch (InterruptedException e) { break; }
			 */
			// 스레드 -실행중인 클래스가 main()에서 interrupt()가 호출되었을떄

			if (Thread.interrupted()) { // 인터럽트 시킨 이벤트 처리 interrupted 
				System.out.println("인터럽트가 발생 되었습니다 반복문을 종료합니다");
				break;
				// while문 빠져나가기

			} // if
		} // while
	}// run
}// class

class MusicRunnable implements Runnable {
	@Override
	public void run() {
		for (int cnt = 0; cnt < 3; cnt++) {
			System.out.println("음악을 재생합니다");
		} // for
	}// run
}// class

public class Threadc {

	public static void main(String[] args) {
		Thread threadMovie = new MovieThread(); // 초기값을 무비스레드에서 가졍모
		threadMovie.setDaemon(true); 
		//백그라운드로 실행설정
		threadMovie.start();
		//main() 스레드에서 1초후 threadMovie를 종료하는코드
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
			System.out.println(e.toString());
		}

		threadMovie.interrupt(); //무비스레드를 중지하겟다는 메서드 실행
		Thread threadMusic = new Thread(new MusicRunnable());
		threadMusic.start();
	}
}
