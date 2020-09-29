package kr.or.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Calendar;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
/* 파싱 : xml,json 데이터를 웹페이지 형식으로 
 * 데이터를 조립해 원하는 데이터를 빼내는프로그램을 하는것  
 * token(어휘 분석의 단위) 으로 분해하고 그것들로 이루어진 Parse tree를 만드는 과정
 */

public class OpenApi {
	// 외부 연계 메서드
	public static void serviceApi() {
		BufferedReader br = null; // hrd 넷에서 전송받은 값을 요청하면 데이터를 일시 저장하는 저수지와 같은 역할
		String urlstr = 
		  "http://www.hrd.go.kr/jsp/HRDP/HRDPO00/HRDPOA60/HRDPOA60_1.jsp?"
		+"returnType=XML&authKey=cFIuo78T4uoczodc4oTg4Xvk3e7TxSRf&pageNum=1&pageSize=10&srchTraStDt=20200"
		+"501&srchTraEndDt=20201231&outType=1&sort=DESC&sortCol=TR_STT_DT&srchTraArea1=44";
		try {
			URL url = new URL(urlstr);
			HttpURLConnection urlconnection = (HttpURLConnection) url.openConnection();
			urlconnection.setRequestMethod("GET");
			br = new BufferedReader(new InputStreamReader(urlconnection.getInputStream(), "euc-kr"));
			String result = "";
			String line;
			while ((line = br.readLine()) != null) {
				result = result + line + "\n";
			}
			/* System.out.println(result); */
			String result_xmlUtils = XmlUtils.formatXml(result);
			System.out.println(result_xmlUtils);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// 콘솔 현재 시간 출력
		Calendar cal = Calendar.getInstance();
		System.out.println(cal.getTime());
	}

	public static void main(String[] args) {
		// 실행간격 지정 (10초)
		// 일괄처리 프로그램 batch
		int sleepSec = 10;
		// 주기적인 작업을 위한 코딩
		final ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1);
		exec.scheduleAtFixedRate(new Runnable(){
			// run 메서드 생성 
			public void run() {
			serviceApi();
			
			}//run
		},0,sleepSec,TimeUnit.SECONDS); //exec
		serviceApi(); // 메소드 호출
	}

}
