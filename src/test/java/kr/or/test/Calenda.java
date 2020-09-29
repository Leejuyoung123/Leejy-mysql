/*package kr.or.test;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

public class Calenda {
	SimpleDateFormat currentDate = new SimpleDateFormat("yyyyMMdd");
	Date date = new Date();

	// 해당 월의 마지막 날짜를 구하기 위함
	date = currentDate.parse(currentDate.format(date));

	Calendar cal = Calendar.getInstance();

	int startYear = Integer.parseInt(searchVO.getSearchSdate().substring(0,4));			// 시작년도
	int endYear = Integer.parseInt(searchVO.getSearchEdate().substring(0,4));			// 끝 년도

	int startMonth = Integer.parseInt(searchVO.getSearchSdate().substring(4,6));			// 시작 월
	int endMonth = Integer.parseInt(searchVO.getSearchEdate().substring(4,6));			// 끝 월

	int startDay = Integer.parseInt(searchVO.getSearchSdate().substring(6,8));			// 시작 일
	int endDay = Integer.parseInt(searchVO.getSearchEdate().substring(6,8));			// 끝 일


	// ~년 계산
	for(int y = startYear; y <= endYear; ++y){

	    int tempStartMonth;
	    int tempEndMonth;
	    
	    // 시작년도와 끝년도가 다를 경우 시작년도는 1월, 마지막 달을 12월로 잡도록 함
	    if(startYear != endYear) {
	        if(y == startYear) {
	            tempStartMonth = startMonth;
	            tempEndMonth = 12;
	        } else if(y == endYear) {
	            tempStartMonth = 1;
	            tempEndMonth = endMonth;	
	        } else {
	            tempStartMonth = 1;
	            tempEndMonth = 12;
	        }
	    } else {
	        tempStartMonth = startMonth;
	        tempEndMonth = endMonth;
	    }
	    
	    // 달 계산 
	    for(int m = tempStartMonth; m <= tempEndMonth; ++m) {
	        
	        cal.setTime(new Date(y, m+1, 1));
	        
	        int tempStartDay = 0;
	        int tempEndDay = 0;
	        
	        // 첫년도에의 첫 달은 검색한 일로 셋팅
	        if(startYear == endYear) {
	            if(endMonth == startMonth) {
	                tempStartDay = startDay;
	                tempEndDay = endDay;
	            } else if(startMonth != endMonth) {
	                if(m == tempStartMonth) {
	                    tempStartDay = startDay;
	                    tempEndDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
	                } else if(m == tempEndMonth) {
	                    tempStartDay = 1;
	                    tempEndDay = endDay;
	                } else {
	                    tempStartDay = 1;
	                    tempEndDay = 1;
	                }
	            }
	        } else {
	            if(y == startYear) {
	                tempStartDay = startDay;
	                tempEndDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
	            } else if(y != endYear) {
	                tempStartDay = 1;
	                tempEndDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
	            } else if(y == endYear) {
	                if(m == endMonth) {
	                    tempStartDay = 1;
	                    tempEndDay = endDay;	
	                } else {
	                    tempStartDay = 1;
	                    tempEndDay = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
	                }
	            }	
	        }
	        
	        
	        String inputMonth;

	        if(m < 10)
	            inputMonth = "0"+m;
	        else 
	            inputMonth = String.valueOf(m);
	        
	        // 일 계산
	        for(int i=tempStartDay; i<=tempEndDay; ++i){
	            
	            String day = y+"-"+inputMonth+"-";
	            
	            if(i<10) {
	                day += "0"+i;
	            } else {
	                day += i;
	            }
	        }
	    }
	}}}
*/