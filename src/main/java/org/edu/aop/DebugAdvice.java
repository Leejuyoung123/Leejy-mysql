package org.edu.aop;

import java.util.Arrays;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
@Component
@Aspect
public class DebugAdvice {
	private static final Logger logger = LoggerFactory.getLogger(DebugAdvice.class);
	/*
	 * ...481p.@Around는 메서드 실행에 직접 관여함.
	 * ...Around타입의 기능은 파라미터로 ProceedingJoinPoint 타입을 사용함.
	 * ...ProceedingJoinPoint는 JoinPoint의 모든 메서드를 가지면서도, 직접 target객체의
	 * ...메서드를 실행할 수 있는 기능이 추가됨.
	 * ...ProceedingJoinPoint.proceed()는 특이하게도 Exception보다 상위의 Throwable을 처리하므로
	 * ...메서드의 선언에 Throwable을 사용하고 있고, 시간을 체크하는 기능을 작성할 수 있음.
	 * ...@Around를 이용하는 경우 반드시 메서드의 리턴타입은 Object로 선언해야 함.
	 * ...@Around는 메서드를 직접 호출하고, 결과를 반환해야만 정상적인 처리가 됨. 
	 *  aop DI IOC 관련 설명 자세히 https://addio3305.tistory.com/86
	 */	
	//@Around("execution(* org.edu.service.MemberService*.*(..))")//...495p.주석.트랜잭션.
	@Around("execution(* org.edu.controller.AdminController.*(..))")
	public Object timeLog(ProceedingJoinPoint pjp)throws Throwable{
		
		logger.debug("S.debug.=============================================");
	  long startTime = System.currentTimeMillis();
	  logger.debug(Arrays.toString(pjp.getArgs()));
	  
	  Object result = pjp.proceed();
	  
	  long endTime = System.currentTimeMillis();
	  logger.debug( pjp.getSignature().getName()+ " : " + (endTime - startTime) );
	  logger.debug("E.debugLog.=============================================");
	  
	  return result;
	}   
}
