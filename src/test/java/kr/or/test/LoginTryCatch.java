package kr.or.test;

import java.net.PasswordAuthentication;

class NotExistIDException extends Exception {
	// 아이디가 존재하지 않을떄 예외사항 처리 내용
	public NotExistIDException() {
	}

	public NotExistIDException(String message) {
		super(message);
	}

}

class WrongPasswordException extends Exception {
	// 잘못된 패스워드를 입력 했을때 예외사항 처리 내용
	public WrongPasswordException() {
	}

	public WrongPasswordException(String message) {
		super(message);
	}
}

public class LoginTryCatch {
	public LoginTryCatch() {
	}

	public static void main(String[] args) {
		try {
			login("white", "12345"); //로그인1
		} catch (NotExistIDException e1) {
			e1.printStackTrace();
		} catch (WrongPasswordException e1) {
			e1.printStackTrace();
		}

		try {
			login("blue", "54321"); //로그인2
		} catch (NotExistIDException e) {
			e.printStackTrace();
		} catch (WrongPasswordException e) {
			e.printStackTrace();
		}
	}

	public static void login(String id, String password) throws NotExistIDException, WrongPasswordException {
		// id가 "blue"가 아니라면 NotExistIDException 발생시킴
		if (!id.equals("blue")) {
			//강제 오류예외 발생 -NotExistIDException
			throw new NotExistIDException("아이디가 존재하지 않습니다.");
		}

		if (!password.equals("12345")) {
			//강제 오류예외 발생 -WrongPasswordException
			throw new WrongPasswordException("패스워드가 일치하지 않습니다.");
		}
	}
}