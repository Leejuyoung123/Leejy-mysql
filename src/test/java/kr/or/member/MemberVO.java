package kr.or.member;

public class MemberVO {
	private String name;
	private int age;
	private String phoneNum; 
	@Override   // 오버라이드 메서드 재정의 
	public String toString() {
		return "MemberVO클래스 [이름은=" + name + ", 나이는=" + age + ", 전화번호는=" + phoneNum + "]";
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getAge() {
		return age;
	}
	public void setAge(int age) {
		this.age = age;
	}
	public String getPhoneNum() {
		return phoneNum;
	}
	public void setPhoneNum(String phoneNum) {
		this.phoneNum = phoneNum;
	}
}

