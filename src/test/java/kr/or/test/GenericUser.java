package kr.or.test;

import java.util.HashMap;
import java.util.Map;

// 제네릭 타입 클래스 생성
class Container<T> {
	private T t;

	public void set(T t) {
		this.t = t;
	}

	public T get() {
		return t;
	}
}

class ContainerKV<K,V>{
	private K key;
	private V value;
public void set (K key , V value) {
	this.key=key;
	this.value=value;
}
public K getKey() {
	return key;
}
public V getvaue() {
	return value;
	
	}
}
public class GenericUser {

	public static void main(String[] args) {
		ContainerKV <String,String> container3 = new ContainerKV <String,String>();
		container3.set("name","홍길동");
		String namekey = container3.getKey();
		String namevalue = container3.getvaue();
		System.out.println("입력된 이름키:"+ namekey + "입력된 value키:"+namevalue);
		
		Map<String, String> tableKV = new HashMap<String, String>();
		tableKV.put("userid", "user01"); // type , value 
		tableKV.put("userpw", "1234"); 
		System.out.println(" 아이디는 "+tableKV.get("userid")+ "입니다");
		System.out.println(" 암호는 "+tableKV.get("userpw")+ "입니다");
		
		/*Container<String> container1 = new Container<String>();
		// 컨테이너1변수t: String 홍길동
		container1.set("홍길동");
		String srt = container1.get();
		System.out.println(srt);

		Container<Integer> container2 = new Container<Integer>();
		// 컨테이너2변수t: Integer 변수에는 6
		container2.set(6);
		int value = container2.get();
		System.out.println(value);*/
	}
}
