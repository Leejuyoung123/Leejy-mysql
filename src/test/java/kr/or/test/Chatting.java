package kr.or.test;

public class Chatting {
	
	public static void main(String[] args) {
		Chatting ct = new Chatting();
		ct.startChat("user2");
	}
	    void startChat(String chatId) {
		final String nickName = chatId;
		Chat chat = new Chat() {
			@Override
			public void start() {
				while (true) {
					String inputData = "채팅방 입장을 환영합니다";
					String message = "[" + nickName + "]" + inputData;
					sendMessage(message);
					break;
				} // end while
			} // end start
		}; // end chat
		chat.start();
	}// end startChat

	class Chat {
	void start() {}
	void sendMessage(String message) {
		 System.out.println(message);
		}
	}
}