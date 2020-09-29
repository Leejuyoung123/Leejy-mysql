package kr.or.test;

import java.util.function.ToIntFunction;

class Student {
	private String name;
	private int englishScore;
	private int mathScore;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getEnglishScore() {
		return englishScore;
	}
	public void setEnglishScore(int englishScore) {
		this.englishScore = englishScore;
	}
	public int getMathScore() {
		return mathScore;
	}
	public void setMathScore(int mathScore) {
		this.mathScore = mathScore;
	}
	public Student(String name, int eng, int math) {
		this.name = name;
		this.englishScore = eng;
		this.mathScore = math;
	}
}

public class LambdaAvg {
	private static Student[] students = {
			new Student("홍길동", 90, 96),
			new Student("신용권", 95, 93)
	};
	public static double avg(ToIntFunction<Student> function) {
		int sum = 0;
		for(Student student:students) {
			System.out.println("더하는 점수:" + function.applyAsInt(student));
			sum = sum + function.applyAsInt(student);
		}
		double avg = (double) sum / students.length;
		return avg;
	}
	public static void main(String[] args) {
		double englishAvg = avg(s->s.getEnglishScore());
		System.out.println("영어평균점수: " + englishAvg);
		double mathAvg = avg(s->s.getMathScore());
		System.out.println("수학평균점수: " + mathAvg);
	}

}