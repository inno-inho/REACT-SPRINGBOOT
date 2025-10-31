package com.example.app.domain.dto;

import jakarta.validation.constraints.*;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemoDto {
    @Min(value=10,message = "최소 숫자는 10이상 이어야합니다.")
    @Max(value=65535,message = "최대 숫자는 65535이하 이어야합니다.")
    @NotNull(message="ID를 입력하세요")
    private Integer id;			//메모ID
    @NotBlank(message="메모를 입력하세요")
    private String text;	//메모내용

    @NotBlank(message="작성자를 입력하세요")
    @Email(message="example@example.com에 맞게 입력해주세요")
    private String writer;	//작성자
    @DateTimeFormat(pattern="yyyy-MM-dd'T'HH:mm")
    @NotNull(message="날짜정보를 선택해주세요")
    private LocalDateTime regdate;


}