package com.example.demo.controller;


import com.example.demo.domain.dto.MemoDto;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.io.FileNotFoundException;
import java.util.LinkedHashMap;
import java.util.Map;

/*
    REACT - SPRINGBOOT PARAMETER 확인하기
 */
@RestController
@Slf4j
@RequestMapping(value = "/memo")
@CrossOrigin(origins = {"http://127.0.0.1:3000","http://localhost:3000"})
public class MemoController {

    @ExceptionHandler(FileNotFoundException.class)
	public ResponseEntity<Exception> error1(Exception ex) {
		System.out.println("memoExceptionHandler FileNotFoundException... ex " + ex);
		return new ResponseEntity<>(ex,HttpStatus.EXPECTATION_FAILED);
	}
	@ExceptionHandler(ArithmeticException.class)
	public  ResponseEntity<Exception>  error2(Exception ex) {
		System.out.println("memoExceptionHandler ArithmeticException... ex " + ex);
        return new ResponseEntity<>(ex,HttpStatus.EXPECTATION_FAILED);
	}
	@ExceptionHandler(Exception.class)
	public  ResponseEntity<Exception>  error3(Exception ex) {
		System.out.println("memoExceptionHandler Exception... ex " + ex);
        return new ResponseEntity<>(ex,HttpStatus.EXPECTATION_FAILED);
	}


    @PostMapping(value = "/post",consumes = MediaType.APPLICATION_JSON_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>>  post(@RequestBody @Valid MemoDto dto, BindingResult bindingResult) {
        Map<String,Object> map = new LinkedHashMap<>();
        log.info("POST /memo/post... "+dto);
//        log.info("POST /memo/post... isError "+bindingResult.getFieldError("id"));
        if(bindingResult.hasFieldErrors()) {
//			log.info("POST /memo/post... isError "+bindingResult.getFieldError("id").getDefaultMessage());
            for( FieldError error  : bindingResult.getFieldErrors()) {
                log.info(error.getField()+ " : " + error.getDefaultMessage());
                map.put(error.getField(), error.getDefaultMessage());
            }
            return new ResponseEntity<>(map, HttpStatus.EXPECTATION_FAILED);
        }
        map.put("Post /memo/post","success");
        return new ResponseEntity<>(map, HttpStatus.OK);

    }

    //    예외발생 함수
    @GetMapping("/list1")
    public void list1() throws Exception{
        System.out.println("GET /memo/list1");
        throw new FileNotFoundException("파일이 없다..");
    }

    @GetMapping("/list2")
    public void list2() throws Exception{
        System.out.println("GET /memo/list2");
        throw new ArithmeticException("계산똑바로해..");

    }

    @GetMapping("/list3/{n1}/{n2}")
    public void list3(@PathVariable int n1, @PathVariable int n2) {
        System.out.println("GET /memo/list3");
        System.out.println("계산결과 : " + (n1/n2));

    }
    @GetMapping("/list4")
    public void list4() {
        System.out.println("GET /memo/list4");
        throw new NullPointerException();
    }

}
