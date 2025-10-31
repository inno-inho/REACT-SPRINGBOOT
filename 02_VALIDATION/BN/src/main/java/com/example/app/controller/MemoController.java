package com.example.app.controller;


import com.example.app.domain.dto.MemoDto;
import com.example.app.domain.dto.PersonDto;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/memo")
@CrossOrigin(origins={"http://localhost:3000","http://127.0.0.1:3000"})
public class MemoController {

    @PostMapping(value="/add",consumes = MediaType.APPLICATION_JSON_VALUE,produces= MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String,Object>> add(@RequestBody @Valid MemoDto memoDto, BindingResult bindingResult){
        Map<String,Object> map = new LinkedHashMap<>();
        log.info("GET /memo/add..."+ memoDto);

        if(bindingResult.hasErrors()) {
//			log.info("데이터 유효성 체크 오류 : " + bindingResult.getFieldError("id").getDefaultMessage()  );
//			model.addAttribute("id",bindingResult.getFieldError("id").getDefaultMessage());
            for(FieldError error : bindingResult.getFieldErrors()) {
                log.info("Error Field : "+error.getField()+" Error Msg : "+error.getDefaultMessage());
                map.put(error.getField(),error.getDefaultMessage());
            }
            return new ResponseEntity<>(map, HttpStatus.EXPECTATION_FAILED);
        }

        return new ResponseEntity<>(map,HttpStatus.OK);
    }
}
