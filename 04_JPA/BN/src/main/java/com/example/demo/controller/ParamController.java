package com.example.demo.controller;


import com.example.demo.domain.dto.Person;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.LinkedHashMap;
import java.util.Map;

//https://velog.io/@ghwns9991/%EC%8A%A4%ED%94%84%EB%A7%81-%EB%B6%80%ED%8A%B8-3.2-%EB%A7%A4%EA%B0%9C%EB%B3%80%EC%88%98-%EC%9D%B4%EB%A6%84-%EC%9D%B8%EC%8B%9D-%EB%AC%B8%EC%A0%9C

@RestController
@Slf4j
@RequestMapping(value = "/test")
@CrossOrigin(origins = {"http://127.0.0.1:3000","http://localhost:3000"})
public class ParamController {

	@RequestMapping(value="/param" ,method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE )
	public ResponseEntity<Map<String,Object>> paramTest_01(@RequestParam(required = true,value="name") String name) {
		Map<String,Object> map = new LinkedHashMap<>();
		log.info("GET /test/param.." + name);
		map.put("GET /test/param.","success");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	@GetMapping(value = "/param/{name}/{age}/{addr}", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String,Object>> paramTest_02(Person person) {
		Map<String,Object> map = new LinkedHashMap<>();
		log.info("GET /param/{name}/{age}/{addr}.." + person);
		map.put("/param/{name}/{age}/{addr}","success");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	@PostMapping(value = "/param", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String,Object>> paramTest_03(@RequestBody Person person) {
		Map<String,Object> map = new LinkedHashMap<>();
		log.info("POST /param/.." + person);
		map.put("POST /param/..","success");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}

}


