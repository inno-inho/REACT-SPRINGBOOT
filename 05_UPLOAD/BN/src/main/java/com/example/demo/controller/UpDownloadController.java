package com.example.demo.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = {"http://127.0.0.1:3000","http://localhost:3000"})
@RestController
@Slf4j
public class UpDownloadController {

    @Value("${root.path}")
    private String Root;

    @Value("${upload.path}")
    private String Upload;

    @PostMapping(value="/upload",consumes = MediaType.MULTIPART_FORM_DATA_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
    public void upload(@RequestParam("files") MultipartFile[] files) throws IOException {
        log.info("POST /upload... file : "+files);
        String uploadPath = Root+ File.separator+Upload+File.separator;
        File dir = new File(uploadPath);
        if(!dir.exists())
            dir.mkdirs();
        for(MultipartFile file : files){
            File fileObj = new File(dir,file.getOriginalFilename());
            file.transferTo(fileObj);   //파일업로드
        }

    }

    //ERROR  - consume Type 지정하지 않는다
    @GetMapping(value="/download",produces=MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<Resource>  download(@RequestParam("filePath") String filePath) throws UnsupportedEncodingException {
        log.info("POST /download...file : " + filePath);
        //FileSystemResource : 파일시스템의 특정 파일로부터 정보를 가져오는데 사용
        Resource resource = new FileSystemResource(filePath);
        //파일명 추출
        String filename = resource.getFilename();
        //헤더 정보 추가
        HttpHeaders headers = new HttpHeaders();
        //ISO-8859-1 : 라틴어(특수문자등 깨짐 방지)
        headers.add("Content-Disposition","attachment; filename="+new String(filename.getBytes("UTF-8"),"ISO-8859-1"));
        //리소스,파일정보가 포함된 헤더,상태정보를 전달
        return new ResponseEntity<Resource>(resource,headers,HttpStatus.OK);
    }


    @GetMapping("/upload/list")
    public ResponseEntity<List<String>> filelist(){
        log.info("GET /upload/list...");
        String uploadPath = Root+ File.separator+Upload+File.separator;
        File dir = new File(uploadPath);
        File[] fileList = dir.listFiles();
        for(File file : fileList)
            log.info(file.getName());

        if(fileList.length!=0) {
            List list = Arrays  .stream(fileList)
                                .map(el-> uploadPath + File.separator +  el.getName())
                                .collect(Collectors.toList());
            return new ResponseEntity(list, HttpStatus.OK);
        }
        return new ResponseEntity(null,HttpStatus.EXPECTATION_FAILED);
    }
}
