package com.example.demo.controller;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
@RestController
@Slf4j
@RequestMapping("/api")
@CrossOrigin(origins = {"http://127.0.0.1:3000","http://localhost:3000"})
public class OpenDataAPIController {

    @GetMapping(value="/open/food/{addr}",produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String,String> getFoodInfo(@PathVariable("addr") String addr) throws Exception{
        log.info("GET /openData/food/"+addr);

        //URL
        String url="https://www.daegufood.go.kr/kor/api/tasty.html?mode=json&addr="+addr;

        //HEADER(생략)
        //PARAMETER(생략)
        //ENTITY(HEADER+PARAMETER) (생략)

        //REQUEST
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET,null,String.class);
        System.out.println(response);
        System.out.println();
        System.out.println(response.getBody());

        // STRING -> JSON 변환
        ObjectMapper objectMapper = new ObjectMapper();
        JSONObject result = objectMapper.readValue(response.getBody(),JSONObject.class);
        System.out.println();
        System.out.println(result.get("data"));

        //System.out.println(result.get("data"));
        JSONParser parser = new JSONParser();
        JSONObject data_init = (JSONObject)parser.parse(response.getBody());
        JSONArray data = (JSONArray)data_init.get("data");

        Map<String,String> map = new HashMap();

        data.forEach(el->{
            JSONObject obj = (JSONObject)el;
            System.out.println(obj.get("BZ_NM")+" : " + obj.get("GNG_CS"));
            map.put(obj.get("BZ_NM").toString(),obj.get("GNG_CS").toString());
        });

        return map;
    }
    
    
    // 기상청 단기예보조회

    @GetMapping(value = "/weather/{nx}/{ny}/{basedate}/{basetime}",produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Item> weather(
            @PathVariable("nx")int nx,
            @PathVariable("ny")int ny,
            @PathVariable("basedate") String basedate,
            @PathVariable("basetime") String basetime
    )
    {
        log.info("/openData/weather.." + nx + " , " + ny+", " );

        String serviceKey="jXqTYgzxm73mgthwTg+MoIPShLI7R8npCFzwME5IPitFT/kGA9ViRLLcaAjFzR5ZY+XE0aA9H+DFQqvR3Slouw==";

        String url="http://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getUltraSrtNcst?";
        url += "serviceKey="+serviceKey;
        url += "&numOfRows="+100;
        url += "&pageNo="+1;
        url += "&dataType=json";
        url += "&base_date="+basedate;
        url += "&base_time="+basetime;
        url += "&nx="+nx;
        url += "&ny="+ny;
        //HEADER x
        //PARAM x
        //ENTITY x

        //REQUEST
        RestTemplate rt = new RestTemplate();
        ResponseEntity<WeatherResponse> response = rt.exchange(url, HttpMethod.GET,null,WeatherResponse.class);
        System.out.println(response.getBody());
        response.getBody().getResponse().getBody().getItems().getItem().forEach(item->{
            System.out.println(item);
        });

        return response.getBody().getResponse().getBody().getItems().getItem();

    }
    //------------------------
    @Data
    private static class Body{
        public String dataType;
        public Items items;
        public int pageNo;
        public int numOfRows;
        public int totalCount;
    }
    @Data
    private static class Header{
        public String resultCode;
        public String resultMsg;
    }
    @Data
    private static class Item{
        public String baseDate;
        public String baseTime;
        public String category;
        public int nx;
        public int ny;
        public String obsrValue;
    }
    @Data
    private static class Items{
        public ArrayList<Item> item;
    }
    @Data
    private static class Response{
        public Header header;
        public Body body;
    }
    @Data
    private static class WeatherResponse{
        public Response response;
    }



}
