
import React, { useState } from 'react';
import axios from 'axios';

const Param = () => {

  const requestHandler1 = ()=>{
    axios
      .get('http://localhost:8080/test/param', { params: { name: "홍길동" } })
      .then(response => {
        console.log(response.data);
      })
      .catch(error => {
        console.error('error', error);
      });

  }
  const requestHandler2 = ()=>{
    axios
    .get(`http://localhost:8080/test/param/${'홍길동'}/${55}/${'울산'}`)
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error('error', error);
    });
  }
  const requestHandler3 = ()=>{
    axios
    .post(
        `http://localhost:8080/test/param`,                 //URL
        {"name":"홍길동","age":55,"addr":"울산"},            //PARAM
        {headers: {'Content-Type': 'application/json'}}     //CONTENT_TYPE

      )
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error('error', error);
    });
  }

  return (
    <div className="wrapper">
      <main>

        <div>
          <button onClick={requestHandler1}>GET /test/param?name=value</button>
        </div>
        <hr />
        <div>
          <button onClick={requestHandler2}>GET /test/param/이름/나이/주소</button>
        </div>
        <hr />
        <div>
          <button onClick={requestHandler3}>POST /test/param</button>
        </div>


      </main>
    </div>
  );
};

export default Param;
