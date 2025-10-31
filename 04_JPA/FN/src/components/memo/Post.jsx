import React, { useState } from "react";
import axios from "axios";

const Post = () => {
    const [id , setId] = useState();
    const [writer , setWriter] = useState();
    const [text , setText] = useState();
    const [regdate, setRegDate] = useState();
    const [message,setMessage] = useState({});
  
    const postHandler = (e) => {
      
      axios
      .post(
        `http://localhost:8080/memo/post`,                          //URL
        {"id":id,"text":text,"writer":writer,"regdate":regdate},    //PARAM
        {headers: {'Content-Type': 'application/json'}}             //CONTENT_TYPE
      )
      .then(response => {
        console.log(response.data);
      })
      .catch(error => {
        console.error('error.response.data', error.response.data);
        setMessage(error.response.data)
      });
        
    };
  return (
    <div>
      <div>
        <h2>메모 POST</h2>
      </div>
      <div>
        <label htmlFor="">ID : </label> <span className="id">{message.id}</span><br/>
        <input name="id" type="text" onChange={(e)=>{setId(e.target.value)}}/>
      </div>
      <div>
        <label htmlFor="">WRITER : </label> <span className="id">{message.writer}</span><br/>
        <input name="writer" type="text" onChange={(e)=>{setWriter(e.target.value)}}/>
      </div>
      <div>
        <label htmlFor="">TEXT : </label> <span className="id">{message.text}</span><br/>
        <textarea name="" onChange={(e)=>{setText(e.target.value)}}></textarea>
      </div>
      <div>
      <label htmlFor="">REGDATE : </label> <span className="id">{message.regdate}</span><br/>
        <input type="datetime-local" onChange={(e)=>{setRegDate(e.target.value)}} />
      </div>
      <div>
        <button onClick={postHandler}>전송</button>
      </div>
    </div>
  );
};

export default Post;
