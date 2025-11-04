import axios from "axios";
import {useState} from "react";
import { useNavigate } from 'react-router-dom';

//스프링 서버로 요청
const KakaoLogin = ()=>{
    const [message,setMessage] = useState();

    const KakaoLogin = ()=>{
        try{
            const reqFunc = async ()=>{
                const response = await axios.get(`http://localhost:8080/kakao/getCode`)
                console.log(response.data);
            }
            reqFunc();

        }catch(error){

        }
    }

    const profileHandler = ()=>{
        try{
            const reqFunc = async ()=>{
                const response = await axios.get(`http://localhost:8080/kakao/profile`)
                console.log(response.data);
            }
            reqFunc();

        }catch(error){

        }
    }
    const sendMeHandler = ()=>{
        try{
            const reqFunc = async ()=>{
                const response = await axios.get(`http://localhost:8080/kakao/message/me/${message}`)
                // /console.log(response.data);
            }
            reqFunc();

        }catch(error){

        }
    }
    const handleClick_2 = ()=>{
        
        const reqFunction_ = async ()=>{
                
                window.open("http://localhost:8080/kakao/getCode","팝업 테스트","width=400, height=300, top=10, left=10");
            }
        reqFunction_();
        

    }
    return (
        <>
            <h1>KAKAO LOGIN</h1>        
            {/* 동기요청 */}
            <a href="http://localhost:8080/kakao/getCode">로그인요청</a> | 

            {/* 비동기 로그인 요청 */}
            <button onClick = {handleClick_2}>로그인 요청(비동기)</button>

            {/* 비동기요청 */}
            <button onClick={profileHandler}>프로필 확인</button> | 
            {/* 동기요청  */}
            <a href="http://localhost:8080/kakao/logoutWithKakao">로그아웃</a> | 

            {/* 동기요청 */}
            <a href="http://localhost:8080/kakao/getCodeMsg">메시지 송신위한 코드요청</a> | 
            
            {/* 비동기요청  */}
            <input type="text" onChange={e=>{setMessage(e.target.value)}} />
            <button  onClick={sendMeHandler}>메시지 보내기</button>

        </>
    )
}


export default KakaoLogin;