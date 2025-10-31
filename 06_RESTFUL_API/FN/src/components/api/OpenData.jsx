import axios from "axios";
import {useState,useEffect} from "react";
import { useNavigate,Link } from 'react-router-dom';

//직접 요청?
const OpenData = ()=>{
    const [addr,setAddr] = useState();
    const [foodList,setFoodList] = useState({})


    useEffect(()=>{
        console.log('foodList : ',foodList);        

    },[foodList])

    //맛집 요청
    const reqFoodHandler  = (e)=>{
        try{
            const reqFunction = async ()=>{
                const response = await axios.get(`http://localhost:8080/api/open/food/${addr}`)
                console.log(response);
                setFoodList(response.data);
            }
            reqFunction();


        }catch(error){
            //예외발생시 error페이지로 이동
        }

    }

    //날씨 요청

    return (
        <div>
            <input type="text" onChange={e=>setAddr(e.target.value)}   placeholder="중구,달서구,서구,남구 중 입력" />
            <button onClick={reqFoodHandler}>맛집정보확인(OPENDATA</button>
            <br></br>   
            <div>
                {
                    true && console.log("!!!",foodList)
                    
                }
            </div>
        </div>
    )

}

export default OpenData;


