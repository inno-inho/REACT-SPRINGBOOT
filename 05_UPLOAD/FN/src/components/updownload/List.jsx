import axios from "axios";
import {useState,useEffect} from "react";
import { useNavigate,Link } from 'react-router-dom';

const List  = ()=>{
    const navigate = useNavigate();
    const [fileList, setFileList] = useState([])
    
    useEffect(()=>{
        const reqServer = async()=>{
            try{
                const resp = await axios.get("http://localhost:8080/upload/list");         
                console.log(resp);
                setFileList(resp.data);
            }catch(error){
                console.log(error);
                navigate('/exception', { state: { message: error.response.data.message, status: error.response?.status } } );
            }

        }
        reqServer();

    },[])


    const downloadHandler = (e)=>{
        // console.log(e.target);
        const filePath = e.target.getAttribute('data-filename');
        console.log('filePath',filePath);

        try{
            const reqFunction = async ()=>{
                const resp =  await axios.get(
                    `http://localhost:8080/download`,
                    {params:{"filePath":filePath},responseType:'blob',headers:{"Content-Type":"application/json"},},
                )
                console.log('resp',resp);

                //전달받은 파일 Download 처리하기
                const filename = filePath.split("/").pop();                             //마지막 경로 추출(파일명)
                const url = window.URL.createObjectURL(new Blob([resp.data]));          //blob 객체 생성,해당 경로를 URL로 지정 
                console.log("url",url);
                const link = document.createElement('a');                               //a태그생성
                link.href=url;                                                          //URL지정
                link.setAttribute('download',filename);                                 //해당 태그 클릭시 다운로드 처리를 위한 태그속성으로 변경
                document.body.appendChild(link);                                        //Body에 추가
                link.click();                                                           //클릭
                link.parentNode.removeChild(link);                                      //Body에서 제거


            }
            reqFunction();

        }catch(error){

            console.error('error.response.data', error.response.data);
            navigate('/exception', { state: { message: error.response.data.message, status: error.response?.status } } );
        }


    }

    return (
        
        <div>
            <h1>파일 목록 확인 (REACT-SPRINGBOOT)</h1>
            {fileList&&(
                
                fileList.map( (el,idx)=>{
                    return (
                        <div key={idx}>
                            <Link  onClick={downloadHandler} data-filename={el}>{el}</Link>
                        </div> 
                    )
                })

            )}
        </div>
    )

}

export default List;
