
import axios from "axios";
import { useNavigate } from 'react-router-dom';
const List = ()=>{
    const navigate = useNavigate();

    const test1 =(endPoint, ...params)=>{
        console.log('endPoint',endPoint);
        axios
        .get(
          `http://localhost:8085${endPoint}`,                    //URL
        )
        .then(response => {
          console.log(response.data);
        })
        .catch(error => {
            console.log(error)
            console.error('error.response.data', error.response.data);
            // navigate는 강제로 리다이렉팅 시키는 코드(프론트엔드에서)
            navigate('/exception', { state: { message: error.response.data.message, status: error.response?.status } } );
        });

    }
    const test2 =()=>{ }
    const test3 =()=>{}
    const test4 =()=>{}

    return (
        <>
            <button onClick={(e)=>{test1("/memo/list1")}}>LIST1</button><br/>
            <button onClick={(e)=>{test1("/memo/list2")}}>LIST2</button><br/>
            <button onClick={(e)=>{test1("/memo/list3",100,0)}}>LIST3</button><br/>

        </>

    )

}

export default List;


