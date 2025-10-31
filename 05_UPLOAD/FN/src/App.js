import logo from "./logo.svg";
import "./App.css";

import Param from "./components/Param";
import MemoPost from "./components/memo/Post";
import MemoList from "./components/memo/List";
import Exception from "./components/Exception";
// FILE UP DOWNLOAD
import FileUpload from "./components/updownload/Upload";
// import FileDownload from "./components/updownload/Download";
import FileList from "./components/updownload/List";
import { BrowserRouter as Router, Route, Routes, Link } from "react-router-dom";

function App() {
  return (
    <Router>
      <div>
        <Link to="/param">PARAM TEST</Link> <br/>
        <hr></hr>
        <Link to="/memo/post">MEMO POST</Link> <br/>
        <Link to="/memo/list">MEMO LIST(EXCEPTION TEST)</Link> <br/><br/>
        <hr></hr>
        <Link to="/file/upload">UPLOAD</Link> <br/>
        <Link to="/file/list">LIST</Link> <br/>
        
      </div>
      <Routes>
        {/* Route 설정 */}
        <Route path="/param" element={<Param />} />
        
        {/*  */}
        <Route path="/memo/post" element={<MemoPost />} />
        <Route path="/memo/list" element={<MemoList />} />
        <Route path="/exception" element={<Exception />} />
        
        {/*  */}
        <Route path="/file/upload" element={<FileUpload />} />
        {/* <Route path="/file/download" element={<FileDownload />} /> */}
        <Route path="/file/list" element={<FileList />} />
      </Routes>
    </Router>
  );
}

export default App;
