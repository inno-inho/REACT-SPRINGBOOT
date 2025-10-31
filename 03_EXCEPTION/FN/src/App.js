import logo from "./logo.svg";
import "./App.css";

import Param from "./components/Param";
import MemoPost from "./components/memo/Post";
import MemoList from "./components/memo/List";
import Exception from "./components/Exception";

import { BrowserRouter as Router, Route, Routes, Link } from "react-router-dom";

function App() {
  return (
    <Router>
      <div>
        <Link to="/param">PARAM TEST</Link> <br/>
        <Link to="/memo/post">MEMO POST</Link> <br/>
        <Link to="/memo/list">MEMO LIST(EXCEPTION TEST)</Link> <br/><br/>
      </div>
      <Routes>
        {/* Route 설정 */}
        <Route path="/param" element={<Param />} />
        <Route path="/memo/post" element={<MemoPost />} />
        <Route path="/memo/list" element={<MemoList />} />
        <Route path="/exception" element={<Exception />} />
      </Routes>
    </Router>
  );
}

export default App;
