import { useState, useEffect } from "react";
import axios from "axios";

const User = () => {
  useEffect(() => {
    const req = async () => {
      const token = localStorage.getItem("accesstoken");

      try {
        if (token != null) {
          const resp = await axios.get("http://localhost:8095/user", {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          });
          console.log("resp",resp)
          if (
            resp.data != null &&
            resp.data.auth &&
            resp.data.accesstoken != null
          ) {
            localStorage.setItem("accesstoken", resp.data.accesstoken);
          } else if (!resp.data.auth) {
            localStorage.removeItem("accesstoken");
          }
        }
      } catch (err) {
        console.log(err);
      }
    };
    req();
  }, []);

  return <h1>USER PAGE</h1>;
};

export default User;
