// src/api.js
import axios from "axios";

const api = axios.create({
  baseURL: "/",
  withCredentials: true, // IMPORTANT: send cookies
});

export default api;
