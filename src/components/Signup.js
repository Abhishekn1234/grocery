// Signup.js

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

export default function Signup() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
 const [MobileNumber,setMobileNumber]=useState('');
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:5000/signup', { name, email, password,MobileNumber });
      localStorage.setItem("name",name);
      localStorage.setItem("MobileNumber",MobileNumber);
      navigate('/login'); // Use navigate to redirect to login page after successful signup
    } catch (error) {
      console.error('Signup error:', error.response.data.message);
    }
  };

  return (
    <div>
      <h2>Signup</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Name:</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div>
          <label>Email:</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        <div>
          <label>Password:</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <div>
          <label>Mobile Number:</label>
          <input type="text" value={MobileNumber} onChange={(e) => setMobileNumber(e.target.value)} required />
        </div>
        <button type="submit">Signup</button>
      </form>
    </div>
  );
}
