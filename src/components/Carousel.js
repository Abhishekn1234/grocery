import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Carousel } from 'react-bootstrap';

export default function Carousell() {
  const [categories, setCategories] = useState([]);

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('http://localhost:5000/categories', {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        setCategories(response.data); // Set the state here
      } catch (error) {
        console.error('Error fetching categories:', error);
      }
    };

    fetchCategories();
  }, []);

  return (
    <div>
      <Carousel indicators={true} controls={true} style={{ marginBottom: "0px" }}>
        {categories.map((category, index) => (
          <Carousel.Item key={index}>
            <img src={category.image} alt={`Slide ${index}`} style={{ "height": "35%", "width": "100%" }} />
            <Carousel.Caption>
              <h3>{category.title}</h3>
              {/* Add any additional content you want here */}
            </Carousel.Caption>
          </Carousel.Item>
        ))}
      </Carousel>
    </div>
  );
}
