import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Form, Button, Image } from 'react-bootstrap';
import axios from 'axios';
import { useCart } from './ContextReducer';

export default function Profile() {
  const [name, setName] = useState(localStorage.getItem('name') || '');
  const [email, setEmail] = useState(localStorage.getItem('email') || '');
  const [phoneNumber, setPhoneNumber] = useState(localStorage.getItem('MobileNumber') || '');
  const [address, setAddress] = useState('');
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const { cart } = useCart();

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.put(`http://localhost:5000/user-profile/${email}`, {
        name,
        mobileNumber: phoneNumber,
        address
      });
      console.log(response);
      console.log('Profile updated successfully');
    } catch (error) {
      console.error('Error updating profile:', error);
    }
  };

  return (
    <Container fluid style={{ backgroundColor: 'orange', minHeight: '100vh', color: '#fff' }}>
      <h1>{name}</h1>

      <Row className="mb-4">
        <Col>
          <Card>
            <Card.Body>
              <Card.Title>Personal Information</Card.Title>
              <Form onSubmit={handleFormSubmit}>
                <Form.Group className="mb-3" controlId="formName">
                  <Form.Label>Name</Form.Label>
                  <Form.Control type="text" placeholder="Enter your name" value={name} onChange={(e) => setName(e.target.value)} required />
                </Form.Group>
                <Form.Group className="mb-3" controlId="formEmail">
                  <Form.Label>Email</Form.Label>
                  <Form.Control type="email" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                </Form.Group>
                <Form.Group className="mb-3" controlId="formPhoneNumber">
                  <Form.Label>Phone Number</Form.Label>
                  <Form.Control type="tel" placeholder="Enter your phone number" value={phoneNumber} onChange={(e) => setPhoneNumber(e.target.value)} />
                </Form.Group>
                <Form.Group className="mb-3" controlId="formAddress">
                  <Form.Label>Address</Form.Label>
                  <Form.Control as="textarea" rows={3} placeholder="Enter your address" value={address} onChange={(e) => setAddress(e.target.value)} />
                </Form.Group>
                <Button variant="primary" type="submit">Save Changes</Button>
              </Form>
            </Card.Body>
          </Card>
        </Col>
      </Row>
      <Row className="mb-4">
        <Col>
          <Card>
            <Card.Body>
              <Card.Title>My Cart - {cart.length} items</Card.Title>
              <Row xs={1} md={2} lg={3} className="g-4">
                {cart.map((item) => (
                  <Col key={item.productId}>
                    <Card className="h-70">
                      <Card.Body>
                        <Card.Title>{item.name}</Card.Title>
                        <Card.Text>Quantity: {item.quantity}</Card.Text>
                        <Card.Text>Price: Rs. {item.price.toFixed(2)}</Card.Text>
                        <div className="d-flex justify-content-end">
                          <Image src={item.imageUrl} thumbnail style={{ width: '90px', height: '100px' }} />
                        </div>
                      </Card.Body>
                    </Card>
                  </Col>
                ))}
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}
