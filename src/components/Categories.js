import React, { useState, useEffect } from 'react';
import { useCart } from './ContextReducer';
import { Card, Button, Modal, Form, Row, Col, Dropdown } from 'react-bootstrap';
import {  useNavigate } from 'react-router-dom';
import axios from 'axios'; // Import axios for making HTTP requests

export default function Categories() {
  const { addToCart } = useCart();
  const navigate = useNavigate();
  const [showModal, setShowModal] = useState(false);
  const [quantity, setQuantity] = useState(1);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [selectedProductInModal, setSelectedProductInModal] = useState(null); 
  const [categories,setCategories]=useState([]);
  useEffect(() => {
    // Fetch categories from the backend when the component mounts
    const fetchCategories = async () => {
      try {
        const response = await axios.get('http://localhost:5000/categories');
        setCategories(response.data);
      } catch (error) {
        console.error('Error fetching categories:', error);
      }
    };

    fetchCategories();
  }, []);

  const handleCardClick = (product) => {
    setSelectedProductInModal(product);
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
  };

  const handleQuantityChange = (e) => {
    const value = parseFloat(e.target.value);
    setQuantity(value);
  };

  const handleAddToCart = () => {
    if (selectedProductInModal) {
      addToCart(selectedProductInModal, quantity);
      handleCloseModal();
      navigate('/cart');
    }
  };

  const handleCategorySelect = (category) => {
    setSelectedCategory(category === 'All Categories' ? null : category);
  };

  return (
    <div>
      <div style={{ backgroundColor: 'orange', minHeight: '100vh', color: '#fff' }}>
        <Dropdown>
          <Dropdown.Toggle variant="primary" id="categoryDropdown">
            {selectedCategory ? selectedCategory.title : 'All Categories'}
          </Dropdown.Toggle>
          <Dropdown.Menu>
            <Dropdown.Item onClick={() => handleCategorySelect('All Categories')}>
              All Categories
            </Dropdown.Item>
            {categories.map((category, index) => (
              <Dropdown.Item key={index} onClick={() => handleCategorySelect(category)}>
                {category.title}
              </Dropdown.Item>
            ))}
          </Dropdown.Menu>
        </Dropdown>
        {selectedCategory === null ? (
          <>
            <h2>All Categories</h2>
            {categories.map((category, index) => (
              <div key={index}>
                <h3>{category.title}</h3>
                <Row className="gx-2" noGutters>
                  {category.products.map((product, productIndex) => (
                    <Col key={productIndex} xs={12} md={6} lg={4}>
                      <Card style={{ width: '100%', height: '90%', margin: '5px' }}>
                        <Card.Body>
                          <img
                            src={product.imageUrl}
                            alt={product.name}
                            style={{ width: '110px',height:"90px", objectFit: 'cover', marginRight: '20px' }}
                          />
                          <div>
                            <p>{product.name}</p>
                            <p>Price: Rs. {product.price}</p>
                            <Button onClick={() => handleCardClick(product)}>Add to Cart</Button>
                          </div>
                        </Card.Body>
                      </Card>
                    </Col>
                  ))}
                </Row>
              </div>
            ))}
          </>
        ) : (
          <>
            <h2>{selectedCategory.title}</h2>
            <Row className="gx-4" noGutters>
              {selectedCategory.products.map((product, productIndex) => (
                <Col key={productIndex} xs={12} md={6} lg={4}>
                  <Card style={{ width: '100%', height: '90%', margin: '5px' }}>
                    <Card.Body>
                      <img
                        src={product.imageUrl}
                        alt={product.name}
                        style={{ width: '110px',height:'90px', objectFit: 'cover', marginRight: '20px' }}
                      />
                      <div>
                        <p>{product.name}</p>
                        <p>Price: Rs. {product.price}</p>
                        <Button onClick={() => handleCardClick(product)}>Add to Cart</Button>
                      </div>
                    </Card.Body>
                  </Card>
                </Col>
              ))}
            </Row>
          </>
        )}

        <Modal show={showModal} onHide={handleCloseModal}>
          <Modal.Header closeButton>
            <Modal.Title>Add to Cart</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <p>Product: {selectedProductInModal?.name}</p>
            <Form.Group controlId="quantity">
              <Form.Label>Quantity</Form.Label>
              <Form.Control type="number" min="0" step="0.25" value={quantity} onChange={handleQuantityChange} />
            </Form.Group>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={handleCloseModal}>
              Close
            </Button>
            <Button variant="primary" onClick={handleAddToCart}>
              Add to Cart
            </Button>
          </Modal.Footer>
        </Modal>
      </div>
    </div>
  );
}
