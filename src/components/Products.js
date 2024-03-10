import React, { useState, useEffect } from 'react';
import { useCart } from './ContextReducer';
import { Card, Button, Modal, Form, InputGroup, FormControl } from 'react-bootstrap';
import axios from 'axios';
import { useNavigate } from "react-router-dom";

export default function Products() {
  const { addToCart } = useCart();
  const [showModal, setShowModal] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [quantity, setQuantity] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [products, setProducts] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await axios.get('http://localhost:5000/products');
        setProducts(response.data);
      } catch (error) {
        console.error('Error fetching products:', error);
      }
    };

    fetchProducts();
  }, []);

  const handleCardClick = (product) => {
    setSelectedProduct(product);
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setSelectedProduct(null);
    setShowModal(false);
  };

  const handleQuantityChange = (e) => {
    const value = parseFloat(e.target.value);
    setQuantity(value);
  };

  const handleAddToCart = () => {
    addToCart(selectedProduct, quantity);
    handleCloseModal();
    navigate('/cart');
  };

  // Filter products based on search term
  const filteredProducts = products.filter(product =>
    product.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Sort products alphabetically in ascending order
  const sortedProducts = filteredProducts.sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div style={{ backgroundColor: "orange", minHeight: "100vh", color: "#fff" }}>
      {/* Search input */}
      <InputGroup className="mb-3">
        <FormControl
          placeholder="Search products"
          aria-label="Search products"
          aria-describedby="basic-addon2"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </InputGroup>

      {/* Render products */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px' }}>
        {sortedProducts.map((product, index) => (
          <Card key={index} style={{ width: '200px', height: '300px', margin: '5px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <Card.Img variant="top" src={product.imageUrl} style={{ objectFit: 'cover', width: '100%', height: '50%' }} />
            <Card.Body style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <Card.Title>{product.name}</Card.Title>
              <Card.Text>Price: Rs. {product.price}</Card.Text>
              <Button onClick={() => handleCardClick(product)}>Add to Cart</Button>
            </Card.Body>
          </Card>
        ))}
      </div>

      {/* Modal */}
      <Modal show={showModal} onHide={handleCloseModal}>
        <Modal.Header closeButton>
          <Modal.Title>Add to Cart</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Product: {selectedProduct?.name}</p>
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
  );
}
